package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var (
	externalAccountKeyTable                   = []byte("acme_external_account_keys")
	externalAccountKeyIDsByReferenceTable     = []byte("acme_external_account_keyID_reference_index")
	externalAccountKeyIDsByProvisionerIDTable = []byte("acme_external_account_keyID_provisionerID_index")
)

type externalAccountKey struct {
	ID            string    `json:"id"`
	ProvisionerID string    `json:"provisionerID"`
	Reference     string    `json:"reference"`
	AccountID     string    `json:"accountID,omitempty"`
	HmacKey       []byte    `json:"key"`
	CreatedAt     time.Time `json:"createdAt"`
	BoundAt       time.Time `json:"boundAt"`
}

type externalAccountKeyReference struct {
	Reference            string `json:"reference"`
	ExternalAccountKeyID string `json:"externalAccountKeyID"`
}

type listedExternalAccountKey struct {
	ID            string `json:"id"`
	Key           string `json:"key,omitempty"`
	Reference     string `json:"reference,omitempty"`
	ProvisionerID string `json:"provisionerID,omitempty"`
	AccountID     string `json:"accountID,omitempty"`
}

type referenceIndexEntry struct {
	ProvisionerID string
	Reference     string
}

type provisionerIndexMutation struct {
	exists bool
	ids    []string
}

// main runs the command.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "acme-eab: %v\n", err)
		os.Exit(1)
	}
}

// run dispatches the requested subcommand.
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: acme-eab <add|ls|rm> ...")
	}

	switch args[0] {
	case "add":
		return runAdd(args[1:])
	case "ls":
		return runList(args[1:])
	case "rm":
		return runRemove(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return errors.Errorf("unknown subcommand %q", args[0])
	}
}

// runAdd parses flags and writes the EAB key.
func runAdd(args []string) (err error) {
	var (
		dbPath        string
		keyValue      string
		kid           string
		provisionerID string
		reference     string
		replace       bool
	)

	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&dbPath, "db", "", "path to the Step CA Badger DB")
	fs.StringVar(&keyValue, "key", "", "base64url-encoded ACME EAB HMAC key")
	fs.StringVar(&kid, "kid", "", "ACME EAB key ID")
	fs.StringVar(&provisionerID, "provisioner-id", "", "ACME provisioner ID")
	fs.StringVar(&reference, "reference", "", "human-readable EAB reference")
	fs.BoolVar(&replace, "replace", false, "replace any existing EAB key for the same provisioner/reference")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.Errorf("unexpected add argument %q", fs.Arg(0))
	}

	if dbPath == "" {
		return errors.New("--db is required")
	}
	if keyValue == "" {
		return errors.New("--key is required")
	}
	if kid == "" {
		return errors.New("--kid is required")
	}
	if replace && reference == "" {
		return errors.New("--replace requires --reference")
	}

	rawKey, err := base64.RawURLEncoding.DecodeString(keyValue)
	if err != nil {
		return errors.Wrap(err, "decoding --key")
	}

	db, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil && err == nil {
			err = errors.Wrap(closeErr, "closing DB")
		}
	}()

	if err := ensureTables(db); err != nil {
		return err
	}

	key := &externalAccountKey{
		ID:            kid,
		ProvisionerID: provisionerID,
		Reference:     reference,
		HmacKey:       rawKey,
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
	return addKey(db, key, replace)
}

// runList parses flags and lists EAB keys as JSON.
func runList(args []string) (err error) {
	var dbPath string

	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&dbPath, "db", "", "path to the Step CA Badger DB")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.Errorf("unexpected ls argument %q", fs.Arg(0))
	}
	if dbPath == "" {
		return errors.New("--db is required")
	}

	db, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil && err == nil {
			err = errors.Wrap(closeErr, "closing DB")
		}
	}()

	keys, err := listKeys(db)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return errors.Wrap(enc.Encode(keys), "encoding JSON")
}

// runRemove parses flags and removes one or more EAB key IDs.
func runRemove(args []string) (err error) {
	var dbPath string

	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&dbPath, "db", "", "path to the Step CA Badger DB")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if dbPath == "" {
		return errors.New("--db is required")
	}
	if fs.NArg() == 0 {
		return errors.New("at least one key ID is required")
	}

	db, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil && err == nil {
			err = errors.Wrap(closeErr, "closing DB")
		}
	}()

	for _, kid := range fs.Args() {
		if err := removeKey(db, kid); err != nil {
			return err
		}
	}
	return nil
}

// printUsage prints the top-level usage.
func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: acme-eab <add|ls|rm> ...")
}

// openDB opens the Step CA Badger DB.
func openDB(dbPath string) (nosql.DB, error) {
	db, err := nosql.New("badgerv2", dbPath)
	if err != nil {
		return nil, errors.Wrap(err, "opening DB")
	}
	return db, nil
}

// ensureTables creates the tables used by Step CA's ACME EAB storage.
func ensureTables(db nosql.DB) error {
	for _, table := range [][]byte{
		externalAccountKeyTable,
		externalAccountKeyIDsByReferenceTable,
		externalAccountKeyIDsByProvisionerIDTable,
	} {
		if err := db.CreateTable(table); err != nil {
			return errors.Wrapf(err, "creating table %s", table)
		}
	}
	return nil
}

// listKeys returns all EAB keys in a stable order.
func listKeys(db nosql.DB) ([]listedExternalAccountKey, error) {
	references, err := referenceIndexByKeyID(db)
	if err != nil {
		return nil, err
	}

	entries, err := db.List(externalAccountKeyTable)
	if nosql.IsErrNotFound(err) {
		return []listedExternalAccountKey{}, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "listing keys")
	}

	keys := make([]listedExternalAccountKey, 0, len(entries))
	for _, entry := range entries {
		var key externalAccountKey
		if err := json.Unmarshal(entry.Value, &key); err != nil {
			return nil, errors.Wrapf(err, "unmarshaling key %s", entry.Key)
		}
		if key.ID == "" {
			key.ID = string(entry.Key)
		}
		if key.Reference == "" && len(references[key.ID]) > 0 {
			key.Reference = references[key.ID][0].Reference
		}
		if key.ProvisionerID == "" && len(references[key.ID]) > 0 {
			key.ProvisionerID = references[key.ID][0].ProvisionerID
		}

		keys = append(keys, listedExternalAccountKey{
			ID:            key.ID,
			Key:           base64.RawURLEncoding.EncodeToString(key.HmacKey),
			Reference:     key.Reference,
			ProvisionerID: key.ProvisionerID,
			AccountID:     key.AccountID,
		})
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ID < keys[j].ID
	})

	return keys, nil
}

// removeKey removes an EAB key and its secondary indexes.
func removeKey(db nosql.DB, kid string) error {
	references, err := referenceIndexByKeyID(db)
	if err != nil {
		return err
	}

	keyRaw, err := db.Get(externalAccountKeyTable, []byte(kid))
	if nosql.IsErrNotFound(err) {
		return errors.Errorf("%s not found", kid)
	}
	if err != nil {
		return errors.Wrapf(err, "reading key %s", kid)
	}

	var key externalAccountKey
	if err := json.Unmarshal(keyRaw, &key); err != nil {
		return errors.Wrapf(err, "unmarshaling key %s", kid)
	}

	if key.Reference != "" {
		if err := deleteReference(db, key.ProvisionerID, key.Reference); err != nil {
			return err
		}
	}
	for _, ref := range references[kid] {
		if ref.ProvisionerID == key.ProvisionerID && ref.Reference == key.Reference {
			continue
		}
		if err := deleteReference(db, ref.ProvisionerID, ref.Reference); err != nil {
			return err
		}
	}
	if err := deleteKey(db, kid); err != nil {
		return err
	}
	if err := removeProvisionerIndex(db, key.ProvisionerID, kid); err != nil {
		return err
	}

	return nil
}

// referenceIndexByKeyID returns reference index entries grouped by EAB key ID.
func referenceIndexByKeyID(db nosql.DB) (map[string][]referenceIndexEntry, error) {
	entries, err := db.List(externalAccountKeyIDsByReferenceTable)
	if nosql.IsErrNotFound(err) {
		return map[string][]referenceIndexEntry{}, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "listing reference index")
	}

	refs := make(map[string][]referenceIndexEntry, len(entries))
	for _, entry := range entries {
		var ref externalAccountKeyReference
		if err := json.Unmarshal(entry.Value, &ref); err != nil {
			return nil, errors.Wrapf(err, "unmarshaling reference index %s", entry.Key)
		}
		provisionerID, reference := splitReferenceKey(entry.Key)
		if ref.Reference != "" {
			reference = ref.Reference
		}
		if ref.ExternalAccountKeyID == "" || reference == "" {
			continue
		}
		refs[ref.ExternalAccountKeyID] = append(refs[ref.ExternalAccountKeyID], referenceIndexEntry{
			ProvisionerID: provisionerID,
			Reference:     reference,
		})
	}

	return refs, nil
}

// splitReferenceKey returns the provisioner ID and reference from a reference index key.
func splitReferenceKey(key []byte) (string, string) {
	provisionerID, reference, ok := bytes.Cut(key, []byte{0})
	if !ok {
		return "", string(key)
	}
	return string(provisionerID), string(reference)
}

// addKey adds an EAB key and updates its secondary indexes in one transaction.
func addKey(db nosql.DB, key *externalAccountKey, replace bool) error {
	var replacedKey *externalAccountKey
	refKey := referenceKey(key.ProvisionerID, key.Reference)
	tx := &database.Tx{}
	provisionerIndexes := map[string]*provisionerIndexMutation{}

	getProvisionerIndex := func(provisionerID string) (*provisionerIndexMutation, error) {
		if provisionerID == "" {
			return nil, nil
		}
		if index, ok := provisionerIndexes[provisionerID]; ok {
			return index, nil
		}

		index := &provisionerIndexMutation{}
		raw, err := db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
		switch {
		case err == nil:
			index.exists = true
			if err := json.Unmarshal(raw, &index.ids); err != nil {
				return nil, errors.Wrap(err, "unmarshaling provisioner index")
			}
		case nosql.IsErrNotFound(err):
		default:
			return nil, errors.Wrap(err, "reading provisioner index")
		}

		provisionerIndexes[provisionerID] = index
		return index, nil
	}

	if replace {
		refRaw, err := db.Get(externalAccountKeyIDsByReferenceTable, []byte(refKey))
		switch {
		case err == nil:
			var ref externalAccountKeyReference
			if err := json.Unmarshal(refRaw, &ref); err != nil {
				return errors.Wrap(err, "unmarshaling existing reference")
			}

			keyRaw, err := db.Get(externalAccountKeyTable, []byte(ref.ExternalAccountKeyID))
			switch {
			case err == nil:
				var oldKey externalAccountKey
				if err := json.Unmarshal(keyRaw, &oldKey); err != nil {
					return errors.Wrap(err, "unmarshaling existing key")
				}
				if oldKey.ProvisionerID != key.ProvisionerID {
					return errors.New("existing key has a different provisioner")
				}
				replacedKey = &oldKey
			case nosql.IsErrNotFound(err):
				tx.Del(externalAccountKeyIDsByReferenceTable, []byte(refKey))
			default:
				return errors.Wrap(err, "reading existing key")
			}
		case nosql.IsErrNotFound(err):
		default:
			return errors.Wrap(err, "reading existing reference")
		}
	}

	_, err := db.Get(externalAccountKeyTable, []byte(key.ID))
	switch {
	case err == nil:
		if replacedKey == nil || replacedKey.ID != key.ID {
			return errors.Errorf("%s/%s already exists", externalAccountKeyTable, key.ID)
		}
	case nosql.IsErrNotFound(err):
	default:
		return errors.Wrap(err, "reading existing key")
	}

	if key.Reference != "" && !replace {
		_, err := db.Get(externalAccountKeyIDsByReferenceTable, []byte(refKey))
		switch {
		case err == nil:
			return errors.Errorf("%s/%s already exists", externalAccountKeyIDsByReferenceTable, refKey)
		case nosql.IsErrNotFound(err):
		default:
			return errors.Wrap(err, "reading existing reference")
		}
	}

	if replacedKey != nil {
		tx.Del(externalAccountKeyTable, []byte(replacedKey.ID))
		if replacedKey.Reference != "" {
			tx.Del(externalAccountKeyIDsByReferenceTable, []byte(referenceKey(replacedKey.ProvisionerID, replacedKey.Reference)))
		}

		index, err := getProvisionerIndex(replacedKey.ProvisionerID)
		if err != nil {
			return err
		}
		if index != nil {
			index.ids = removeString(index.ids, replacedKey.ID)
		}
	}

	index, err := getProvisionerIndex(key.ProvisionerID)
	if err != nil {
		return err
	}
	if index != nil {
		if containsString(index.ids, key.ID) {
			return errors.Errorf("provisioner index already contains %s", key.ID)
		}
		index.ids = append(index.ids, key.ID)
	}

	keyData, err := json.Marshal(key)
	if err != nil {
		return errors.Wrap(err, "marshaling key")
	}
	tx.Set(externalAccountKeyTable, []byte(key.ID), keyData)

	if key.Reference != "" {
		ref := &externalAccountKeyReference{
			Reference:            key.Reference,
			ExternalAccountKeyID: key.ID,
		}
		refData, err := json.Marshal(ref)
		if err != nil {
			return errors.Wrap(err, "marshaling reference")
		}
		tx.Set(externalAccountKeyIDsByReferenceTable, []byte(refKey), refData)
	}

	for provisionerID, index := range provisionerIndexes {
		if !index.exists && len(index.ids) == 0 {
			continue
		}
		if len(index.ids) == 0 {
			tx.Del(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
			continue
		}

		indexData, err := json.Marshal(index.ids)
		if err != nil {
			return errors.Wrap(err, "marshaling provisioner index")
		}
		tx.Set(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID), indexData)
	}

	return errors.Wrap(db.Update(tx), "writing key")
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func removeString(values []string, value string) []string {
	filtered := values[:0]
	for _, v := range values {
		if v != value {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// replaceReference removes an existing reference key.
func replaceReference(db nosql.DB, provisionerID string, reference string) error {
	refRaw, err := db.Get(externalAccountKeyIDsByReferenceTable, []byte(referenceKey(provisionerID, reference)))
	if nosql.IsErrNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "reading existing reference")
	}

	var ref externalAccountKeyReference
	if err := json.Unmarshal(refRaw, &ref); err != nil {
		return errors.Wrap(err, "unmarshaling existing reference")
	}

	keyRaw, err := db.Get(externalAccountKeyTable, []byte(ref.ExternalAccountKeyID))
	if nosql.IsErrNotFound(err) {
		return deleteReference(db, provisionerID, reference)
	}
	if err != nil {
		return errors.Wrap(err, "reading existing key")
	}

	var key externalAccountKey
	if err := json.Unmarshal(keyRaw, &key); err != nil {
		return errors.Wrap(err, "unmarshaling existing key")
	}
	if key.ProvisionerID != provisionerID {
		return errors.New("existing key has a different provisioner")
	}

	if key.Reference != "" {
		if err := deleteReference(db, provisionerID, key.Reference); err != nil {
			return err
		}
	}
	if err := deleteKey(db, key.ID); err != nil {
		return err
	}
	if err := removeProvisionerIndex(db, provisionerID, key.ID); err != nil {
		return err
	}

	return nil
}

// deleteReference deletes a reference index entry.
func deleteReference(db nosql.DB, provisionerID string, reference string) error {
	err := db.Del(externalAccountKeyIDsByReferenceTable, []byte(referenceKey(provisionerID, reference)))
	if nosql.IsErrNotFound(err) {
		return nil
	}
	return errors.Wrap(err, "deleting existing reference")
}

// deleteKey deletes an EAB key.
func deleteKey(db nosql.DB, kid string) error {
	err := db.Del(externalAccountKeyTable, []byte(kid))
	if nosql.IsErrNotFound(err) {
		return nil
	}
	return errors.Wrap(err, "deleting existing key")
}

// createJSON writes a JSON value if absent.
func createJSON(db nosql.DB, table []byte, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "marshaling value")
	}

	_, swapped, err := db.CmpAndSwap(table, []byte(key), nil, data)
	switch {
	case err != nil:
		return errors.Wrapf(err, "writing %s/%s", table, key)
	case !swapped:
		return errors.Errorf("%s/%s already exists", table, key)
	default:
		return nil
	}
}

// removeProvisionerIndex removes a key ID.
func removeProvisionerIndex(db nosql.DB, provisionerID string, kid string) error {
	if provisionerID == "" {
		return nil
	}

	var oldIDs []string
	oldRaw, err := db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
	if nosql.IsErrNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "reading provisioner index")
	}
	if err := json.Unmarshal(oldRaw, &oldIDs); err != nil {
		return errors.Wrap(err, "unmarshaling provisioner index")
	}

	newIDs := make([]string, 0, len(oldIDs))
	for _, id := range oldIDs {
		if id != kid {
			newIDs = append(newIDs, id)
		}
	}

	if len(newIDs) == len(oldIDs) {
		return nil
	}

	if len(newIDs) == 0 {
		_, swapped, err := db.CmpAndSwap(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID), oldRaw, nil)
		switch {
		case err != nil:
			return errors.Wrap(err, "deleting provisioner index")
		case !swapped:
			return errors.New("provisioner index changed while writing")
		default:
			err := db.Del(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
			if err == nil || nosql.IsErrNotFound(err) {
				return nil
			}
			return errors.Wrap(err, "deleting provisioner index")
		}
	}

	newRaw, err := json.Marshal(newIDs)
	if err != nil {
		return errors.Wrap(err, "marshaling provisioner index")
	}

	_, swapped, err := db.CmpAndSwap(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID), oldRaw, newRaw)
	switch {
	case err != nil:
		return errors.Wrap(err, "writing provisioner index")
	case !swapped:
		return errors.New("provisioner index changed while writing")
	default:
		return nil
	}
}

// addProvisionerIndex adds a key ID.
func addProvisionerIndex(db nosql.DB, provisionerID string, kid string) error {
	if provisionerID == "" {
		return nil
	}

	var oldIDs []string
	oldRaw, err := db.Get(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID))
	if err == nil {
		if err := json.Unmarshal(oldRaw, &oldIDs); err != nil {
			return errors.Wrap(err, "unmarshaling provisioner index")
		}
	} else if !nosql.IsErrNotFound(err) {
		return errors.Wrap(err, "reading provisioner index")
	}

	for _, id := range oldIDs {
		if id == kid {
			return errors.Errorf("provisioner index already contains %s", kid)
		}
	}

	newIDs := append(append([]string{}, oldIDs...), kid)
	newRaw, err := json.Marshal(newIDs)
	if err != nil {
		return errors.Wrap(err, "marshaling provisioner index")
	}

	var expected []byte
	if len(oldIDs) > 0 {
		expected = oldRaw
	}

	_, swapped, err := db.CmpAndSwap(externalAccountKeyIDsByProvisionerIDTable, []byte(provisionerID), expected, newRaw)
	switch {
	case err != nil:
		return errors.Wrap(err, "writing provisioner index")
	case !swapped:
		return errors.New("provisioner index changed while writing")
	default:
		return nil
	}
}

// referenceKey returns the reference index key.
func referenceKey(provisionerID string, reference string) string {
	return provisionerID + "\x00" + reference
}
