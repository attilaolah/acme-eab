# acme-eab-add

`acme-eab-add` writes ACME External Account Binding credentials directly into a Smallstep `step-ca` Badger database.

Smallstep's open-source ACME provisioner requires EAB for locked-down account creation, but creating EAB keys through the admin API is Certificate Manager-only. This tool is intended for controlled provisioning workflows where `step-ca` is stopped, the database is updated locally on the ACME host, and the service is started again.

## Usage

```sh
acme-eab-add \
  --db /var/lib/step-ca/db \
  --kid "$kid" \
  --hmac-key "$hmac_key" \
  --reference "$machine" \
  --replace
```

`--hmac-key` must be base64url encoded without padding. `--reference` is optional, but useful for replacing a machine's previous bootstrap credential. `--provisioner-id` is optional for databases that do not use a provisioner-specific index.

## Development

```sh
go test ./...
nix build
```
