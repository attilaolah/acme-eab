# `acme-eab-add`

![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/attilaolah/acme-eab?utm_source=oss&utm_medium=github&utm_campaign=attilaolah%2Facme-eab&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

`acme-eab-add` writes ACME External Account Binding credentials directly into a Smallstep `step-ca` Badger database.

Smallstep's open-source ACME provisioner requires EAB for locked-down account creation, but creating EAB keys through
the admin API is Certificate Manager-only. This tool is intended for controlled provisioning workflows where `step-ca`
is stopped, the database is updated locally on the ACME host, and the service is started again.

## Usage

```sh
acme-eab-add \
  --db /var/lib/step-ca/db \
  --kid "$kid" \
  --hmac-key "$hmac_key" \
  --reference "$machine" \
  --replace
```

- `--hmac-key` must be base64url encoded without padding
- `--reference` is optional, but useful for replacing a machine's previous bootstrap credential
- `--provisioner-id` is optional for databases that do not use a provisioner-specific index

## Development

```sh
go test ./...
nix build
```

## Vibe coded

Yes this is entirely vibe-coded. You have been warned.
