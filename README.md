# KeyPairGenerator

CLI that generates an unencrypted PKCS#8 RSA key pair and prints the values needed for Snowflake key-pair auth and the `SNOWFLAKE_PRIVATE_KEY_B64` AWS secret key.

```text
$ ./keypair-generator -generate
wrote ./rsa_key.p8
wrote ./rsa_key.pub
AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64
<base64 of the private PEM>

Snowflake:
ALTER USER auditorium SET RSA_PUBLIC_KEY='<public key body>';
```

## Users

This section is for people who only need the CLI. You do not need Go, Make, or a clone of this repository.

### Download

Get the binary for your OS and CPU from the [latest GitHub Release](https://github.com/localytics/KeyPairGenerator/releases/latest):

| Platform | Architecture | Download |
| --- | --- | --- |
| Linux | amd64 | [keypair-generator-linux-amd64](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-linux-amd64) |
| Linux | arm64 | [keypair-generator-linux-arm64](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-linux-arm64) |
| Linux | 386 | [keypair-generator-linux-386](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-linux-386) |
| Windows | amd64 | [keypair-generator-windows-amd64.exe](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-windows-amd64.exe) |
| Windows | arm64 | [keypair-generator-windows-arm64.exe](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-windows-arm64.exe) |
| Windows | 386 | [keypair-generator-windows-386.exe](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-windows-386.exe) |
| macOS | amd64 | [keypair-generator-darwin-amd64](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-darwin-amd64) |
| macOS | arm64 | [keypair-generator-darwin-arm64](https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-darwin-arm64) |

macOS on Apple Silicon is `darwin-arm64`. Intel Macs are `darwin-amd64`. There is no 32-bit macOS build.

Each release also includes `checksums.txt` with SHA-256 hashes of every binary.

**Linux / macOS**

```bash
curl -sSL -o keypair-generator \
  https://github.com/localytics/KeyPairGenerator/releases/latest/download/keypair-generator-darwin-arm64
chmod +x keypair-generator
```

Replace the download URL with the row from the table that matches your machine.

**Windows**

Download `keypair-generator-windows-amd64.exe` (or arm64 / 386) from the release page, then run it from PowerShell or Command Prompt.

### Create a new key pair

Run the binary in the directory where you want the files created:

```bash
./keypair-generator -generate
```

Windows:

```bat
keypair-generator-windows-amd64.exe -generate
```

That writes `rsa_key.p8` (private) and `rsa_key.pub` (public) in the current directory, then prints:

1. **`SNOWFLAKE_PRIVATE_KEY_B64`** — Base64 of the full private PEM. Paste this into the AWS secret named `SNOWFLAKE_PRIVATE_KEY_B64`.
2. **Snowflake `ALTER USER`** — run this statement so user `auditorium` gets the matching public key.

Treat `rsa_key.p8` as a secret. Do not email it, commit it, or share it.

### Print values from existing keys

If `rsa_key.p8` and `rsa_key.pub` are already in the current directory:

```bash
./keypair-generator
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-dir` | `.` | Directory that contains (or will receive) `rsa_key.p8` and `rsa_key.pub` |
| `-generate` | `false` | Create a new unencrypted PKCS#8 key pair before printing |
| `-force` | `false` | Allow `-generate` to overwrite existing key files |
| `-bits` | `2048` | RSA key size used only with `-generate` |

Write keys in another directory, or replace an existing pair:

```bash
./keypair-generator -dir ./snowflake-keys -generate
./keypair-generator -generate -force -bits 4096
```

### Key format

The CLI only accepts unencrypted PKCS#8 PEMs:

- Private file must contain `-----BEGIN PRIVATE KEY-----`
- Public file must contain `-----BEGIN PUBLIC KEY-----`
- Encrypted private keys (`BEGIN ENCRYPTED PRIVATE KEY`) are rejected

If the key files are missing, the process exits with an error unless you also pass `-generate`.

## Developers

### From source

Requires [Go](https://go.dev/dl/) 1.27.1 or later.

```bash
git clone https://github.com/localytics/KeyPairGenerator.git
cd KeyPairGenerator

make build
./bin/keypair-generator -generate
```

Or without Make:

```bash
go run . -generate
```

### Publish binaries

Pushing a `v*` tag runs the [Release](.github/workflows/release.yml) workflow, which compiles `linux`, `windows`, and `darwin` for `amd64`, `arm64`, and `386` (except `darwin/386`) and attaches them to that tag's GitHub Release.

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Makefile

| Target | Action |
| --- | --- |
| `make build` | Build `bin/keypair-generator` |
| `make run` | Build, then print values from existing keys |
| `make generate` | Build, then create a new pair in `.` and print values |
| `make test` | Run package tests |
| `make fmt` | `go fmt` and `go vet` |
| `make clean` | Remove `bin/`, `rsa_key` / `rsa_key.p8` / `rsa_key.pub`, and coverage artifacts |
| `make help` | List targets |

### Contributing

```bash
make fmt
make test
make build
```

## License

No license file is published in this repository.
