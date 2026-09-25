# KeyPairGenerator

CLI that generates a PKCS#8 RSA key pair and writes the values needed for Snowflake key-pair auth and the `SNOWFLAKE_PRIVATE_KEY_B64` AWS secret key to `output.txt` and stdout. Pass `--passphrase` to encrypt the private key.

```text
$ ./keypair-generator --generate
wrote ./rsa_key.p8
wrote ./rsa_key.pub
wrote ./output.txt
AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64
LS0tLS1CRUdJTi...

Snowflake:
ALTER USER {} SET RSA_PUBLIC_KEY='MIIBIjANBgkqh...';
```

## Users

This section is for people who only need the CLI. You do not need Go, Make, or a clone of this repository.

### Download

Open the [Releases](https://github.com/localytics/KeyPairGenerator/releases) page and download the asset that matches your OS and CPU. Those files are created by the Release workflow; they are not in the repository itself.

| Platform | Architecture | Asset name |
| --- | --- | --- |
| Linux | amd64 | `keypair-generator-linux-amd64` |
| Linux | arm64 | `keypair-generator-linux-arm64` |
| Linux | 386 | `keypair-generator-linux-386` |
| Windows | amd64 | `keypair-generator-windows-amd64.exe` |
| Windows | arm64 | `keypair-generator-windows-arm64.exe` |
| Windows | 386 | `keypair-generator-windows-386.exe` |
| macOS | amd64 | `keypair-generator-darwin-amd64` |
| macOS | arm64 | `keypair-generator-darwin-arm64` |

macOS on Apple Silicon is `darwin-arm64`. Intel Macs are `darwin-amd64`. There is no 32-bit macOS build.

Each release also includes `checksums.txt` with SHA-256 hashes of every binary.

**Linux / macOS**

On the release, copy the asset URL (right-click the file → Copy link), then:

```bash
curl -sSL -o keypair-generator 'PASTE_ASSET_URL'
chmod +x keypair-generator
```

**Windows**

Download `keypair-generator-windows-amd64.exe` (or arm64 / 386) from the same Releases page, then run it from PowerShell or Command Prompt.

### Create a new key pair

Run the binary in the directory where you want the files created:

```bash
./keypair-generator --generate
```

Windows:

```bat
keypair-generator-windows-amd64.exe --generate
```

That writes `rsa_key.p8` (private), `rsa_key.pub` (public), and `output.txt` in the current directory. `output.txt` contains:

1. **`SNOWFLAKE_PRIVATE_KEY_B64`** — Base64 of the full private PEM (starts with `LS0t`, which is `-----BEGIN ...`). Paste this into the AWS secret named `SNOWFLAKE_PRIVATE_KEY_B64`. Consumers that `pem.Decode` the decoded bytes need the headers.
2. **Snowflake `ALTER USER ... SET RSA_PUBLIC_KEY`** — run this statement after replacing `{}` if you did not pass `--user`. The public key value is the PEM body only (no headers).

Treat `rsa_key.p8` and `output.txt` as secrets. Do not email them, commit them, or share them.

### Write values from existing keys

If `rsa_key.p8` and `rsa_key.pub` are already in the current directory:

```bash
./keypair-generator
```

That overwrites `output.txt` with the same Base64 values and prints the same text to stdout. The private key secret appears in your terminal and scrollback, so redirect stdout (`./keypair-generator > /dev/null`) if you only want the file.

### Verify a key pair matches

Confirm that `rsa_key.pub` actually corresponds to `rsa_key.p8` (catches a stale or mixed-up public key file):

```bash
./keypair-generator test
./keypair-generator test --dir ./snowflake-keys
```

On success it prints `OK: ... matches ...` and exits 0. On a mismatch it exits 1 with an error.

### Help

```bash
./keypair-generator help
./keypair-generator --help
```

That lists every command, flag, example, and what `output.txt` contains.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--dir`, `-d` | `.` | Directory that contains (or will receive) `rsa_key.p8`, `rsa_key.pub`, and `output.txt` |
| `--user`, `-u` | `{}` | Snowflake user written into the `ALTER USER` statement |
| `--generate`, `-g` | `false` | Create a new PKCS#8 key pair before writing `output.txt` |
| `--force`, `-f` | `false` | Allow `--generate` to overwrite existing key files |
| `--bits`, `-b` | `2048` | RSA key size used only with `--generate` (minimum 2048) |
| `--passphrase`, `-p` | | Encrypt a new private key, or decrypt an existing one. Not written to `output.txt` |
| `--help`, `-h` | | Show the same help as `help` |

Write keys in another directory, or replace an existing pair:

```bash
./keypair-generator --dir ./snowflake-keys --generate
./keypair-generator --generate --user EXAMPLE_USER
./keypair-generator --generate --force --bits 4096
./keypair-generator --generate --passphrase 'your passphrase'
```

### Tab completion

Cobra can print a completion script for bash, zsh, fish, or PowerShell. Generate it from the same binary you downloaded (or rename the binary first), then load it in your shell.

```bash
./keypair-generator completion --help
```

**This session**

```bash
source <(./keypair-generator completion bash)     # bash
source <(./keypair-generator completion zsh)      # zsh
./keypair-generator completion fish | source      # fish
```

PowerShell:

```powershell
./keypair-generator-windows-amd64.exe completion powershell | Out-String | Invoke-Expression
```

After that, Tab completes `help`, `completion`, `test`, `--dir` / `-d`, `--user` / `-u`, `--generate` / `-g`, `--force` / `-f`, `--bits` / `-b`, `--passphrase` / `-p`, directories after `--dir`, and `2048` / `4096` after `--bits`.

**Persistent**

```bash
# bash
./keypair-generator completion bash > ~/.local/share/bash-completion/completions/keypair-generator

# zsh — put this on your fpath, then run: compinit
./keypair-generator completion zsh > "${fpath[1]}/_keypair-generator"

# fish
./keypair-generator completion fish > ~/.config/fish/completions/keypair-generator.fish
```

### Key format

The CLI accepts PKCS#8 PEMs:

- An unencrypted private file is a `PRIVATE KEY` PEM block
- `--passphrase` writes an `ENCRYPTED PRIVATE KEY` block (PBES2 AES-256-CBC, PBKDF2-HMAC-SHA256). The same flag is required to read or `test` that file. The passphrase is not stored in `output.txt`; keep it somewhere else. The AWS secret is the encrypted PEM, so the consumer needs the passphrase too
- Public file must be a `PUBLIC KEY` PEM block
- An encrypted private key is rejected unless `--passphrase` is set

If the key files are missing, the process exits with an error unless you also pass `--generate`.

## Developers

### From source

Requires [Go](https://go.dev/dl/) 1.27.1 or later.

```bash
git clone https://github.com/localytics/KeyPairGenerator.git
cd KeyPairGenerator

make build
./bin/keypair-generator --generate
```

Or without Make:

```bash
go run ./cmd/keypair-generator --generate
```

### Publish binaries

Run the [Release](.github/workflows/release.yml) workflow from the Actions tab. Enter a version such as `v0.1.0`. The workflow creates that tag, pushes it, compiles `linux`, `windows`, and `darwin` for `amd64`, `arm64`, and `386` (except `darwin/386`), and attaches the binaries to the GitHub Release.

Pushing a `v*` tag yourself still runs the same build and publish jobs.

### Makefile

| Target | Action |
| --- | --- |
| `make build` | Build `bin/keypair-generator` |
| `make run` | Build, then write `output.txt` from existing keys |
| `make generate` | Build, then create a new pair in `.` and write `output.txt` |
| `make test` | Run package tests |
| `make fmt` | `go fmt` and `go vet` |
| `make lint` | Run golangci-lint |
| `make clean` | Remove `bin/`, `rsa_key` / `rsa_key.p8` / `rsa_key.pub` / `output.txt`, and coverage artifacts |
| `make help` | List targets |

### Contributing

```bash
make fmt
make test
make lint
make build
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
