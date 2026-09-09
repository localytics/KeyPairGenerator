# KeyPairGenerator

CLI that generates an unencrypted PKCS#8 RSA key pair and prints the values needed for Snowflake key-pair auth and the `SNOWFLAKE_PRIVATE_KEY_B64` AWS secret key.

```text
$ ./keypair-generator --generate
wrote ./rsa_key.p8
wrote ./rsa_key.pub
AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64
<base64 of the private PEM>

Snowflake:
ALTER USER {?user?} SET RSA_PUBLIC_KEY='<public key body>';
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

That writes `rsa_key.p8` (private) and `rsa_key.pub` (public) in the current directory, then prints:

1. **`SNOWFLAKE_PRIVATE_KEY_B64`** — Base64 of the full private PEM. Paste this into the AWS secret named `SNOWFLAKE_PRIVATE_KEY_B64`.
2. **Snowflake `ALTER USER`** — run this statement after replacing `{?user?}` with the Snowflake user.

Treat `rsa_key.p8` as a secret. Do not email it, commit it, or share it.

### Print values from existing keys

If `rsa_key.p8` and `rsa_key.pub` are already in the current directory:

```bash
./keypair-generator
```

### Help

```bash
./keypair-generator help
./keypair-generator --help
```

That lists every command, flag, example, and what the printed values mean.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--dir`, `-d` | `.` | Directory that contains (or will receive) `rsa_key.p8` and `rsa_key.pub` |
| `--generate`, `-g` | `false` | Create a new unencrypted PKCS#8 key pair before printing |
| `--force`, `-f` | `false` | Allow `--generate` to overwrite existing key files |
| `--bits`, `-b` | `2048` | RSA key size used only with `--generate` (minimum 2048) |
| `--help`, `-h` | | Show the same help as `help` |

Write keys in another directory, or replace an existing pair:

```bash
./keypair-generator --dir ./snowflake-keys --generate
./keypair-generator --generate --force --bits 4096
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

After that, Tab completes `help`, `completion`, `--dir` / `-d`, `--generate` / `-g`, `--force` / `-f`, `--bits` / `-b`, directories after `--dir`, and `2048` / `4096` after `--bits`.

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

The CLI only accepts unencrypted PKCS#8 PEMs:

- Private file must be a `PRIVATE KEY` PEM block
- Public file must be a `PUBLIC KEY` PEM block
- Encrypted private keys (`ENCRYPTED PRIVATE KEY`) are rejected

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
| `make run` | Build, then print values from existing keys |
| `make generate` | Build, then create a new pair in `.` and print values |
| `make test` | Run package tests |
| `make fmt` | `go fmt` and `go vet` |
| `make lint` | Run golangci-lint |
| `make clean` | Remove `bin/`, `rsa_key` / `rsa_key.p8` / `rsa_key.pub`, and coverage artifacts |
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
