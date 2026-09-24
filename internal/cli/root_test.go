package cli

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/localytics/KeyPairGenerator/internal/keys"
)

func execute(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	cmd := New()
	out := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()

	return out.String(), errBuf.String(), err
}

func readOutput(t *testing.T, dir string) string {
	t.Helper()

	//nolint:gosec // G304: path is a t.TempDir() file this test just wrote
	contents, err := os.ReadFile(filepath.Join(dir, keys.OutputFile))
	if err != nil {
		t.Fatal(err)
	}

	return string(contents)
}

func outputSecret(t *testing.T, contents string) string {
	t.Helper()

	const label = "AWS secret key: SNOWFLAKE_PRIVATE_KEY_B64\n"

	_, rest, ok := strings.Cut(contents, label)
	if !ok {
		t.Fatalf("output.txt missing secret label:\n%s", contents)
	}

	secret, _, _ := strings.Cut(rest, "\n")
	if secret == "" {
		t.Fatal("empty secret")
	}

	return secret
}

func TestGenerateAndWriteOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	stdout, stderr, err := execute(t, "--dir", dir, "--generate")
	if err != nil {
		t.Fatal(err)
	}

	contents := readOutput(t, dir)
	if stdout != contents {
		t.Fatalf("stdout does not match output.txt:\nstdout:\n%s\noutput.txt:\n%s", stdout, contents)
	}

	secret := outputSecret(t, contents)
	if !strings.HasPrefix(secret, "LS0t") {
		t.Fatalf("secret %q, want prefix LS0t (base64 of PEM text)", secret)
	}

	pemBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not base64: %v", err)
	}

	if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("decoded secret %q, want PEM header", pemBytes)
	}

	if block, _ := pem.Decode(pemBytes); block == nil {
		t.Fatal("pem.Decode failed on decoded secret")
	}

	if !strings.Contains(contents, "SET RSA_PUBLIC_KEY=") {
		t.Fatalf("output.txt missing SET RSA_PUBLIC_KEY:\n%s", contents)
	}

	if strings.Contains(contents, "ADD KEY PAIR") {
		t.Fatalf("output.txt still uses ADD KEY PAIR:\n%s", contents)
	}

	if !strings.Contains(contents, "ALTER USER "+defaultUser+" ") {
		t.Fatalf("output.txt missing default user:\n%s", contents)
	}

	if !strings.Contains(stderr, "wrote ") {
		t.Fatalf("stderr missing wrote lines:\n%s", stderr)
	}

	info, err := os.Stat(filepath.Join(dir, keys.OutputFile))
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output.txt mode %o, want 0600", info.Mode().Perm())
	}
}

func TestRewriteFromExistingKeysPrintsOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate"); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}

	contents := readOutput(t, dir)
	if stdout != contents {
		t.Fatalf("stdout does not match output.txt:\n%s", stdout)
	}

	if !strings.Contains(contents, "SNOWFLAKE_PRIVATE_KEY_B64") {
		t.Fatal("rewrite missing secret label")
	}
}

func TestUserFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate", "--user", "EXAMPLE_USER"); err != nil {
		t.Fatal(err)
	}

	contents := readOutput(t, dir)
	if !strings.Contains(contents, "ALTER USER EXAMPLE_USER ") {
		t.Fatalf("output.txt missing configured user:\n%s", contents)
	}

	if strings.Contains(contents, defaultUser) {
		t.Fatalf("output.txt still has default user:\n%s", contents)
	}
}

func TestEmptyUserUsesDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate", "--user", ""); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(readOutput(t, dir), "ALTER USER "+defaultUser+" ") {
		t.Fatal("empty --user should write the default placeholder")
	}
}

func TestGenerateWithoutForceFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, _, err := execute(t, "--dir", dir, "--generate"); err != nil {
		t.Fatal(err)
	}

	_, _, err := execute(t, "--dir", dir, "--generate")
	if err == nil {
		t.Fatal("expected error")
	}

	if ExitCode(err) != 1 {
		t.Fatalf("exit %d, want 1", ExitCode(err))
	}
}

func TestBitsTooSmall(t *testing.T) {
	t.Parallel()

	_, _, err := execute(t, "--dir", t.TempDir(), "--generate", "--bits", "512")
	if err == nil {
		t.Fatal("expected error")
	}

	if ExitCode(err) != 1 {
		t.Fatalf("exit %d, want 1", ExitCode(err))
	}
}

func TestExtraArgsAreUsageError(t *testing.T) {
	t.Parallel()

	_, _, err := execute(t, "unexpected")
	if err == nil {
		t.Fatal("expected error")
	}

	if _, ok := errors.AsType[*UsageError](err); !ok {
		t.Fatalf("error %v, want UsageError", err)
	}

	if ExitCode(err) != 2 {
		t.Fatalf("exit %d, want 2", ExitCode(err))
	}
}

func TestUnknownFlagIsUsageError(t *testing.T) {
	t.Parallel()

	_, _, err := execute(t, "--nope")
	if err == nil {
		t.Fatal("expected error")
	}

	if ExitCode(err) != 2 {
		t.Fatalf("exit %d, want 2", ExitCode(err))
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()

	stdout, _, err := execute(t, "help")
	if err != nil {
		t.Fatal(err)
	}

	for _, part := range []string{"--dir", "--generate", "--force", "--bits", "--user", "SNOWFLAKE_PRIVATE_KEY_B64"} {
		if !strings.Contains(stdout, part) {
			t.Errorf("help missing %q", part)
		}
	}
}

func TestCompletion(t *testing.T) {
	t.Parallel()

	stdout, _, err := execute(t, "completion", "bash")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout, "keypair-generator") {
		t.Fatalf("completion script missing binary name:\n%s", stdout)
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: 0},
		{name: "usage", err: &UsageError{Err: errors.New("bad flag")}, want: 2},
		{name: "unknown command", err: errors.New(`unknown command "foo"`), want: 2},
		{name: "runtime", err: errors.New("read rsa_key.p8"), want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTestCommandMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate"); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "test", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout, "OK: ") {
		t.Fatalf("stdout missing OK line:\n%s", stdout)
	}
}

func TestTestCommandMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	otherDir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := execute(t, "--dir", otherDir, "--generate"); err != nil {
		t.Fatal(err)
	}

	otherPublicPath := filepath.Join(otherDir, keys.PublicFile)
	mixedPublicPath := filepath.Join(dir, keys.PublicFile)

	//nolint:gosec // G304: path is a t.TempDir() file this test just wrote
	publicBytes, err := os.ReadFile(otherPublicPath)
	if err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // G306: public key is not secret; 0644 matches WriteNewPair
	if err := os.WriteFile(mixedPublicPath, publicBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err = execute(t, "test", "--dir", dir)
	if !errors.Is(err, keys.ErrKeyMismatch) {
		t.Fatalf("error %v, want ErrKeyMismatch", err)
	}

	if ExitCode(err) != 1 {
		t.Fatalf("exit %d, want 1", ExitCode(err))
	}
}

func TestTestCommandExtraArgsAreUsageError(t *testing.T) {
	t.Parallel()

	_, _, err := execute(t, "test", "unexpected")
	if err == nil {
		t.Fatal("expected error")
	}

	if _, ok := errors.AsType[*UsageError](err); !ok {
		t.Fatalf("error %v, want UsageError", err)
	}

	if ExitCode(err) != 2 {
		t.Fatalf("exit %d, want 2", ExitCode(err))
	}
}

func TestFreshCommandPerExecute(t *testing.T) {
	t.Parallel()

	// Documents the Cobra isolation rule: New() per Execute, never reuse.
	first := New()

	second := New()
	if first == second {
		t.Fatal("New() must return a distinct command tree")
	}
}

// rsaPublicKeyStmt matches the documented RSA_PUBLIC_KEY form:
// https://docs.snowflake.com/en/user-guide/key-pair-auth
//
//	ALTER USER example_user SET RSA_PUBLIC_KEY='<public key body>';
var rsaPublicKeyStmt = regexp.MustCompile(`(?m)^ALTER USER (\S+) SET RSA_PUBLIC_KEY='([^'\n]+)';$`)

func TestRSAPublicKeyStatementMatchesSnowflakeSyntax(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := execute(t, "--dir", dir, "--generate", "--user", "EXAMPLE_USER"); err != nil {
		t.Fatal(err)
	}

	contents := readOutput(t, dir)

	m := rsaPublicKeyStmt.FindStringSubmatch(contents)
	if m == nil {
		t.Fatalf("output.txt has no ALTER USER ... SET RSA_PUBLIC_KEY statement:\n%s", contents)
	}

	if m[1] != "EXAMPLE_USER" {
		t.Fatalf("username %q, want EXAMPLE_USER", m[1])
	}

	publicKey := m[2]
	if strings.Contains(publicKey, "-----") {
		t.Fatalf("RSA_PUBLIC_KEY includes PEM delimiters: %q", publicKey)
	}

	der, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("RSA_PUBLIC_KEY is not base64: %v", err)
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("RSA_PUBLIC_KEY is not a PKIX public key: %v", err)
	}

	if _, ok := parsed.(*rsa.PublicKey); !ok {
		t.Fatalf("RSA_PUBLIC_KEY is %T, want *rsa.PublicKey", parsed)
	}
}
