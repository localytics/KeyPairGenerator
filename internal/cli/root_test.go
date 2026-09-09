package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
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

func TestGenerateAndPrint(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	stdout, stderr, err := execute(t, "--dir", dir, "--generate")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout, "SNOWFLAKE_PRIVATE_KEY_B64") {
		t.Fatalf("stdout missing secret label:\n%s", stdout)
	}

	if !strings.Contains(stdout, "ALTER USER") {
		t.Fatalf("stdout missing snowflake statement:\n%s", stdout)
	}

	if !strings.Contains(stderr, "wrote ") {
		t.Fatalf("stderr missing wrote lines:\n%s", stderr)
	}

	stdout, _, err = execute(t, "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout, "SNOWFLAKE_PRIVATE_KEY_B64") {
		t.Fatalf("reprint missing secret label:\n%s", stdout)
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

	for _, part := range []string{"--dir", "--generate", "--force", "--bits", "SNOWFLAKE_PRIVATE_KEY_B64"} {
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

func TestFreshCommandPerExecute(t *testing.T) {
	t.Parallel()

	// Documents the Cobra isolation rule: New() per Execute, never reuse.
	first := New()

	second := New()
	if first == second {
		t.Fatal("New() must return a distinct command tree")
	}
}
