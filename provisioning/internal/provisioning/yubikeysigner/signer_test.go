package yubikeysigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const testURI = "pkcs11:serial=12345678;id=%02;type=private"

type runnerFunc func(context.Context, Invocation) (Result, error)

func (function runnerFunc) Run(ctx context.Context, invocation Invocation) (Result, error) {
	return function(ctx, invocation)
}

type fakeOpenSSL struct {
	privateKey  *rsa.PrivateKey
	sourcePath  string
	mutateInput bool
	badVerify   bool
	signOutput  []byte

	mu    sync.Mutex
	calls []Invocation
}

func (f *fakeOpenSSL) Run(_ context.Context, invocation Invocation) (Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, Invocation{
		Path: invocation.Path,
		Args: append([]string(nil), invocation.Args...),
		Env:  append([]string(nil), invocation.Env...),
	})
	f.mu.Unlock()
	if len(invocation.Args) != 9 || invocation.Args[0] != "dgst" || invocation.Args[1] != "-sha256" {
		return Result{}, errors.New("unexpected fake OpenSSL invocation")
	}
	switch invocation.Args[2] {
	case "-sign":
		input, err := os.ReadFile(invocation.Args[8])
		if err != nil {
			return Result{}, err
		}
		digest := sha256.Sum256(input)
		signature, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA256, digest[:])
		if err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(invocation.Args[7], signature, 0o600); err != nil {
			return Result{}, err
		}
		if f.mutateInput {
			if err := os.Chmod(f.sourcePath, 0o600); err != nil {
				return Result{}, err
			}
			if err := os.WriteFile(f.sourcePath, []byte("changed after snapshot"), 0o600); err != nil {
				return Result{}, err
			}
			if err := os.Chmod(f.sourcePath, 0o400); err != nil {
				return Result{}, err
			}
		}
		return Result{Stdout: append([]byte(nil), f.signOutput...)}, nil
	case "-verify":
		input, err := os.ReadFile(invocation.Args[8])
		if err != nil {
			return Result{}, err
		}
		signature, err := os.ReadFile(invocation.Args[5])
		if err != nil {
			return Result{}, err
		}
		digest := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(&f.privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			return Result{}, err
		}
		if f.badVerify {
			return Result{Stdout: []byte("Verification Failure\n")}, nil
		}
		return Result{Stdout: []byte("Verified OK\n")}, nil
	default:
		return Result{}, errors.New("unexpected fake OpenSSL operation")
	}
}

func (f *fakeOpenSSL) invocations() []Invocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Invocation(nil), f.calls...)
}

type fixture struct {
	config     Config
	privateKey *rsa.PrivateKey
	inputPath  string
	pinPath    string
	configPath string
	openssl    string
	artifact   []byte
}

func newFixture(t *testing.T, runner Runner) fixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	opensslPath := filepath.Join(directory, "openssl")
	configPath := filepath.Join(directory, "openssl.cnf")
	providerModulePath := filepath.Join(directory, "pkcs11-provider.so")
	ykcs11ModulePath := filepath.Join(directory, "libykcs11.so.2")
	publicKeyPath := filepath.Join(directory, "public.pem")
	pinPath := filepath.Join(directory, "pin")
	inputPath := filepath.Join(directory, "input.bin")
	artifact := []byte("approved Raspberry Pi boot artifact")
	writeTestFile(t, opensslPath, []byte("fake executable\n"), 0o500)
	writeTestFile(t, providerModulePath, []byte("fake provider module\n"), 0o400)
	writeTestFile(t, ykcs11ModulePath, []byte("fake YKCS11 module\n"), 0o400)
	writeTestFile(t, configPath, canonicalOpenSSLConfig(providerModulePath, ykcs11ModulePath, pinPath), 0o400)
	writeTestFile(t, publicKeyPath, publicKeyPEM, 0o400)
	writeTestFile(t, pinPath, []byte("654321\n"), 0o400)
	writeTestFile(t, inputPath, artifact, 0o400)

	return fixture{
		config: Config{
			OpenSSLPath: opensslPath, OpenSSLConfigPath: configPath,
			PKCS11ProviderModulePath: providerModulePath, YKCS11ModulePath: ykcs11ModulePath,
			PKCS11URI: testURI, PINCredentialPath: pinPath,
			PrivateTemporaryRootPath:     directory,
			PublicKeyPEMPath:             publicKeyPath,
			ExpectedPublicKeyFingerprint: bundle.Sum(der),
			TrustedOwnerUID:              uint32(os.Geteuid()), RuntimeOwnerUID: uint32(os.Geteuid()),
			OperationTimeout: time.Second, Runner: runner,
		},
		privateKey: privateKey, inputPath: inputPath, pinPath: pinPath,
		configPath: configPath, openssl: opensslPath, artifact: artifact,
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestSignerUsesExactProviderContractAndVerifiesSignature(t *testing.T) {
	var fake *fakeOpenSSL
	fixture := newFixture(t, runnerFunc(func(ctx context.Context, invocation Invocation) (Result, error) {
		return fake.Run(ctx, invocation)
	}))
	fake = &fakeOpenSSL{privateKey: fixture.privateKey, sourcePath: fixture.inputPath}
	signer, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), fixture.inputPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture.artifact)
	if err := rsa.VerifyPKCS1v15(&fixture.privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("returned signature did not verify: %v", err)
	}

	calls := fake.invocations()
	if len(calls) != 2 {
		t.Fatalf("OpenSSL calls = %d, want 2", len(calls))
	}
	if calls[0].Path != fixture.openssl || calls[1].Path != fixture.openssl {
		t.Fatalf("executable paths = %q / %q", calls[0].Path, calls[1].Path)
	}
	expectedEnvironment := []string{"LANG=C", "LC_ALL=C", "OPENSSL_CONF=" + fixture.configPath}
	for index, call := range calls {
		if !reflect.DeepEqual(call.Env, expectedEnvironment) {
			t.Fatalf("call %d environment = %#v", index, call.Env)
		}
		joined := strings.Join(append(append([]string(nil), call.Args...), call.Env...), "\x00")
		if strings.Contains(joined, "654321") || strings.Contains(joined, fixture.pinPath) {
			t.Fatalf("call %d leaked PIN material or credential path: %#v", index, call)
		}
	}
	if got := calls[0].Args[:7]; !reflect.DeepEqual(got, []string{
		"dgst", "-sha256", "-sign", testURI, "-sigopt", "rsa_padding_mode:pkcs1", "-out",
	}) {
		t.Fatalf("sign arguments prefix = %#v", got)
	}
	if calls[0].Args[8] == fixture.inputPath {
		t.Fatal("OpenSSL received the caller's mutable input instead of a private snapshot")
	}
	if got := calls[1].Args[:3]; !reflect.DeepEqual(got, []string{"dgst", "-sha256", "-verify"}) {
		t.Fatalf("verify arguments prefix = %#v", got)
	}
}

func TestSignerRejectsChangedInputAfterSnapshot(t *testing.T) {
	var fake *fakeOpenSSL
	fixture := newFixture(t, runnerFunc(func(ctx context.Context, invocation Invocation) (Result, error) {
		return fake.Run(ctx, invocation)
	}))
	fake = &fakeOpenSSL{privateKey: fixture.privateKey, sourcePath: fixture.inputPath, mutateInput: true}
	signer, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if signature, err := signer.Sign(context.Background(), fixture.inputPath); err == nil || signature != nil || !strings.Contains(err.Error(), "changed during signing") {
		t.Fatalf("signature/error = %x/%v", signature, err)
	}
}

func TestSignerFailsClosedOnOutputOrVerificationDrift(t *testing.T) {
	tests := []struct {
		name       string
		signOutput []byte
		badVerify  bool
	}{
		{name: "sign diagnostics", signOutput: []byte("unexpected\n")},
		{name: "verification response", badVerify: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var fake *fakeOpenSSL
			fixture := newFixture(t, runnerFunc(func(ctx context.Context, invocation Invocation) (Result, error) {
				return fake.Run(ctx, invocation)
			}))
			fake = &fakeOpenSSL{
				privateKey: fixture.privateKey, sourcePath: fixture.inputPath,
				signOutput: test.signOutput, badVerify: test.badVerify,
			}
			signer, err := New(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			if signature, err := signer.Sign(context.Background(), fixture.inputPath); err == nil || signature != nil {
				t.Fatalf("signature/error = %x/%v", signature, err)
			}
		})
	}
}

func TestSignerRejectsUnsafeInputAndCredentialFiles(t *testing.T) {
	fixture := newFixture(t, runnerFunc(func(context.Context, Invocation) (Result, error) {
		t.Fatal("runner must not be called")
		return Result{}, nil
	}))
	signer, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.inputPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), fixture.inputPath); err == nil || !strings.Contains(err.Error(), "mode must be 0400") {
		t.Fatalf("unsafe input error = %v", err)
	}
	if err := os.Chmod(fixture.inputPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.pinPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), fixture.inputPath); err == nil || !strings.Contains(err.Error(), "credential mode") {
		t.Fatalf("unsafe credential error = %v", err)
	}
}

func TestSignerRejectsSymlinks(t *testing.T) {
	fixture := newFixture(t, runnerFunc(func(context.Context, Invocation) (Result, error) {
		t.Fatal("runner must not be called")
		return Result{}, nil
	}))
	signer, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(fixture.inputPath), "input-link")
	if err := os.Symlink(fixture.inputPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestNewRejectsWrongFingerprintAndNonCanonicalURI(t *testing.T) {
	fixture := newFixture(t, runnerFunc(func(context.Context, Invocation) (Result, error) {
		return Result{}, nil
	}))
	fixture.config.ExpectedPublicKeyFingerprint = bundle.Sum([]byte("wrong"))
	if _, err := New(fixture.config); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong fingerprint error = %v", err)
	}
	fixture.config.ExpectedPublicKeyFingerprint = bundle.Sum(mustPublicDER(t, fixture.privateKey))
	for _, uri := range []string{
		"pkcs11:id=%02;serial=12345678;type=private",
		"pkcs11:serial=12345678;id=%02;type=public",
		"pkcs11:serial=other;id=%02;type=private",
		"pkcs11:serial=12345678;id=%02;type=private?pin-value=123456",
	} {
		fixture.config.PKCS11URI = uri
		if _, err := New(fixture.config); err == nil {
			t.Fatalf("New accepted URI %q", uri)
		}
	}
}

func TestNewRejectsProviderConfigurationDrift(t *testing.T) {
	fixture := newFixture(t, runnerFunc(func(context.Context, Invocation) (Result, error) {
		return Result{}, nil
	}))
	if err := os.Chmod(fixture.configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	configured, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	configured = append(configured, []byte("PKCS11_PROVIDER_MODULE = /attacker/module\n")...)
	if err := os.WriteFile(fixture.configPath, configured, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.configPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := New(fixture.config); err == nil || !strings.Contains(err.Error(), "canonical provider configuration") {
		t.Fatalf("configuration drift error = %v", err)
	}
}

func mustPublicDER(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignerBoundsOperationWithContext(t *testing.T) {
	fixture := newFixture(t, runnerFunc(func(ctx context.Context, _ Invocation) (Result, error) {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}))
	fixture.config.OperationTimeout = 20 * time.Millisecond
	signer, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := signer.Sign(context.Background(), fixture.inputPath); err == nil {
		t.Fatal("timed-out signer succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}
