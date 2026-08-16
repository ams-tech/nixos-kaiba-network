package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxExternalDiagnosticBytes = 4096

// ExternalCommandConfig is trusted process configuration populated when the
// signer is built or launched by its service manager. It is never populated
// from a signing request or browser action.
type ExternalCommandConfig struct {
	ExecutablePath string
	FixedArguments []string
}

// ExternalCommandBackend invokes a fixed absolute executable with a fixed
// argument prefix and one internally created input file. It never invokes a
// shell, searches PATH, accepts a key path, or forwards request-controlled
// arguments.
type ExternalCommandBackend struct {
	executable string
	arguments  []string
}

func NewExternalCommandBackend(config ExternalCommandConfig) (*ExternalCommandBackend, error) {
	if config.ExecutablePath == "" || !filepath.IsAbs(config.ExecutablePath) || filepath.Clean(config.ExecutablePath) != config.ExecutablePath {
		return nil, errors.New("external signer executable must be an absolute clean path")
	}
	arguments := append([]string(nil), config.FixedArguments...)
	for index, argument := range arguments {
		if argument == "" || strings.ContainsRune(argument, '\x00') || strings.ContainsAny(argument, "\r\n") {
			return nil, fmt.Errorf("external signer fixed argument %d is invalid", index)
		}
	}
	return &ExternalCommandBackend{executable: config.ExecutablePath, arguments: arguments}, nil
}

func (s *ExternalCommandBackend) Sign(ctx context.Context, algorithm Algorithm, artifact []byte) ([]byte, error) {
	if algorithm != AlgorithmRSA2048SHA256 {
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
	temporaryDirectory, err := os.MkdirTemp("", "kaiba-provision-signer-")
	if err != nil {
		return nil, fmt.Errorf("create signer temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	inputPath := filepath.Join(temporaryDirectory, "approved-input.bin")
	input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return nil, fmt.Errorf("create signer input: %w", err)
	}
	if _, err := input.Write(artifact); err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("write signer input: %w", err)
	}
	if err := input.Close(); err != nil {
		return nil, fmt.Errorf("close signer input: %w", err)
	}

	arguments := make([]string, 0, len(s.arguments)+3)
	arguments = append(arguments, s.arguments...)
	arguments = append(arguments, "-a", string(algorithm), inputPath)
	command := exec.CommandContext(ctx, s.executable, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("external signer failed: %w%s", err, formatDiagnostic(stderr.Bytes()))
	}
	signature, err := ParseSignatureHex(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("external signer output: %w", err)
	}
	return signature, nil
}

// ParseSignatureHex accepts exactly 512 lowercase hexadecimal characters and
// an optional single trailing LF, matching Raspberry Pi's HSM wrapper output.
func ParseSignatureHex(output []byte) ([]byte, error) {
	if len(output) == RSASignatureBytes*2+1 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
	}
	if len(output) != RSASignatureBytes*2 {
		return nil, fmt.Errorf("signature must contain exactly %d lowercase hexadecimal characters", RSASignatureBytes*2)
	}
	for _, char := range output {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return nil, errors.New("signature must contain lowercase hexadecimal only")
		}
	}
	signature := make([]byte, RSASignatureBytes)
	if _, err := hex.Decode(signature, output); err != nil {
		return nil, errors.New("signature is not valid hexadecimal")
	}
	return signature, nil
}

func formatDiagnostic(diagnostic []byte) string {
	if len(diagnostic) == 0 {
		return ""
	}
	if len(diagnostic) > maxExternalDiagnosticBytes {
		diagnostic = diagnostic[:maxExternalDiagnosticBytes]
	}
	return ": " + strings.TrimSpace(string(diagnostic))
}
