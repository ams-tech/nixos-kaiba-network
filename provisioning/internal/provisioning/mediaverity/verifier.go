// Package mediaverity is the read-only adapter from the pure media contract to
// one immutable veritysetup executable selected by the containing Nix build.
package mediaverity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

const maximumOutputBytes = 64 * 1024

type FixedVerifier struct {
	Path string
}

func (verifier FixedVerifier) Validate() error {
	if verifier.Path == "" || !filepath.IsAbs(verifier.Path) || filepath.Clean(verifier.Path) != verifier.Path || !strings.HasPrefix(verifier.Path, "/nix/store/") {
		return errors.New("generic build has no linker-fixed veritysetup store authority")
	}
	info, err := os.Lstat(verifier.Path)
	if err != nil {
		return fmt.Errorf("inspect linker-fixed veritysetup: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("linker-fixed veritysetup must be an executable non-symlink regular file")
	}
	return nil
}

func (verifier FixedVerifier) Verify(ctx context.Context, target io.ReaderAt, data, hash mediacontract.GPTPartition, contract mediacontract.VerityContract) error {
	if err := verifier.Validate(); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("", "kaiba-media-verity-")
	if err != nil {
		return fmt.Errorf("create private verity workspace: %w", err)
	}
	defer os.RemoveAll(temporary) //nolint:errcheck
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	dataPath := filepath.Join(temporary, "root-data.img")
	hashPath := filepath.Join(temporary, "root-hash.img")
	if err := extractRange(target, data.OffsetBytes, data.UsedSizeBytes, dataPath); err != nil {
		return fmt.Errorf("extract root-data used range: %w", err)
	}
	if err := extractRange(target, hash.OffsetBytes, hash.UsedSizeBytes, hashPath); err != nil {
		return fmt.Errorf("extract root-hash used range: %w", err)
	}
	command := exec.CommandContext(ctx, verifier.Path,
		"verify",
		fmt.Sprintf("--data-block-size=%d", contract.DataBlockSizeBytes),
		fmt.Sprintf("--hash-block-size=%d", contract.HashBlockSizeBytes),
		dataPath,
		hashPath,
		strings.TrimPrefix(string(contract.RootHash), "sha256:"),
	)
	command.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/nonexistent"}
	output := &boundedBuffer{maximum: maximumOutputBytes}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if output.overflow {
			return errors.New("veritysetup output exceeded the fixed diagnostic bound")
		}
		return fmt.Errorf("linker-fixed veritysetup rejected the staged pair: %w: %s", err, strings.TrimSpace(output.String()))
	}
	if output.overflow {
		return errors.New("veritysetup output exceeded the fixed diagnostic bound")
	}
	return nil
}

func extractRange(target io.ReaderAt, offset, size uint64, destination string) error {
	maximumInt64 := uint64(^uint64(0) >> 1)
	if target == nil || offset > maximumInt64 || size > maximumInt64 || offset+size < offset || offset+size > maximumInt64 {
		return errors.New("verity range exceeds supported file offsets")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return err
	}
	section := io.NewSectionReader(target, int64(offset), int64(size))
	_, copyErr := io.CopyN(file, section, int64(size))
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if buffer.Len()+len(value) <= buffer.maximum {
		return buffer.Buffer.Write(value)
	}
	remaining := buffer.maximum - buffer.Len()
	if remaining > 0 {
		_, _ = buffer.Buffer.Write(value[:remaining])
	}
	buffer.overflow = true
	return len(value), nil
}
