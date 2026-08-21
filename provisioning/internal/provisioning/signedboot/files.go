package signedboot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

var planFileLimits = map[string]int64{
	"plan.json":  maxPlanBytes,
	"boot.img":   int64(signing.MaxArtifactBytes),
	"public.pem": maxPublicKeyBytes,
}

var signedFileLimits = map[string]int64{
	"boot.sig":            maxBootSigBytes,
	"signing-result.json": maxResultBytes,
}

// LoadPlanDirectory opens an absolute, non-symlink directory containing
// exactly plan.json, boot.img, and public.pem and validates every binding.
func LoadPlanDirectory(path string) (LoadedPlan, error) {
	files, err := readExactDirectory(path, planFileLimits)
	if err != nil {
		return LoadedPlan{}, fmt.Errorf("load signing plan directory: %w", err)
	}
	plan, err := parsePlan(files["plan.json"])
	if err != nil {
		return LoadedPlan{}, err
	}
	canonicalPlan, err := plan.CanonicalJSON()
	if err != nil {
		return LoadedPlan{}, err
	}
	if !bytes.Equal(files["plan.json"], jsonFile(canonicalPlan)) {
		return LoadedPlan{}, errors.New("plan.json is not canonical JSON")
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return LoadedPlan{}, err
	}
	publicKey, fingerprint, err := parsePublicKey(files["public.pem"])
	if err != nil {
		return LoadedPlan{}, err
	}
	if plan.PublicKeyFingerprint != fingerprint {
		return LoadedPlan{}, errors.New("public.pem fingerprint does not match the signing plan")
	}
	if uint64(len(files["boot.img"])) != plan.BootImageSizeBytes {
		return LoadedPlan{}, errors.New("boot.img size does not match the signing plan")
	}
	if digest := bundle.Sum(files["boot.img"]); digest != plan.BootImageDigest {
		return LoadedPlan{}, errors.New("boot.img digest does not match the signing plan")
	}
	return LoadedPlan{
		Plan: plan, PlanJSON: canonicalPlan, BootImage: files["boot.img"],
		PublicPEM: files["public.pem"], PublicKey: publicKey, PlanDigest: planDigest,
	}, nil
}

// LoadResultDirectory opens an absolute, non-symlink directory containing
// exactly boot.sig and signing-result.json. Cryptographic and plan bindings
// are checked by Finalize.
func LoadResultDirectory(path string) (LoadedResult, error) {
	files, err := readExactDirectory(path, signedFileLimits)
	if err != nil {
		return LoadedResult{}, fmt.Errorf("load signing result directory: %w", err)
	}
	result, err := parseResult(files["signing-result.json"])
	if err != nil {
		return LoadedResult{}, err
	}
	canonicalResult, err := result.CanonicalJSON()
	if err != nil {
		return LoadedResult{}, err
	}
	if !bytes.Equal(files["signing-result.json"], jsonFile(canonicalResult)) {
		return LoadedResult{}, errors.New("signing-result.json is not canonical JSON")
	}
	return LoadedResult{Result: result, ResultJSON: canonicalResult, BootSig: files["boot.sig"]}, nil
}

func readExpectedPublicKey(path string) ([]byte, bundle.Digest, error) {
	encoded, err := readAbsoluteRegularFile(path, maxPublicKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read configured public key: %w", err)
	}
	_, fingerprint, err := parsePublicKey(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("validate configured public key: %w", err)
	}
	return encoded, fingerprint, nil
}

func readExactDirectory(path string, expected map[string]int64) (map[string][]byte, error) {
	if err := validateExistingAbsolutePath(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("input path must be a non-symlink directory")
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input directory changed while opening")
	}
	if err := requireExactDirectoryEntries(directory, expected); err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(expected))
	for name, maximum := range expected {
		contents, err := readRegularFileAt(directory, name, maximum)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		files[name] = contents
	}
	if err := requireExactDirectoryEntries(directory, expected); err != nil {
		return nil, fmt.Errorf("input directory changed while reading: %w", err)
	}
	after, err := directory.Stat()
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("input directory identity changed while reading")
	}
	return files, nil
}

func requireExactDirectoryEntries(directory *os.File, expected map[string]int64) error {
	if _, err := directory.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind input directory: %w", err)
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list input directory: %w", err)
	}
	sort.Strings(names)
	wanted := make([]string, 0, len(expected))
	for name := range expected {
		wanted = append(wanted, name)
	}
	sort.Strings(wanted)
	if len(names) != len(wanted) {
		return fmt.Errorf("input directory must contain exactly %s", strings.Join(wanted, ", "))
	}
	for index := range wanted {
		if names[index] != wanted[index] {
			return fmt.Errorf("input directory must contain exactly %s", strings.Join(wanted, ", "))
		}
	}
	return nil
}

func readRegularFileAt(directory *os.File, name string, maximum int64) ([]byte, error) {
	if name == "" || filepath.Base(name) != name || maximum <= 0 {
		return nil, errors.New("invalid fixed input file configuration")
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open input file")
	}
	defer file.Close()
	return readOpenedRegularFile(file, maximum)
}

func readAbsoluteRegularFile(path string, maximum int64) ([]byte, error) {
	if err := validateExistingAbsolutePath(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input changed while opening")
	}
	return readOpenedRegularFile(file, maximum)
}

func readOpenedRegularFile(file *os.File, maximum int64) ([]byte, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if before.Size() <= 0 || before.Size() > maximum {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", maximum)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != before.Size() {
		return nil, errors.New("input changed while reading")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("input identity changed while reading")
	}
	return contents, nil
}

func validateExistingAbsolutePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return errors.New("path must be absolute and clean")
	}
	current := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(path, current), current)
	for _, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
	}
	return nil
}

func validateNewOutputPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || strings.IndexByte(path, 0) >= 0 {
		return errors.New("output path must be absolute and clean")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("output path already exists")
		}
		return err
	}
	parent := filepath.Dir(path)
	if err := validateExistingAbsolutePath(parent); err != nil {
		return fmt.Errorf("output parent: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("output parent must be an existing directory")
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	relative, err := filepath.Rel(left, right)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(right, left)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func sameLoadedPlan(left, right LoadedPlan) bool {
	return left.Plan == right.Plan && left.PlanDigest == right.PlanDigest &&
		bytes.Equal(left.PlanJSON, right.PlanJSON) && bytes.Equal(left.BootImage, right.BootImage) &&
		bytes.Equal(left.PublicPEM, right.PublicPEM)
}

func sameLoadedResult(left, right LoadedResult) bool {
	return left.Result == right.Result && bytes.Equal(left.ResultJSON, right.ResultJSON) && bytes.Equal(left.BootSig, right.BootSig)
}

func createAtomicDirectory(path string, files map[string][]byte) error {
	if err := validateNewOutputPath(path); err != nil {
		return err
	}
	lockPath := path + ".kaiba-create-lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("reserve output path: %w", err)
	}
	if err := lock.Close(); err != nil {
		_ = os.Remove(lockPath)
		return fmt.Errorf("close output reservation: %w", err)
	}
	defer os.Remove(lockPath)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("output path already exists")
		}
		return err
	}
	parent := filepath.Dir(path)
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary output directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	for name, contents := range files {
		if name == "" || filepath.Base(name) != name {
			return errors.New("output file name must be a single path component")
		}
		filePath := filepath.Join(temporary, name)
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o644)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := file.Write(contents); err != nil {
			_ = file.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}
	if err := os.Chmod(temporary, 0o755); err != nil {
		return fmt.Errorf("set output directory mode: %w", err)
	}
	if err := syncDirectory(temporary); err != nil {
		return err
	}
	// The kernel must enforce non-replacement at the publication instant. A
	// preceding Lstat followed by os.Rename is insufficient because rename(2)
	// may replace an empty directory created in between those operations.
	if err := renameNoReplace(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("output path appeared while creating the bundle")
		}
		return fmt.Errorf("publish output directory: %w", err)
	}
	committed = true
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync output parent: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func jsonFile(encoded []byte) []byte {
	return append(append([]byte(nil), encoded...), '\n')
}
