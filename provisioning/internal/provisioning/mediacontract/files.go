package mediacontract

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func ReadBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("input path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open non-symlink input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("input exceeds %d bytes", maximum)
	}
	return data, nil
}

func LoadPlan(path string) (Plan, error) {
	data, err := ReadBoundedRegularFile(path, maximumContractBytes)
	if err != nil {
		return Plan{}, err
	}
	return ParsePlan(data)
}

func LoadStageReceipt(path string, plan Plan) (StageReceipt, error) {
	data, err := ReadBoundedRegularFile(path, maximumContractBytes)
	if err != nil {
		return StageReceipt{}, err
	}
	return ParseStageReceipt(data, plan)
}

func LoadVerificationReceipt(path string, plan Plan, stage StageReceipt) (VerificationReceipt, error) {
	data, err := ReadBoundedRegularFile(path, maximumContractBytes)
	if err != nil {
		return VerificationReceipt{}, err
	}
	return ParseVerificationReceipt(data, plan, stage)
}

func LoadColdPowerObservation(path string, plan Plan, stage StageReceipt, verification VerificationReceipt) (ColdPowerObservation, error) {
	data, err := ReadBoundedRegularFile(path, maximumContractBytes)
	if err != nil {
		return ColdPowerObservation{}, err
	}
	return ParseColdPowerObservation(data, plan, stage, verification)
}

func LoadRuntimeFacts(path string) (RuntimeFacts, error) {
	data, err := ReadBoundedRegularFile(path, maximumContractBytes)
	if err != nil {
		return RuntimeFacts{}, err
	}
	return ParseRuntimeFacts(data)
}
