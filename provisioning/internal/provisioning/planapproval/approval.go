// Package planapproval enforces the linker-fixed plan authority of one
// specialized staging or verification binary.
package planapproval

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func Require(plan mediacontract.Plan, approvedPath string) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if approvedPath == "" || !filepath.IsAbs(approvedPath) || filepath.Clean(approvedPath) != approvedPath || !strings.HasPrefix(approvedPath, "/nix/store/") {
		return errors.New("generic build has no linker-fixed approved media plan store path")
	}
	approved, err := mediacontract.LoadPlan(approvedPath)
	if err != nil {
		return errors.New("load linker-fixed approved media plan: " + err.Error())
	}
	if plan.PlanDigest != approved.PlanDigest {
		return errors.New("caller media plan differs from the linker-fixed approved plan")
	}
	actual, err := plan.CanonicalJSON()
	if err != nil {
		return err
	}
	expected, err := approved.CanonicalJSON()
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("caller media plan content differs from the linker-fixed approved plan")
	}
	return nil
}
