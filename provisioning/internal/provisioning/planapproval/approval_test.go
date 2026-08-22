package planapproval

import (
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func TestGenericAndDifferentPlanFailClosed(t *testing.T) {
	invalid := mediacontract.Plan{}
	if err := Require(invalid, ""); err == nil {
		t.Fatal("Require accepted an invalid generic plan")
	}
	// Plan mismatch behavior is exercised end-to-end by specialized package
	// checks using canonical generated plans; this unit protects the generic
	// build without duplicating the full media-plan fixture here.
}
