package mediacontract

import (
	"bytes"
	"strings"
	"testing"
)

func TestUARTRecordsAreExactBoundedAndOrdered(t *testing.T) {
	facts := testRuntimeFacts()
	records, err := BuildUARTRecords(facts)
	if err != nil {
		t.Fatal(err)
	}
	text, err := records.Text(facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(records.CompatibilityLine) > MaximumUARTRecordBytes || len(records.DMVerityLine) > MaximumUARTRecordBytes {
		t.Fatal("UART record exceeded its fixed bound")
	}
	capture := append([]byte("firmware diagnostic\r\n"), text...)
	parsed, err := ParseUARTCapture(capture, facts)
	if err != nil || parsed != records {
		t.Fatalf("ParseUARTCapture() = %#v, %v", parsed, err)
	}

	lines := bytes.Split(bytes.TrimSuffix(text, []byte{'\n'}), []byte{'\n'})
	tests := map[string][]byte{
		"reordered":      append(append(append([]byte(nil), lines[1]...), '\n'), append(lines[0], '\n')...),
		"duplicate":      append(append([]byte(nil), text...), append(lines[0], '\n')...),
		"extra field":    bytes.Replace(text, []byte(" boot_ramdisk=true"), []byte(" forged=true boot_ramdisk=true"), 1),
		"wrong digest":   bytes.Replace(text, []byte(facts.BootImageDigest), []byte(testDigest("wrong boot")), 1),
		"pass suffix":    []byte("KAIBA_UNFUSED_COMPATIBILITY=passx\n" + records.DMVerityLine + "\n"),
		"active suffix":  []byte(records.CompatibilityLine + "\nKAIBA_DM_VERITY=activex\n"),
		"nul":            append(append([]byte(nil), text...), 0),
		"oversized line": append(bytes.Repeat([]byte{'x'}, MaximumUARTRecordBytes+1), '\n'),
	}
	for name, capture := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseUARTCapture(capture, facts); err == nil {
				t.Fatalf("accepted %s UART capture", name)
			}
		})
	}
}

func TestRuntimeFactsRequireIndependentPlanCorrelation(t *testing.T) {
	plan := minimalPlan(t)
	facts := runtimeFactsForPlan(plan)
	if err := facts.ValidateAgainst(plan); err != nil {
		t.Fatal(err)
	}
	mutated := facts
	mutated.BootImageDigest = testDigest("caller-authored forgery")
	if err := mutated.Validate(); err != nil {
		t.Fatalf("syntactically valid fixture mutation unexpectedly failed: %v", err)
	}
	if err := mutated.ValidateAgainst(plan); err == nil {
		t.Fatal("runtime facts accepted caller-authored values not bound to the plan")
	}
	canonical, err := facts.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("plan_digest")) {
		t.Fatal("target runtime facts claimed a circular, non-observable plan digest")
	}
}

func TestRuntimeFactsCannotClaimOwnedOrMutableState(t *testing.T) {
	facts := testRuntimeFacts()
	mutations := []func(*RuntimeFacts){
		func(value *RuntimeFacts) { value.BootRAMDisk = false },
		func(value *RuntimeFacts) { value.RootReadOnly = false },
		func(value *RuntimeFacts) { value.EnrollmentReady = true },
		func(value *RuntimeFacts) { value.CustomerKeyOTP = true },
		func(value *RuntimeFacts) { value.DataPARTUUID = value.HashPARTUUID },
		func(value *RuntimeFacts) { value.Mapper = "/dev/mapper/other" },
	}
	for index, mutate := range mutations {
		candidate := facts
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("runtime facts mutation %d was accepted", index)
		}
	}
	canonical, err := facts.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), "hardware_observed") || strings.Contains(string(canonical), "security_enforced") {
		t.Fatal("runtime-facts contract gained an authority claim")
	}
}

func testRuntimeFacts() RuntimeFacts {
	return RuntimeFacts{
		SchemaVersion:               RuntimeFactsSchemaVersion,
		TransactionID:               "transaction:media:1",
		ReleaseID:                   "release:rpi5:1",
		SignedReleaseManifestDigest: testDigest("release"),
		MediaBindingDigest:          testDigest("binding"),
		BootImageDigest:             testDigest("boot image"),
		BootSignatureDigest:         testDigest("boot signature"),
		RootDataDigest:              testDigest("root data"),
		RootHashTreeDigest:          testDigest("root hash tree"),
		VerityRootHash:              testDigest("verity root hash"),
		DataPARTUUID:                "PARTUUID=33333333-3333-4333-8333-333333333333",
		HashPARTUUID:                "PARTUUID=44444444-4444-4444-8444-444444444444",
		Mapper:                      "/dev/mapper/root",
		BootRAMDisk:                 true,
		RootReadOnly:                true,
		EnrollmentReady:             false,
		CustomerKeyOTP:              false,
	}
}

func runtimeFactsForPlan(plan Plan) RuntimeFacts {
	return RuntimeFacts{
		SchemaVersion: RuntimeFactsSchemaVersion, TransactionID: plan.TransactionID,
		ReleaseID: plan.Release.ReleaseID, SignedReleaseManifestDigest: plan.Release.SignedReleaseManifestDigest,
		MediaBindingDigest: plan.Layout.Payloads.MediaBinding.Digest, BootImageDigest: plan.Layout.Payloads.BootImage.Digest,
		BootSignatureDigest: plan.Layout.Payloads.BootSignature.Digest, RootDataDigest: plan.Layout.Payloads.RootData.Digest,
		RootHashTreeDigest: plan.Layout.Payloads.RootHashTree.Digest, VerityRootHash: plan.Layout.Verity.RootHash,
		DataPARTUUID: "PARTUUID=" + plan.Layout.Verity.DataPartitionGUID,
		HashPARTUUID: "PARTUUID=" + plan.Layout.Verity.HashPartitionGUID,
		Mapper:       plan.Layout.Verity.Mapper, BootRAMDisk: true, RootReadOnly: true,
	}
}
