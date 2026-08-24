package mediacontract

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPlanAndReceiptChainIsCanonicalAndFailClosed(t *testing.T) {
	plan := minimalPlan(t)
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlan(append(canonical, '\n'))
	if err != nil || parsed.PlanDigest != plan.PlanDigest {
		t.Fatalf("ParsePlan() = %#v, %v", parsed, err)
	}

	stage, err := NewStageReceipt(plan, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 11, plan.ExpectedMediaDigest)
	if err != nil {
		t.Fatal(err)
	}
	expectedBytesWritten := plan.Target.SizeBytes
	for _, source := range plan.Layout.Sources {
		expectedBytesWritten += source.SizeBytes
	}
	if stage.BytesWritten != expectedBytesWritten || !stage.ReopenedTarget || !stage.IndependentReadbackRequired {
		t.Fatalf("stage receipt does not describe full zero+copy and same-phase reopened readback: %#v", stage)
	}
	stageJSON, err := stage.CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stageJSON, []byte("initial_media_digest")) || bytes.Contains(stageJSON, []byte("by_id_path")) {
		t.Fatalf("v1alpha2 stage receipt retained prestate or physical-media identity: %s", stageJSON)
	}
	report := successfulReport(plan)
	verification, err := NewVerificationReceipt(plan, stage, VerificationIndependentDevice, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 12, report)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := (ColdPowerObservation{
		SchemaVersion:             ColdObservationSchemaVersion,
		ObservationID:             "cold-observation:1",
		ObservationMode:           ColdObservationManual,
		TransactionID:             plan.TransactionID,
		PlanDigest:                plan.PlanDigest,
		StageReceiptDigest:        stage.ReceiptDigest,
		VerificationReceiptDigest: verification.ReceiptDigest,
		Target:                    plan.Target,
		BeforeAttachmentBootID:    stage.AttachmentBootID,
		BeforeAttachmentSequence:  stage.AttachmentSequence,
		AfterAttachmentBootID:     verification.AttachmentBootID,
		AfterAttachmentSequence:   verification.AttachmentSequence,
		CompletePowerRemoval:      true,
		CollectorEvidenceDigest:   testDigest("manual reviewed power record"),
	}).WithDerivedDigest(plan, stage, verification)
	if err != nil {
		t.Fatal(err)
	}
	final, err := Finalize(plan, stage, verification, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !final.ColdReadbackVerified || final.CaptureAuthenticated || final.FreshnessEstablished || final.HardwareObserved || final.SecurityEnforced || final.MutationEligible || final.OneTimeSettingsChanged {
		t.Fatalf("final receipt overclaimed authority: %#v", final)
	}
	finalJSON, err := final.CanonicalJSON(plan, stage, verification, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFinalReceipt(finalJSON, plan, stage, verification, observation); err != nil {
		t.Fatalf("ParseFinalReceipt(): %v", err)
	}

	mutated := final
	mutated.HardwareObserved = true
	if err := mutated.ValidateAgainst(plan, stage, verification, observation); err == nil {
		t.Fatal("final receipt accepted an unsupported hardware observation claim")
	}
	authenticated := observation
	authenticated.ObservationMode = ColdObservationMode("authenticated_collector")
	authenticated.CaptureAuthenticated = true
	authenticated.FreshnessEstablished = true
	authenticated.ObservationDigest = ""
	if _, err := authenticated.WithDerivedDigest(plan, stage, verification); err == nil {
		t.Fatal("self-authored observation claimed authenticated/fresh collector authority")
	}
	fixtureVerification, err := NewVerificationReceipt(plan, stage, VerificationRegularFixture, "", 0, report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (ColdPowerObservation{
		SchemaVersion:             ColdObservationSchemaVersion,
		ObservationID:             "fixture-cold:1",
		ObservationMode:           ColdObservationManual,
		TransactionID:             plan.TransactionID,
		PlanDigest:                plan.PlanDigest,
		StageReceiptDigest:        stage.ReceiptDigest,
		VerificationReceiptDigest: fixtureVerification.ReceiptDigest,
		Target:                    plan.Target,
		BeforeAttachmentBootID:    stage.AttachmentBootID,
		BeforeAttachmentSequence:  stage.AttachmentSequence,
		CompletePowerRemoval:      true,
		CollectorEvidenceDigest:   testDigest("fixture"),
	}).WithDerivedDigest(plan, stage, fixtureVerification); err == nil {
		t.Fatal("regular-file verification satisfied a cold-power observation")
	}
}

func TestCanonicalPlanRejectsAmbiguousOrNonCanonicalJSON(t *testing.T) {
	plan := minimalPlan(t)
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(canonical, []byte(`"schema_version":`), []byte(`"unknown":false,"schema_version":`), 1)
	duplicate := bytes.Replace(canonical, []byte(`"transaction_id":`), []byte(`"transaction_id":"duplicate","transaction_id":`), 1)
	nullValue := bytes.Replace(canonical, []byte(`"transaction_id":"transaction:media:1"`), []byte(`"transaction_id":null`), 1)
	oldVersion := bytes.Replace(canonical, []byte(`/v1alpha2"`), []byte(`/v1alpha1"`), 1)
	for name, data := range map[string][]byte{
		"pretty":    pretty.Bytes(),
		"unknown":   unknown,
		"duplicate": duplicate,
		"null":      nullValue,
		"v1alpha1":  oldVersion,
		"trailing":  append(append([]byte(nil), canonical...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlan(data); err == nil {
				t.Fatalf("ParsePlan accepted %s JSON", name)
			}
		})
	}
}

func TestVerityUsedRangesRequireWholeBlocks(t *testing.T) {
	layout := minimalPlan(t).Layout
	layout.Partitions = append([]GPTPartition(nil), layout.Partitions...)
	layout.Partitions[1].UsedSizeBytes++
	if err := layout.validateVerity(); err == nil || !strings.Contains(err.Error(), "whole number of data blocks") {
		t.Fatalf("root-data alignment error = %v", err)
	}
	layout = minimalPlan(t).Layout
	layout.Partitions = append([]GPTPartition(nil), layout.Partitions...)
	layout.Partitions[2].UsedSizeBytes++
	if err := layout.validateVerity(); err == nil || !strings.Contains(err.Error(), "whole number of hash blocks") {
		t.Fatalf("root-hash alignment error = %v", err)
	}
}

func TestPlanValidationCoversEveryByteAndRejectsSourcePaths(t *testing.T) {
	plan := minimalPlan(t)
	for index := 1; index < len(plan.Layout.Regions); index++ {
		previous := plan.Layout.Regions[index-1]
		if plan.Layout.Regions[index].OffsetBytes != previous.OffsetBytes+previous.SizeBytes {
			t.Fatalf("region %d is not contiguous", index)
		}
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{
		"/nix/store", "source_path", "by_id_path", "model", "serial", "wwid", "physical_sector_size_bytes", "initial_media_digest",
	} {
		if strings.Contains(string(encoded), prohibited) {
			t.Fatalf("production plan gained prohibited runtime or media-identity field %q: %s", prohibited, encoded)
		}
	}
	mutated := plan
	mutated.Layout.Regions = append([]MediaRegion(nil), plan.Layout.Regions...)
	mutated.Layout.Regions[3].OffsetBytes++
	mutated.Layout.LayoutDigest = ""
	if _, err := mutated.Layout.WithDerivedDigest(); err == nil {
		t.Fatal("layout accepted a one-byte gap")
	}
}

func TestMediaBindingIsCanonicalNonCircularAndPlanBound(t *testing.T) {
	plan := minimalPlan(t)
	boot, _ := plan.Layout.partition(PartitionBoot)
	data, _ := plan.Layout.partition(PartitionRootData)
	hash, _ := plan.Layout.partition(PartitionRootHash)
	binding := MediaBinding{
		SchemaVersion:               MediaBindingSchemaVersion,
		TransactionID:               plan.TransactionID,
		ReleaseID:                   plan.Release.ReleaseID,
		SignedReleaseManifestDigest: plan.Release.SignedReleaseManifestDigest,
		CapsuleDigest:               plan.Release.CapsuleDigest,
		BootImageDigest:             plan.Layout.Payloads.BootImage.Digest,
		BootSignatureDigest:         plan.Layout.Payloads.BootSignature.Digest,
		RootDataDigest:              plan.Layout.Payloads.RootData.Digest,
		RootHashTreeDigest:          plan.Layout.Payloads.RootHashTree.Digest,
		RootIntegrityDigest:         plan.Layout.Payloads.RootIntegrity.Digest,
		VerityRootHash:              plan.Layout.Verity.RootHash,
		BootPartitionGUID:           boot.UniqueGUID,
		DataPartitionGUID:           data.UniqueGUID,
		HashPartitionGUID:           hash.UniqueGUID,
	}
	canonical, err := binding.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("layout_digest")) || bytes.Contains(canonical, []byte("plan_digest")) || bytes.Contains(canonical, []byte("media_binding_digest")) || bytes.Contains(canonical, []byte("full_media_digest")) {
		t.Fatalf("media binding gained a circular field: %s", canonical)
	}
	parsed, err := ParseMediaBinding(canonical)
	if err != nil || parsed.ValidateAgainst(plan) != nil {
		t.Fatalf("parsed media binding = %#v, %v", parsed, err)
	}
	mutated := parsed
	mutated.TransactionID = "transaction:media:2"
	if err := mutated.ValidateAgainst(plan); err == nil {
		t.Fatal("media binding accepted a different transaction")
	}
	unknown := bytes.Replace(canonical, []byte(`"schema_version":`), []byte(`"plan_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":`), 1)
	if _, err := ParseMediaBinding(unknown); err == nil {
		t.Fatal("media binding accepted a circular unknown field")
	}
}

func successfulReport(plan Plan) VerificationReport {
	regions := make([]RegionVerification, len(plan.Layout.Regions))
	for index, region := range plan.Layout.Regions {
		regions[index] = RegionVerification{Role: region.Role, Digest: region.ContentDigest, Verified: true}
	}
	return VerificationReport{
		SchemaVersion:            VerificationReportSchemaVersion,
		FullMediaDigest:          plan.ExpectedMediaDigest,
		Regions:                  regions,
		GPTVerified:              true,
		FATVerified:              true,
		PartitionDigestsVerified: true,
		DMVerityVerified:         true,
		BootSignatureVerified:    true,
		ReleaseLineageVerified:   true,
	}
}

func TestLayoutRejectsFATPayloadsBeyondVerifierBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		index   int
		maximum uint64
		match   string
	}{
		{name: "boot image", index: 0, maximum: maximumVerifiedBootImageBytes, match: "boot.img exceeds"},
		{name: "boot signature", index: 1, maximum: maximumVerifiedBootSignatureBytes, match: "boot.sig exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := minimalPlan(t)
			plan.Layout.FAT.Allowlist[test.index].SizeBytes = test.maximum + 1
			if test.index == 0 {
				plan.Layout.Payloads.BootImage.SizeBytes = test.maximum + 1
			} else {
				plan.Layout.Payloads.BootSignature.SizeBytes = test.maximum + 1
			}
			if err := plan.Layout.validateFAT(); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("validateFAT() error = %v, want %q", err, test.match)
			}
		})
	}
}

func minimalPlan(t *testing.T) Plan {
	t.Helper()
	primary := ArtifactBinding{Digest: testDigest("primary gpt"), SizeBytes: AlignmentBytes}
	bootFAT := ArtifactBinding{Digest: testDigest("boot fat"), SizeBytes: AlignmentBytes}
	rootData := ArtifactBinding{Digest: testDigest("root data"), SizeBytes: 4096}
	rootHash := ArtifactBinding{Digest: testDigest("root hash tree"), SizeBytes: 4096}
	backup := ArtifactBinding{Digest: testDigest("backup gpt"), SizeBytes: AlignmentBytes}
	rootContent := testDigest("root data plus zero padding")
	hashContent := testDigest("root hash plus zero padding")
	tailContent := testDigest("three MiB of zeros")
	bootImage := ArtifactBinding{Digest: testDigest("boot image"), SizeBytes: 10}
	bootSignature := ArtifactBinding{Digest: testDigest("boot signature"), SizeBytes: 12}
	mediaBinding := ArtifactBinding{Digest: testDigest("media binding"), SizeBytes: 13}
	layout := Layout{
		SchemaVersion:   LayoutSchemaVersion,
		SectorSizeBytes: SectorSizeBytes,
		AlignmentBytes:  AlignmentBytes,
		DiskGUID:        "11111111-1111-4111-8111-111111111111",
		FirstUsableLBA:  34,
		LastUsableLBA:   8*AlignmentBytes/SectorSizeBytes - 34,
		Payloads: PayloadBindings{
			BootImage:     bootImage,
			BootSignature: bootSignature,
			RootData:      rootData,
			RootHashTree:  rootHash,
			RootIntegrity: ArtifactBinding{Digest: testDigest("root integrity"), SizeBytes: 14},
			MediaBinding:  mediaBinding,
			OuterBootFAT:  bootFAT,
			PrimaryGPT:    primary,
			BackupGPT:     backup,
		},
		Sources: []SourceBinding{
			{Role: SourcePrimaryGPT, Digest: primary.Digest, SizeBytes: primary.SizeBytes},
			{Role: SourceBootFilesystem, Digest: bootFAT.Digest, SizeBytes: bootFAT.SizeBytes},
			{Role: SourceRootData, Digest: rootData.Digest, SizeBytes: rootData.SizeBytes},
			{Role: SourceRootHash, Digest: rootHash.Digest, SizeBytes: rootHash.SizeBytes},
			{Role: SourceBackupGPT, Digest: backup.Digest, SizeBytes: backup.SizeBytes},
		},
		Regions: []MediaRegion{
			{Role: RegionPrimaryGPT, ContentKind: ContentExactFile, SourceRole: SourcePrimaryGPT, OffsetBytes: 0, SizeBytes: AlignmentBytes, SourceSizeBytes: AlignmentBytes, SourceDigest: primary.Digest, ContentDigest: primary.Digest},
			{Role: RegionBootFilesystem, ContentKind: ContentExactFile, SourceRole: SourceBootFilesystem, OffsetBytes: AlignmentBytes, SizeBytes: AlignmentBytes, SourceSizeBytes: AlignmentBytes, SourceDigest: bootFAT.Digest, ContentDigest: bootFAT.Digest},
			{Role: RegionRootData, ContentKind: ContentFileZeroPadded, SourceRole: SourceRootData, OffsetBytes: 2 * AlignmentBytes, SizeBytes: AlignmentBytes, SourceSizeBytes: rootData.SizeBytes, SourceDigest: rootData.Digest, ContentDigest: rootContent},
			{Role: RegionRootHash, ContentKind: ContentFileZeroPadded, SourceRole: SourceRootHash, OffsetBytes: 3 * AlignmentBytes, SizeBytes: AlignmentBytes, SourceSizeBytes: rootHash.SizeBytes, SourceDigest: rootHash.Digest, ContentDigest: hashContent},
			{Role: RegionTailZero, ContentKind: ContentZero, SourceRole: SourceZero, OffsetBytes: 4 * AlignmentBytes, SizeBytes: 3 * AlignmentBytes, SourceSizeBytes: 0, SourceDigest: sumBytes(nil), ContentDigest: tailContent},
			{Role: RegionBackupGPT, ContentKind: ContentExactFile, SourceRole: SourceBackupGPT, OffsetBytes: 7 * AlignmentBytes, SizeBytes: AlignmentBytes, SourceSizeBytes: AlignmentBytes, SourceDigest: backup.Digest, ContentDigest: backup.Digest},
		},
		Partitions: []GPTPartition{
			{Number: 1, Role: PartitionBoot, Name: "kaiba-boot", TypeGUID: ESPTypeGUID, UniqueGUID: "22222222-2222-4222-8222-222222222222", OffsetBytes: AlignmentBytes, SizeBytes: AlignmentBytes, UsedSizeBytes: AlignmentBytes, UsedDigest: bootFAT.Digest, PartitionDigest: bootFAT.Digest},
			{Number: 2, Role: PartitionRootData, Name: "kaiba-root", TypeGUID: ARM64RootTypeGUID, UniqueGUID: "33333333-3333-4333-8333-333333333333", OffsetBytes: 2 * AlignmentBytes, SizeBytes: AlignmentBytes, UsedSizeBytes: rootData.SizeBytes, UsedDigest: rootData.Digest, PartitionDigest: rootContent},
			{Number: 3, Role: PartitionRootHash, Name: "kaiba-root-verity", TypeGUID: ARM64VerityGUID, UniqueGUID: "44444444-4444-4444-8444-444444444444", OffsetBytes: 3 * AlignmentBytes, SizeBytes: AlignmentBytes, UsedSizeBytes: rootHash.SizeBytes, UsedDigest: rootHash.Digest, PartitionDigest: hashContent},
		},
		FAT: FATContract{
			Filesystem: "fat32", Label: "KAIBA_BOOT", VolumeID: "4b414942",
			Allowlist: []FATFile{
				{Path: "boot.img", Digest: bootImage.Digest, SizeBytes: bootImage.SizeBytes},
				{Path: "boot.sig", Digest: bootSignature.Digest, SizeBytes: bootSignature.SizeBytes},
				{Path: "config.txt", Digest: testDigest("boot_ramdisk=1\n"), SizeBytes: 15},
				{Path: "kaiba-media-binding.json", Digest: mediaBinding.Digest, SizeBytes: mediaBinding.SizeBytes},
			},
		},
		Verity: VerityContract{
			Algorithm: "sha256", RootHash: testDigest("verity root hash"),
			DataBlockSizeBytes: 4096, HashBlockSizeBytes: 4096,
			DataPartitionGUID: "33333333-3333-4333-8333-333333333333",
			HashPartitionGUID: "44444444-4444-4444-8444-444444444444",
			Mapper:            "/dev/mapper/root",
		},
	}
	var err error
	layout, err = layout.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		SchemaVersion: PlanSchemaVersion,
		TransactionID: "transaction:media:1",
		Release:       ReleaseBinding{ReleaseID: "release:rpi5:1", SignedReleaseManifestDigest: testDigest("signed release"), CapsuleDigest: testDigest("capsule")},
		Target: TargetBinding{
			SizeBytes: 8 * AlignmentBytes, LogicalSectorSizeBytes: SectorSizeBytes,
		},
		Layout:              layout,
		ExpectedMediaDigest: testDigest("expected media"),
	}
	plan, err = plan.WithDerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testDigest(value string) Digest { return sumBytes([]byte(value)) }
