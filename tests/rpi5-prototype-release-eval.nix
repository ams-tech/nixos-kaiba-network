{
  lib,
  pkgs,
  prototype,
  signingProfile,
}:

let
  metadata = prototype.metadata;
  signingContract = signingProfile.signing.kaibaSigning;
  planContract = prototype.signingPlan.kaibaBootSigningPlan;
  unsignedContract = prototype.unsignedArtifacts.kaibaUnsignedArtifacts;
  reviewContract = prototype.review.kaibaPrototypeReleaseReview;
  targetConfig = prototype.target.nixosSystem.config;
  targetPolicy =
    builtins.fromJSON
      targetConfig.environment.etc."kaiba-provisioning/target-policy.json".text;
  mutationCapabilities = [
    planContract.blockDeviceWriteCapable
    planContract.directHardwareAccess
    planContract.eepromProgrammingCapable
    planContract.mutationCapable
    planContract.oneTimeSettingCapable
    planContract.otpCapable
    planContract.privateKeyAccess
    planContract.signingAuthorityConfigured
    unsignedContract.blockDeviceWriteCapable
    unsignedContract.directHardwareAccess
    unsignedContract.eepromProgrammingCapable
    unsignedContract.mutationCapable
    unsignedContract.oneTimeSettingCapable
    unsignedContract.otpCapable
    unsignedContract.privateKeyAccess
    unsignedContract.signingAuthorityConfigured
    reviewContract.blockDeviceWriteCapable
    reviewContract.directHardwareAccess
    reviewContract.eepromProgrammingCapable
    reviewContract.mutationCapable
    reviewContract.oneTimeSettingCapable
    reviewContract.otpCapable
    reviewContract.privateKeyAccess
    reviewContract.signingAuthorityConfigured
  ];
in
assert lib.assertMsg (lib.isDerivation prototype.target.system)
  "the prototype target system is not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.unsignedArtifacts)
  "the prototype unsigned artifact set is not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.signingPlan)
  "the prototype signing plan is not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.review)
  "the prototype release review is not a derivation";
assert lib.assertMsg (
  builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" metadata.sourceRevision != null
  && metadata.planID == "release:rpi5-prototype:${builtins.substring 0 12 metadata.sourceRevision}"
  && builtins.isInt metadata.sourceDateEpoch
) "the prototype release identity is not derived from canonical source metadata";
assert lib.assertMsg (
  metadata.expectedCustomerKeyHash == signingContract.expectedCustomerKeyHash
  && metadata.publicKeyFingerprint == signingContract.publicKeyFingerprint
  && metadata.signerPolicyDigest == signingContract.signerPolicyDigest
) "the prototype release metadata is not bound to the repository signing profile";
assert lib.assertMsg (
  targetPolicy.schema == "provisioning.kaiba.network/target-policy/v1alpha1"
  && targetPolicy.source_revision == metadata.sourceRevision
  && targetPolicy.expected_customer_key_hash == "sha256:${metadata.expectedCustomerKeyHash}"
  && targetPolicy.persistent_root == "dm-verity"
  && targetPolicy.mutable_state == "tmpfs-only"
  && targetPolicy.rollback_gate == "unimplemented"
  && targetPolicy.enrollment_ready == false
) "the prototype target policy is not bound to the release inputs or safe development posture";
assert lib.assertMsg (
  prototype.target.unsignedArtifacts == prototype.unsignedArtifacts
  && unsignedContract.sourceRevision == metadata.sourceRevision
  && unsignedContract.expectedCustomerKeyHash == metadata.expectedCustomerKeyHash
  && unsignedContract.schemaVersion == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
  && unsignedContract.signingStatus == "unsigned"
) "the exposed prototype unsigned output differs from the target artifact set";
assert lib.assertMsg (
  planContract.bootImage == "${prototype.unsignedArtifacts}/unsigned/boot.img"
  && planContract.planID == metadata.planID
  && planContract.reviewedPublicKeyPEM == signingProfile.reviewedPublicKeyPEM
  && planContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && planContract.signerPolicyDigest == metadata.signerPolicyDigest
  && planContract.sourceDateEpoch == metadata.sourceDateEpoch
  && planContract.schemaVersion == "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha1"
) "the exposed prototype signing plan differs from the reviewed public release inputs";
assert lib.assertMsg (
  reviewContract.planID == metadata.planID
  && reviewContract.sourceDateEpoch == metadata.sourceDateEpoch
  && reviewContract.sourceRevision == metadata.sourceRevision
) "the prototype release review is not bound to the same release identity";
assert lib.assertMsg (lib.all (value: value == false)
  mutationCapabilities
) "the prototype release path gained signing, hardware, mutation, or one-time-setting capability";
pkgs.runCommand "kaiba-rpi5-prototype-release-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'clean-source-release-identity: pass' \
    'repository-signing-profile-binding: pass' \
    'unsigned-target-binding: pass' \
    'public-signing-plan-binding: pass' \
    'no-signing-or-mutation-capability: pass' \
    > "$out/results.txt"
''
