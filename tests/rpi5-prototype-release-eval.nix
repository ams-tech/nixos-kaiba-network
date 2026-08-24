{
  lib,
  pkgs,
  prototype,
  signingProfile,
}:

let
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../provisioning/policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  metadata = prototype.metadata;
  signingContract = signingProfile.signing.kaibaSigning;
  planContract = prototype.signingPlan.kaibaBootSigningPlan;
  releaseIntentContract = prototype.releaseIntent.kaibaRpi5ReleaseIntent;
  eepromInputContract = prototype.eepromSigningInputs.kaibaRpi5EEPROMReleaseSigningInputs;
  eepromPlanContract = prototype.eepromSigningPlan.kaibaRpi5EEPROMSigningPlan;
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
    releaseIntentContract.blockDeviceWriteCapable
    releaseIntentContract.directHardwareAccess
    releaseIntentContract.eepromProgrammingCapable
    releaseIntentContract.mutationCapable
    releaseIntentContract.oneTimeSettingCapable
    releaseIntentContract.otpCapable
    releaseIntentContract.privateKeyAccess
    releaseIntentContract.signingAuthorityConfigured
    eepromInputContract.blockDeviceWriteCapable
    eepromInputContract.directHardwareAccess
    eepromInputContract.eepromProgrammingCapable
    eepromInputContract.mutationCapable
    eepromInputContract.oneTimeSettingCapable
    eepromInputContract.otpCapable
    eepromInputContract.privateKeyAccess
    eepromInputContract.signingAuthorityConfigured
    eepromPlanContract.blockDeviceWriteCapable
    eepromPlanContract.directHardwareAccess
    eepromPlanContract.eepromProgrammingCapable
    eepromPlanContract.mutationCapable
    eepromPlanContract.oneTimeSettingCapable
    eepromPlanContract.otpCapable
    eepromPlanContract.privateKeyAccess
    eepromPlanContract.recoverySigningPerformed
    eepromPlanContract.signedEEPROMProduced
    eepromPlanContract.signingAuthorityConfigured
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
assert lib.assertMsg (lib.isDerivation prototype.releaseIntent)
  "the prototype release intent is not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.eepromSigningInputs)
  "the prototype EEPROM signing inputs are not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.eepromSigningPlan)
  "the prototype EEPROM signing plan is not a derivation";
assert lib.assertMsg (lib.isDerivation prototype.review)
  "the prototype release review is not a derivation";
assert lib.assertMsg (
  builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" metadata.sourceRevision != null
  && metadata.planID == "release:rpi5-prototype:${builtins.substring 0 12 metadata.sourceRevision}"
  && metadata.eepromPlanID == "${metadata.planID}:eeprom"
  && builtins.isInt metadata.sourceDateEpoch
) "the prototype release identity is not derived from canonical source metadata";
assert lib.assertMsg (
  metadata.expectedCustomerKeyHash == signingContract.expectedCustomerKeyHash
  && metadata.publicKeyFingerprint == signingContract.publicKeyFingerprint
  && metadata.signerPolicyDigest == signingContract.signerPolicyDigest
) "the prototype release metadata is not bound to the repository signing profile";
assert lib.assertMsg (
  targetPolicy.schema == "provisioning.kaiba.network/target-policy/v1alpha1"
  && targetPolicy.development_posture_id == developmentPosture.posture_id
  && targetPolicy.source_revision == metadata.sourceRevision
  && targetPolicy.expected_customer_key_hash == "sha256:${metadata.expectedCustomerKeyHash}"
  && targetPolicy.persistent_root == "dm-verity"
  && targetPolicy.mutable_state == "tmpfs-only"
  && targetPolicy.rollback_gate == "unimplemented"
  && targetPolicy.enrollment_ready == false
  && targetPolicy.videocore_jtag == developmentPosture.videocore_jtag.policy
  && targetPolicy.eeprom_write_protection == developmentPosture.eeprom_write_protection.policy
) "the prototype target policy is not bound to the release inputs or safe development posture";
assert lib.assertMsg (
  prototype.target.unsignedArtifacts == prototype.unsignedArtifacts
  && unsignedContract.sourceRevision == metadata.sourceRevision
  && unsignedContract.expectedCustomerKeyHash == metadata.expectedCustomerKeyHash
  && unsignedContract.bootOrderPolicy == developmentPosture.boot_order.policy
  && prototype.target.rootDataPartitionGUID == unsignedContract.rootDataPartitionGUID
  && prototype.target.rootHashPartitionGUID == unsignedContract.rootHashPartitionGUID
  && unsignedContract.dataDevice == "PARTUUID=${unsignedContract.rootDataPartitionGUID}"
  && unsignedContract.hashDevice == "PARTUUID=${unsignedContract.rootHashPartitionGUID}"
  && unsignedContract.rootDataPartitionGUID != unsignedContract.rootHashPartitionGUID
  && unsignedContract.schemaVersion == "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1"
  && unsignedContract.signingStatus == "unsigned"
) "the exposed prototype unsigned output differs from the target artifact set";
assert lib.assertMsg (
  planContract.bootImage == "${prototype.unsignedArtifacts}/unsigned/boot.img"
  && planContract.releaseIntent == prototype.releaseIntent
  && planContract.planID == metadata.planID
  && planContract.reviewedPublicKeyPEM == signingProfile.reviewedPublicKeyPEM
  && planContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && planContract.signerPolicyDigest == metadata.signerPolicyDigest
  && planContract.sourceDateEpoch == metadata.sourceDateEpoch
  && planContract.schemaVersion == "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2"
) "the exposed prototype signing plan differs from the reviewed public release inputs";
assert lib.assertMsg (
  releaseIntentContract.releaseID == metadata.planID
  && releaseIntentContract.expectedCustomerKeyHash == "sha256:${metadata.expectedCustomerKeyHash}"
  && releaseIntentContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && releaseIntentContract.signerPolicyDigest == metadata.signerPolicyDigest
  && releaseIntentContract.sourceDateEpoch == metadata.sourceDateEpoch
  && releaseIntentContract.sourceRevision == metadata.sourceRevision
  && releaseIntentContract.authorizationScope == "cohort_release"
) "the exposed prototype release intent differs from the reviewed public release inputs";
assert lib.assertMsg (
  eepromPlanContract.planID == metadata.eepromPlanID
  && eepromPlanContract.releaseIntent == prototype.releaseIntent
  && eepromPlanContract.publicKeyFingerprint == metadata.publicKeyFingerprint
  && eepromPlanContract.signerPolicyDigest == metadata.signerPolicyDigest
  && eepromPlanContract.customerKeyHash == "sha256:${metadata.expectedCustomerKeyHash}"
  && eepromPlanContract.sourceDateEpoch == metadata.sourceDateEpoch
  && eepromPlanContract.schemaVersion == "kaiba.provisioning.rpi5-eeprom-signing-plan/v1alpha1"
  && eepromPlanContract.updaterMode == "fresh-board"
  && eepromPlanContract.updaterFlags == [ "-f" ]
  &&
    builtins.readFile eepromPlanContract.bootConfig
    == "[all]\nBOOT_UART=${toString developmentPosture.boot_uart.value}\nBOOT_ORDER=${developmentPosture.boot_order.value}\nENABLE_SELF_UPDATE=${toString developmentPosture.self_update.value}\n"
) "the exposed prototype EEPROM signing plan differs from the reviewed public release inputs";
assert lib.assertMsg (
  reviewContract.planID == metadata.planID
  && reviewContract.eepromPlanID == metadata.eepromPlanID
  && reviewContract.releaseIntent == prototype.releaseIntent
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
    'public-eeprom-signing-plan-binding: pass' \
    'no-signing-or-mutation-capability: pass' \
    > "$out/results.txt"
''
