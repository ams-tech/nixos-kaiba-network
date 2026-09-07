{
  assets,
  pkgs,
}:

assert
  assets.development.posture.schema_version
  == "provisioning.kaiba.network/rpi5-development-posture/v1alpha1";
assert assets.development.posture.production_ready == false;
assert builtins.match "ssh-ed25519 [A-Za-z0-9+/=]+ .+" assets.development.sshAuthorizedKey != null;
assert assets.signers.developmentPrototype.independentReview.status == "passed";
assert
  assets.releases.rpi5V016.operationalPayloadManifest.schema_version
  == "kaiba.provisioning.rpi5-development-operational-payload/v1alpha1";
pkgs.runCommand "kaiba-provisioning-asset-api-contract"
  {
    nativeBuildInputs = [ pkgs.coreutils ];
  }
  ''
    set -euo pipefail

    test -f ${assets.development.posturePath}
    test -f ${assets.development.sshAuthorizedKeyPath}
    test -f ${assets.configuration.prototypeEEPROMBoot}
    test -f ${assets.configuration.prototypeReleasePlatformAdapter}
    test -f ${assets.profiles.raspberryPi5ModelB}
    test -f ${assets.signers.developmentPrototype.independentReviewPath}
    test -f ${assets.signers.developmentPrototype.reviewedBootPublicKey}

    for schema in \
      ${assets.schemas.bootSigningPlanV1Alpha2} \
      ${assets.schemas.eepromSigningPlanV1Alpha1} \
      ${assets.schemas.hardwareQualificationV1Alpha1} \
      ${assets.schemas.manualLaneQualificationV1Alpha1} \
      ${assets.schemas.platformAdapterV1Alpha1} \
      ${assets.schemas.releaseIntentV1Alpha1} \
      ${assets.schemas.signerIndependentReviewV1Alpha1} \
      ${assets.schemas.unsignedArtifactSetV1Alpha1}
    do
      test -f "$schema"
    done

    release=${assets.releases.rpi5V016.source}
    test -d "$release"
    test ! -L "$release"
    (cd "$release" && sha256sum --check --strict SHA256SUMS)

    test -d ${assets.releases.rpi5V016.signedInputs.bootSignedOutput}
    test -d ${assets.releases.rpi5V016.signedInputs.eepromSignedOutput}
    test -d ${assets.releases.rpi5V016.signedInputs.ownedRecoverySignedOutput}
    test -f ${assets.releases.rpi5V016.signedInputs.signingGrantRegistry}
    test -f ${assets.releases.rpi5V016.signedInputs.signingReceiptExport}

    mkdir -p "$out"
    touch "$out/passed"
  ''
