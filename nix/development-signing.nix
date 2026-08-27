{
  provisioning,
  system,
}:
let
  reviewedPublicKeyPEM = ../provisioning/signers/development-prototype/reviewed-boot-public.pem;
  independentReviewPath = ../provisioning/signers/development-prototype/independent-review-2026-08-27.json;
  independentReview = builtins.fromJSON (builtins.readFile independentReviewPath);

  metadata = {
    schemaVersion = "kaiba.provisioning.development-boot-root/v1alpha1";
    classification = "development-sacrificial";
    productionApproved = false;
    independentReviewComplete = independentReview.status == "passed";
    independentReviewID = independentReview.review_id;

    signerID = "signer:prototype";
    cohortID = "cohort:prototype";
    tokenSerial = "35454358";
    pivSlot = "9c";
    pkcs11URI = "pkcs11:serial=35454358;id=%02;type=private";

    publicKeyFileSHA256 = "93923fb1b289c39e8b336b90defb881f5d15ce3832c74655b295e1a35bfdab80";
    publicKeyFingerprint = "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9";
    expectedCustomerKeyHash = "b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
    signerPolicyDigest = "sha256:c49608752c7aaf96da1976e174fb0e9f853b517bfc6df3a7f91f907ff9ca0db9";
  };

  signing = provisioning.lib.mkDevelopmentYubiKeySigning {
    inherit system;
    name = "kaiba-prototype-signing";
    inherit (metadata)
      cohortID
      expectedCustomerKeyHash
      publicKeyFingerprint
      signerID
      signerPolicyDigest
      tokenSerial
      ;
    publicKeyPEM = reviewedPublicKeyPEM;
    grantRegistryPath = "/etc/kaiba-provisioning/signing-grants.json";
  };
in
assert builtins.hashFile "sha256" reviewedPublicKeyPEM == metadata.publicKeyFileSHA256;
assert metadata.pivSlot == "9c";
assert signing.kaibaSigning.pkcs11URI == metadata.pkcs11URI;
assert independentReview.schema_version == "kaiba.provisioning.signer-independent-review/v1alpha1";
assert independentReview.scope == "development-sacrificial-signer";
assert independentReview.token.serial == metadata.tokenSerial;
assert independentReview.token.piv_slot == metadata.pivSlot;
assert independentReview.token.key_algorithm == "rsa-2048";
assert independentReview.token.key_origin == "generated-on-device";
assert independentReview.token.pin_policy == "always";
assert independentReview.token.touch_policy == "always";
assert independentReview.public_bindings.public_key_file_sha256 == metadata.publicKeyFileSHA256;
assert independentReview.public_bindings.public_key_fingerprint == metadata.publicKeyFingerprint;
assert
  independentReview.public_bindings.customer_key_hash == "sha256:${metadata.expectedCustomerKeyHash}";
assert independentReview.public_bindings.signer_policy_digest == metadata.signerPolicyDigest;
assert independentReview.signing_authorized == false;
assert independentReview.production_approved == false;
{
  inherit
    independentReview
    independentReviewPath
    metadata
    reviewedPublicKeyPEM
    signing
    ;

  unfusedVerifier = provisioning.lib.mkRpi5UnfusedVerifier {
    inherit system;
    name = "kaiba-rpi5-prototype-unfused-verifier";
    trustedPublicKeyFingerprint = signing.kaibaSigning.publicKeyFingerprint;
  };
}
