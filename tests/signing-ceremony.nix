{
  ceremony,
  pkgs,
}:

let
  ceremonyClosure = pkgs.closureInfo { rootPaths = [ ceremony ]; };
in
assert ceremony.kaibaDevelopmentSigningCeremony.approvalAuthoringCapable == false;
assert ceremony.kaibaDevelopmentSigningCeremony.automaticRetry == false;
assert ceremony.kaibaDevelopmentSigningCeremony.directHardwareAccess == false;
assert ceremony.kaibaDevelopmentSigningCeremony.gateControlCapable == false;
assert ceremony.kaibaDevelopmentSigningCeremony.mutationCapable == false;
assert ceremony.kaibaDevelopmentSigningCeremony.privateKeyAccess == false;
assert ceremony.kaibaDevelopmentSigningCeremony.signingAuthorityConfigured == false;
assert ceremony.kaibaDevelopmentSigningCeremony.tokenOperationCapable == false;
assert
  builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" ceremony.kaibaDevelopmentSigningCeremony.sourceRevision
  != null;
assert builtins.isBool ceremony.kaibaDevelopmentSigningCeremony.sourceTreeClean;

pkgs.runCommand "kaiba-development-signing-ceremony-automation-test"
  {
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      gitMinimal
      gnugrep
      jq
      shellcheck
    ];
  }
  ''
    set -euo pipefail
    shellcheck \
      ${../scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh} \
      ${./signing-ceremony/automation_test.sh}
    bash ${./signing-ceremony/automation_test.sh} \
      ${../scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh}
    test -x ${ceremony}/bin/kaiba-provision-signing-ceremony
    env -i PATH=/no-ambient-path HOME="$TMPDIR" \
      ${ceremony}/bin/kaiba-provision-signing-ceremony --help >/dev/null
    readonly forbidden_closure_pattern='/nix/store/[0-9a-z]{32}-(ykman|yubikey|yubico|opensc|pcsc|pcsclite|p11-kit|libp11|softhsm|sudo|kaiba-provision-(sign-boot|sign-eeprom|signer|signing-client|signing-gate))([.-]|$)'
    printf '%s\n' \
      '/nix/store/00000000000000000000000000000000-ykman-5.7.4' \
      '/nix/store/00000000000000000000000000000000-pcsclite-2.3.0' \
      '/nix/store/00000000000000000000000000000000-libp11-0.4.13' \
      '/nix/store/00000000000000000000000000000000-softhsm-2.6.1' \
      '/nix/store/00000000000000000000000000000000-kaiba-provision-signing-gate-0.1.0' \
      | grep -E "$forbidden_closure_pattern" >/dev/null
    cp ${ceremonyClosure}/store-paths "$TMPDIR/ceremony-closure"
    if grep -E "$forbidden_closure_pattern" "$TMPDIR/ceremony-closure"; then
      echo 'ceremony helper closure contains live signing or token authority' >&2
      exit 1
    fi
    mkdir -p "$out"
    touch "$out/passed"
  ''
