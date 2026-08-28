{
  pkgs,
  sourceRevision,
  sourceTreeClean,
}:

assert builtins.isString sourceRevision;
assert builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;
assert builtins.isBool sourceTreeClean;
pkgs.writeShellApplication {
  name = "kaiba-provision-signing-ceremony";
  runtimeInputs = with pkgs; [
    coreutils
    diffutils
    findutils
    gitMinimal
    gnused
    jq
    nix
  ];
  text = ''
    readonly packaged_source_revision=${pkgs.lib.escapeShellArg sourceRevision}
    readonly packaged_source_tree_clean=${if sourceTreeClean then "true" else "false"}
  ''
  + builtins.readFile ../scripts/signing-ceremony/kaiba-provision-signing-ceremony.sh;
  passthru.kaibaDevelopmentSigningCeremony = {
    approvalAuthoringCapable = false;
    automaticRetry = false;
    directHardwareAccess = false;
    gateControlCapable = false;
    mutationCapable = false;
    privateKeyAccess = false;
    signingAuthorityConfigured = false;
    tokenOperationCapable = false;
    inherit sourceRevision;
    inherit sourceTreeClean;
  };
  meta = {
    description = "Resumable public-only orchestration for the Raspberry Pi 5 development signing ceremony";
    platforms = [ "x86_64-linux" ];
    mainProgram = "kaiba-provision-signing-ceremony";
  };
}
