{ pkgs }:

pkgs.stdenvNoCC.mkDerivation {
  pname = "kaiba-ubuntu-signing-gate-deployment";
  version = "0.1.0";

  src = ../deploy/ubuntu-signing-gate;
  dontConfigure = true;
  dontBuild = true;

  nativeCheckInputs = [
    pkgs.bash
    pkgs.shellcheck
  ];
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    ${pkgs.bash}/bin/bash -n install.sh preflight.sh provision-pin-source.sh
    ${pkgs.shellcheck}/bin/shellcheck install.sh preflight.sh provision-pin-source.sh
    grep -Fxq 'LoadCredential=yubikey-pin:/run/kaiba-provision-signing-credentials/yubikey-pin' \
      kaiba-provision-signing-gate.service.in
    grep -Fxq 'LimitCORE=0' kaiba-provision-signing-gate.service.in
    grep -Fxq 'RestrictAddressFamilies=AF_UNIX' kaiba-provision-signing-gate.service.in
    grep -Fq 'subject.user === "kaiba-signing"' 49-kaiba-signing-pcscd.rules
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    destination="$out/share/kaiba/ubuntu-signing-gate"
    mkdir -p "$destination" "$out/bin"
    install -m 0644 \
      49-kaiba-signing-pcscd.rules \
      README.md \
      kaiba-provision-signing-gate.service.in \
      kaiba-provision-signing.conf \
      "$destination/"
    install -m 0755 \
      install.sh \
      preflight.sh \
      provision-pin-source.sh \
      "$destination/"
    ln -s "$destination/install.sh" "$out/bin/kaiba-ubuntu-signing-gate-install"
    ln -s "$destination/preflight.sh" "$out/bin/kaiba-signing-gate-preflight"
    ln -s "$destination/provision-pin-source.sh" "$out/bin/kaiba-signing-gate-provision-pin"
    runHook postInstall
  '';

  passthru.kaibaUbuntuSigningGate = {
    serviceName = "kaiba-provision-signing-gate";
    serviceUser = "kaiba-signing";
    pinSource = "/run/kaiba-provision-signing-credentials/yubikey-pin";
    pinCredential = "/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin";
    registryPath = "/etc/kaiba-provisioning/signing-grants.json";
    receiptExportDirectory = "/var/lib/kaiba-provision-signing-exports";
    deploymentGcRoot = "/nix/var/nix/gcroots/kaiba-ubuntu-signing-gate-deployment";
    signingPackageGcRoot = "/nix/var/nix/gcroots/kaiba-provision-signing-gate";
    socketPath = "/run/kaiba-provision-signing/signing.sock";
    stateDirectoryPath = "/var/lib/kaiba-provision-signing";
  };

  meta = {
    description = "Inert Ubuntu 24.04 deployment bundle for the Kaiba signing gate";
    mainProgram = "kaiba-ubuntu-signing-gate-install";
    platforms = pkgs.lib.platforms.linux;
  };
}
