{
  auditPackage,
  auditPort ? 8092,
  controlPackage,
  controlPort ? 8091,
  listenAddress ? "192.168.8.249",
  pkgs,
}:

let
  stationURI = "spiffe://kaiba.network/station/kaiba-rpi5-provisioner/lane/lane-1";
  approverURI = "spiffe://kaiba.network/approver/verifier";
  source = ../deploy/ubuntu-provisioning-authority;
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "kaiba-ubuntu-provisioning-authority-deployment";
  version = "0.1.0";

  dontUnpack = true;
  strictDeps = true;

  nativeBuildInputs = [
    pkgs.bash
    pkgs.shellcheck
  ];

  configurePhase = ''
    runHook preConfigure
    mkdir -p rendered
    substitute ${source}/kaiba-provisioning-control.service.in \
      rendered/kaiba-provisioning-control.service \
      --subst-var-by CONTROL_PACKAGE ${controlPackage} \
      --subst-var-by LISTEN_ADDRESS ${listenAddress} \
      --subst-var-by CONTROL_PORT ${toString controlPort}
    substitute ${source}/kaiba-provisioning-audit.service.in \
      rendered/kaiba-provisioning-audit.service \
      --subst-var-by AUDIT_PACKAGE ${auditPackage} \
      --subst-var-by LISTEN_ADDRESS ${listenAddress} \
      --subst-var-by AUDIT_PORT ${toString auditPort}
    substitute ${source}/deployment.conf.in rendered/deployment.conf \
      --subst-var-by DEPLOYMENT_PATH "$out" \
      --subst-var-by CONTROL_PACKAGE ${controlPackage} \
      --subst-var-by AUDIT_PACKAGE ${auditPackage} \
      --subst-var-by LISTEN_ADDRESS ${listenAddress} \
      --subst-var-by CONTROL_PORT ${toString controlPort} \
      --subst-var-by AUDIT_PORT ${toString auditPort} \
      --subst-var-by STATION_URI ${stationURI} \
      --subst-var-by APPROVER_URI ${approverURI}
    substitute ${source}/smoke-test.sh rendered/smoke-test.sh \
      --subst-var-by CURL ${pkgs.curl}/bin/curl
    runHook postConfigure
  '';

  dontBuild = true;

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    bash -n \
      ${source}/install.sh \
      ${source}/preflight.sh \
      ${source}/generate-development-pki.sh \
      rendered/smoke-test.sh
    shellcheck \
      ${source}/install.sh \
      ${source}/preflight.sh \
      ${source}/generate-development-pki.sh \
      rendered/smoke-test.sh
    grep -Fxq \
      'LoadCredential=server-key:/etc/kaiba-provisioning/authority/control-server.key' \
      rendered/kaiba-provisioning-control.service
    grep -Fxq \
      'LoadCredential=server-key:/etc/kaiba-provisioning/authority/audit-server.key' \
      rendered/kaiba-provisioning-audit.service
    grep -Fxq 'DynamicUser=yes' rendered/kaiba-provisioning-control.service
    grep -Fxq 'DynamicUser=yes' rendered/kaiba-provisioning-audit.service
    for unit in rendered/kaiba-provisioning-control.service rendered/kaiba-provisioning-audit.service; do
      grep -Fxq 'StateDirectoryMode=0700' "$unit"
      grep -Fxq 'LimitCORE=0' "$unit"
      grep -Fxq 'NoNewPrivileges=yes' "$unit"
      grep -Fxq 'ProtectSystem=strict' "$unit"
      grep -Fxq 'PrivateDevices=yes' "$unit"
      if grep -Eq '^(Environment|EnvironmentFile|PassEnvironment|SetCredential)=' "$unit"; then
        echo "$unit contains a secret-capable environment or inline credential" >&2
        exit 1
      fi
    done
    grep -Fxq 'STATION_URI=${stationURI}' rendered/deployment.conf
    grep -Fxq 'APPROVER_URI=${approverURI}' rendered/deployment.conf
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    destination="$out/share/kaiba/ubuntu-provisioning-authority"
    mkdir -p "$destination" "$out/bin"
    install -m 0644 \
      ${source}/README.md \
      rendered/deployment.conf \
      rendered/kaiba-provisioning-control.service \
      rendered/kaiba-provisioning-audit.service \
      "$destination/"
    install -m 0755 \
      ${source}/install.sh \
      ${source}/preflight.sh \
      ${source}/generate-development-pki.sh \
      "$destination/"
    install -m 0755 rendered/smoke-test.sh "$destination/"
    # These scripts are executed from another Nix derivation during the
    # deployment check, where /bin/bash is intentionally absent.  Use an
    # explicit runtime interpreter so this remains correct even when the
    # generic shebang hook cannot resolve a host-side /bin/bash.
    for script in \
      "$destination/install.sh" \
      "$destination/preflight.sh" \
      "$destination/generate-development-pki.sh" \
      "$destination/smoke-test.sh"; do
      substituteInPlace "$script" \
        --replace-fail '#!/bin/bash' '#!${pkgs.runtimeShell}'
    done
    ln -s "$destination/install.sh" \
      "$out/bin/kaiba-ubuntu-provisioning-authority-install"
    ln -s "$destination/preflight.sh" \
      "$out/bin/kaiba-provision-authority-preflight"
    ln -s "$destination/generate-development-pki.sh" \
      "$out/bin/kaiba-provision-authority-development-pki"
    ln -s "$destination/smoke-test.sh" \
      "$out/bin/kaiba-provision-authority-live-smoke"
    runHook postInstall
  '';

  passthru.kaibaUbuntuProvisioningAuthority = {
    inherit
      approverURI
      auditPort
      controlPort
      listenAddress
      stationURI
      ;
    auditPackagePath = toString auditPackage;
    controlPackagePath = toString controlPackage;
    authorityCredentialDirectory = "/etc/kaiba-provisioning/authority";
    auditServiceName = "kaiba-provisioning-audit";
    controlServiceName = "kaiba-provisioning-control";
    deploymentGcRoot = "/nix/var/nix/gcroots/kaiba-ubuntu-provisioning-authority-deployment";
    enabledByInstaller = false;
    startedByInstaller = false;
    serverCASeparationRequired = true;
  };

  meta = {
    description = "Inert Ubuntu deployment for the v0.1.6 development provisioning authorities";
    mainProgram = "kaiba-ubuntu-provisioning-authority-install";
    platforms = pkgs.lib.platforms.linux;
  };
}
