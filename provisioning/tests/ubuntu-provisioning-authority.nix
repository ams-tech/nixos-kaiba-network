{
  deployment,
  pkgs,
  runtimeDeployment,
}:

pkgs.runCommand "kaiba-ubuntu-provisioning-authority-deployment-test"
  {
    nativeBuildInputs = [
      pkgs.acl
      pkgs.bash
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
      pkgs.openssl
    ];
  }
  ''
    export KAIBA_AUTHORITY_TEST_PATH="$PATH"
    bash ${./deployment/ubuntu_provisioning_authority_test.sh} \
      ${deployment} \
      ${runtimeDeployment}
    mkdir -p "$out"
    touch "$out/passed"
  ''
