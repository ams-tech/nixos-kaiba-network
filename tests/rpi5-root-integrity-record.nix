{
  lib,
  pkgs,
}:

let
  expected = pkgs.writeText "kaiba-root-integrity-record-fixture.json" ''
    {"schema":"provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1","algorithm":"sha256","data_block_size":4096,"hash_block_size":4096,"no_superblock":false,"root_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","data_device":"PARTUUID=bdd5be20-f7ea-56e7-ae90-4465ae950596","hash_device":"PARTUUID=62616022-71fb-5036-8cc4-b7949cc6e52c"}
  '';
  fatFixture =
    pkgs.runCommand "kaiba-root-integrity-fat-fixture" { nativeBuildInputs = [ pkgs.mtools ]; }
      ''
        mkdir "$out"
        truncate --size=4M "$out/boot.img"
        mformat -i "$out/boot.img" -F ::
        mcopy -i "$out/boot.img" ${expected} ::kaiba-root-integrity.json
        chmod 0444 "$out/boot.img"
      '';
  extracted = (import ../nix/rpi5-root-integrity-record.nix { inherit pkgs; }) {
    bootImage = "${fatFixture}/boot.img";
    name = "kaiba-rpi5-root-integrity-record-test-output.json";
  };
in
assert lib.assertMsg (lib.isDerivation extracted)
  "the root-integrity extractor did not return a derivation";
pkgs.runCommand "kaiba-rpi5-root-integrity-record-test" { } ''
  cmp ${expected} ${extracted}
  mkdir "$out"
  touch "$out/passed"
''
