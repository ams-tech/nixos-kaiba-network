{ pkgs }:

{
  bootImage,
  name ? "kaiba-rpi5-root-integrity.json",
}:

pkgs.runCommand name
  {
    bootImageInput = bootImage;
    nativeBuildInputs = [
      pkgs.jq
      pkgs.mtools
    ];
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    test -f "$bootImageInput"
    test ! -L "$bootImageInput"
    mtype -i "$bootImageInput" ::kaiba-root-integrity.json > "$out"
    jq -e '
      (keys | sort) == [
        "algorithm",
        "data_block_size",
        "data_device",
        "hash_block_size",
        "hash_device",
        "no_superblock",
        "root_hash",
        "schema"
      ]
      and .schema == "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1"
      and .algorithm == "sha256"
      and .data_block_size == 4096
      and .hash_block_size == 4096
      and .no_superblock == false
      and (.root_hash | test("^[0-9a-f]{64}$"))
      and (.data_device | test("^PARTUUID=[0-9a-f-]{36}$"))
      and (.hash_device | test("^PARTUUID=[0-9a-f-]{36}$"))
    ' "$out" > /dev/null
    test "$(tail -c 1 "$out" | od -An -tu1 | tr -d ' ')" = 10
    chmod 0444 "$out"
  ''
