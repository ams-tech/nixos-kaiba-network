{ pkgs }:

# This PKI exists only inside the isolated NixOS VM test. It is generated into
# the Nix store and MUST NOT be reused by a deployed controller or device.
pkgs.runCommand "kaiba-test-only-pki"
  {
    nativeBuildInputs = [ pkgs.openssl ];
  }
  ''
      set -eu
      mkdir -p $out

      openssl genrsa -out $out/ca-key.pem 2048
      openssl req -x509 -new -sha256 -key $out/ca-key.pem \
        -out $out/ca.pem -days 36500 -set_serial 1 \
        -subj '/CN=Kaiba Pilot Test CA'

      issue_certificate() {
        name="$1"
        subject="$2"
        extensions="$3"
        serial="$4"

        openssl genrsa -out "$out/$name-key.pem" 2048
        openssl req -new -sha256 -key "$out/$name-key.pem" \
          -out "$out/$name.csr" -subj "$subject"
        printf '%s\n' "$extensions" > "$out/$name.ext"
        openssl x509 -req -sha256 -in "$out/$name.csr" \
          -CA $out/ca.pem -CAkey $out/ca-key.pem -set_serial "$serial" \
          -out "$out/$name.pem" -days 36500 -extfile "$out/$name.ext"
        rm "$out/$name.csr" "$out/$name.ext"
      }

      issue_certificate controller '/CN=updates.kaiba.test' \
        'subjectAltName=DNS:updates.kaiba.test
    extendedKeyUsage=serverAuth' 10

      issue_certificate device-001 '/CN=Kaiba device 001' \
        'subjectAltName=URI:spiffe://kaiba.network/device/001
    extendedKeyUsage=clientAuth' 11

      issue_certificate device-002 '/CN=Kaiba device 002' \
        'subjectAltName=URI:spiffe://kaiba.network/device/002
    extendedKeyUsage=clientAuth' 12

      issue_certificate pi-001 '/CN=pi-001.kaiba.test' \
        'subjectAltName=DNS:pi-001.kaiba.test
    extendedKeyUsage=serverAuth' 13

      # A certificate from this unrelated CA proves that TLS rejects credentials
      # outside the controller trust root.
      openssl genrsa -out $out/rogue-ca-key.pem 2048
      openssl req -x509 -new -sha256 -key $out/rogue-ca-key.pem \
        -out $out/rogue-ca.pem -days 36500 -set_serial 20 \
        -subj '/CN=Kaiba Rogue Test CA'
      openssl genrsa -out $out/rogue-device-key.pem 2048
      openssl req -new -sha256 -key $out/rogue-device-key.pem \
        -out $out/rogue-device.csr -subj '/CN=rogue device'
      printf '%s\n' \
        'subjectAltName=URI:spiffe://kaiba.network/device/001' \
        'extendedKeyUsage=clientAuth' > $out/rogue-device.ext
      openssl x509 -req -sha256 -in $out/rogue-device.csr \
        -CA $out/rogue-ca.pem -CAkey $out/rogue-ca-key.pem -set_serial 21 \
        -out $out/rogue-device.pem -days 36500 -extfile $out/rogue-device.ext

      rm $out/*-ca-key.pem $out/ca-key.pem \
        $out/rogue-device.csr $out/rogue-device.ext
      chmod 0400 $out/*-key.pem
      chmod 0444 $out/*.pem
  ''
