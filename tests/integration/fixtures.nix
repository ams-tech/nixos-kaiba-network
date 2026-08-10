{ pkgs }:

let
  secrets = {
    update = "a2FpYmEtdGVzdC1vbmx5LXB1Ymxpc2hlci1rZXktMDE=";
    p1 = "a2FpYmEtdGVzdC1vbmx5LXAxLXRyYW5zZmVyLWtleQ==";
    public = "a2FpYmEtdGVzdC1vbmx5LW5zMS10cmFuc2Zlci1rZXk=";
  };

  keyBlock = id: secret: ''
    key:
      - id: ${id}
        algorithm: hmac-sha256
        secret: ${secret}
  '';
in
{
  addresses = {
    parent = {
      v4 = "192.0.2.10";
      v6 = "2001:db8:10::10";
    };
    ns1Public = {
      v4 = "192.0.2.11";
      v6 = "2001:db8:10::11";
    };
    ns2Public = {
      v4 = "192.0.2.12";
      v6 = "2001:db8:10::12";
    };
    resolver = {
      v4 = "192.0.2.20";
      v6 = "2001:db8:10::20";
    };
    p0Observer = {
      v4 = "192.0.2.30";
      v6 = "2001:db8:10::30";
    };
    device = {
      v4 = "192.0.2.101";
      v6 = "2001:db8:10::101";
    };
    deviceChanged = {
      v4 = "192.0.2.102";
      v6 = "2001:db8:10::102";
    };
    p0Origin = {
      v4 = "198.51.100.10";
      v6 = "2001:db8:20::10";
    };
    p1Origin = {
      v4 = "198.51.100.11";
      v6 = "2001:db8:20::11";
    };
    ns1Origin = {
      v4 = "198.51.100.21";
      v6 = "2001:db8:20::21";
    };
    ns2Origin = {
      v4 = "198.51.100.22";
      v6 = "2001:db8:20::22";
    };
    p0Update = {
      v4 = "203.0.113.10";
      v6 = "2001:db8:30::10";
    };
    deviceUpdate = {
      v4 = "203.0.113.101";
      v6 = "2001:db8:30::101";
    };
  };

  parentZone = pkgs.writeText "test.zone" ''
    $ORIGIN test.
    $TTL 300
    @       IN SOA parent.test. hostmaster.test. 2026080801 60 30 604800 30
            IN NS  parent.test.
    parent  IN A   192.0.2.10
    parent  IN AAAA 2001:db8:10::10

    kaiba   IN NS  ns1.kaiba.test.
    kaiba   IN NS  ns2.kaiba.test.
    ns1.kaiba IN A 192.0.2.11
    ns1.kaiba IN AAAA 2001:db8:10::11
    ns2.kaiba IN A 192.0.2.12
    ns2.kaiba IN AAAA 2001:db8:10::12
  '';

  kaibaZone = pkgs.writeText "kaiba.test.zone" ''
    $ORIGIN kaiba.test.
    $TTL 300
    @       IN SOA ns1.kaiba.test. hostmaster.kaiba.test. 2026080801 60 30 604800 30
            IN NS  ns1.kaiba.test.
            IN NS  ns2.kaiba.test.
    ns1     IN A   192.0.2.11
    ns1     IN AAAA 2001:db8:10::11
    ns2     IN A   192.0.2.12
    ns2     IN AAAA 2001:db8:10::12
  '';

  keys = {
    update = pkgs.writeText "kaiba-test-only-update-key.conf" (
      keyBlock "kaiba-publisher" secrets.update
    );
    p1 = pkgs.writeText "kaiba-test-only-p1-key.conf" (keyBlock "kaiba-p1-transfer" secrets.p1);
    public = pkgs.writeText "kaiba-test-only-public-key.conf" (
      keyBlock "kaiba-public-transfer" secrets.public
    );
    ns1 = pkgs.writeText "kaiba-test-only-ns1-key.conf" (
      keyBlock "kaiba-public-transfer" secrets.public
    );
    ns2 = pkgs.writeText "kaiba-test-only-ns2-key.conf" (
      keyBlock "kaiba-public-transfer" secrets.public
    );
    publisher = pkgs.writeText "kaiba-test-only-publisher.secret" "${secrets.update}\n";
  };
}
