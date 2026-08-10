{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
  testPki,
}:

let
  fixtures = import ./fixtures.nix { inherit pkgs; };
  a = fixtures.addresses;
  testClockPath = "/var/lib/kaiba-controller/test-clock";
  testClockInitial = "2099-01-01T00:00:00Z";
  testClockRenewal = "2099-01-01T00:00:10Z";
  testClockExpired = "2099-01-01T00:01:00Z";

  interface = v4: v6: {
    useDHCP = false;
    ipv4.addresses = map (address: {
      inherit address;
      prefixLength = 24;
    }) v4;
    ipv6.addresses = map (address: {
      inherit address;
      prefixLength = 64;
    }) v6;
  };

  common = { pkgs, ... }: {
    imports = [ kaibaModules.default ];
    networking.useDHCP = false;
    networking.firewall.enable = false;
    services.resolved.enable = false;
    virtualisation.memorySize = 256;
    virtualisation.cores = 1;
    environment.systemPackages = [
      pkgs.bind.dnsutils
      pkgs.curl
      pkgs.jq
      pkgs.knot-dns
      pkgs.sqlite
      kaibaPackage
    ];
    system.stateVersion = "26.05";
  };

  publicTargets = [
    {
      id = "a";
      address = a.ns1Origin.v4;
    }
    {
      id = "b";
      address = a.ns2Origin.v4;
    }
  ];

  publicMasters = [
    {
      id = "p0";
      address = a.p0Origin.v4;
      keyName = "kaiba-public-transfer";
    }
    {
      id = "p1";
      address = a.p1Origin.v4;
      keyName = "kaiba-public-transfer";
    }
  ];
in
{
  name = "kaiba-dns-pilot";
  globalTimeout = 900;
  requiredFeatures.kvm = false;

  nodeDefaults = common;

  nodes = {
    parent = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1 = interface [ a.parent.v4 ] [ a.parent.v6 ];

      services.knot = {
        enable = true;
        extraArgs = [ "-v" ];
        settings = {
          server.listen = [
            "${a.parent.v4}@53"
            "${a.parent.v6}@53"
          ];
          template.default = {
            storage = "/var/lib/knot";
            zonefile-sync = -1;
            zonefile-load = "difference";
            journal-content = "changes";
            semantic-checks = true;
          };
          zone."test.".file = fixtures.parentZone;
          log.syslog.any = "debug";
        };
      };
    };

    p0 = { ... }: {
      virtualisation.vlans = [
        2
        3
        1
      ];
      networking.interfaces.eth1 = interface [ a.p0Origin.v4 ] [ a.p0Origin.v6 ];
      networking.interfaces.eth2 = interface [ a.p0Update.v4 ] [ a.p0Update.v6 ];
      # The publisher observes the externally served projection through the
      # public-query network. No P0 DNS or controller listener binds here.
      networking.interfaces.eth3 = interface [ a.p0Observer.v4 ] [ a.p0Observer.v6 ];
      systemd.tmpfiles.rules = [
        "f ${testClockPath} 0640 kaiba-controller kaiba-state - ${testClockInitial}"
      ];
      environment.etc."kaiba-test/clock-renewal".text = "${testClockRenewal}\n";
      environment.etc."kaiba-test/clock-expired".text = "${testClockExpired}\n";

      kaiba.dns = {
        listenAddresses = [
          a.p0Origin.v4
          a.p0Origin.v6
        ];
        hiddenPrimary = {
          enable = true;
          zone = "kaiba.test.";
          initialZoneFile = fixtures.kaibaZone;
          publisherUpdate = {
            keyName = "kaiba-publisher";
            keyFile = toString fixtures.keys.update;
            sourceAddresses = [
              a.p0Origin.v4
              a.p0Origin.v6
            ];
          };
          standby = {
            address = a.p1Origin.v4;
            keyName = "kaiba-p1-transfer";
            keyFile = toString fixtures.keys.p1;
          };
          publicTransfer = {
            keyName = "kaiba-public-transfer";
            keyFile = toString fixtures.keys.public;
            secondaries = publicTargets;
          };
        };
      };
      services.knot.extraArgs = [ "-v" ];
      services.knot.settings.log.syslog.any = lib.mkForce "debug";

      kaiba.updateController = {
        enable = true;
        zone = "kaiba.test.";
        leaseDuration = "45s";
        renewAfter = "15s";
        credentials = {
          serverCertificate = "${testPki}/controller.pem";
          serverKey = "${testPki}/controller-key.pem";
          clientCA = "${testPki}/ca.pem";
          publisherTSIGSecret = toString fixtures.keys.publisher;
        };
        controller = {
          package = kaibaPackage;
          listenAddress = a.p0Update.v4;
          port = 8443;
          allowNonGlobalAddresses = true;
          extraArgs = [
            "--clock-file"
            testClockPath
          ];
        };
        publisher = {
          package = kaibaPackage;
          dnsServer = "${a.p0Origin.v4}:53";
          tsigName = "kaiba-publisher";
          ttl = 300;
          pollInterval = "1s";
          observeServers = [
            "${a.ns1Public.v4}:53"
            "${a.ns2Public.v4}:53"
          ];
          extraArgs = [
            "--clock-file"
            testClockPath
          ];
        };
      };
      # The scenario controls publisher startup so P0 recovery can durably
      # accept a renewal before reconciliation, avoiding a boot-time expiry
      # race in the deliberately shortened lease policy.
      systemd.services.kaiba-publisher.wantedBy = lib.mkForce [ ];
    };

    p1 = { ... }: {
      virtualisation.vlans = [ 2 ];
      networking.interfaces.eth1 = interface [ a.p1Origin.v4 ] [ a.p1Origin.v6 ];

      kaiba.dns = {
        listenAddresses = [
          a.p1Origin.v4
          a.p1Origin.v6
        ];
        hiddenStandby = {
          enable = true;
          zone = "kaiba.test.";
          primary = {
            address = a.p0Origin.v4;
            keyName = "kaiba-p1-transfer";
            keyFile = toString fixtures.keys.p1;
          };
          publicTransfer = {
            keyName = "kaiba-public-transfer";
            keyFile = toString fixtures.keys.public;
            secondaries = publicTargets;
          };
        };
      };
      services.knot.extraArgs = [ "-v" ];
      services.knot.settings.log.syslog.any = lib.mkForce "debug";
    };

    public_a = { ... }: {
      virtualisation.vlans = [
        1
        2
      ];
      networking.interfaces.eth1 = interface [ a.ns1Public.v4 ] [ a.ns1Public.v6 ];
      networking.interfaces.eth2 = interface [ a.ns1Origin.v4 ] [ a.ns1Origin.v6 ];

      kaiba.dns = {
        listenAddresses = [
          a.ns1Public.v4
          a.ns1Public.v6
          a.ns1Origin.v4
          a.ns1Origin.v6
        ];
        publicSecondary = {
          enable = true;
          zone = "kaiba.test.";
          masters = publicMasters;
          keyFiles = [ (toString fixtures.keys.ns1) ];
        };
      };
      services.knot.extraArgs = [ "-v" ];
      services.knot.settings.log.syslog.any = lib.mkForce "debug";
    };

    public_b = { ... }: {
      virtualisation.vlans = [
        1
        2
      ];
      networking.interfaces.eth1 = interface [ a.ns2Public.v4 ] [ a.ns2Public.v6 ];
      networking.interfaces.eth2 = interface [ a.ns2Origin.v4 ] [ a.ns2Origin.v6 ];

      kaiba.dns = {
        listenAddresses = [
          a.ns2Public.v4
          a.ns2Public.v6
          a.ns2Origin.v4
          a.ns2Origin.v6
        ];
        publicSecondary = {
          enable = true;
          zone = "kaiba.test.";
          masters = publicMasters;
          keyFiles = [ (toString fixtures.keys.ns2) ];
        };
      };
      services.knot.extraArgs = [ "-v" ];
      services.knot.settings.log.syslog.any = lib.mkForce "debug";
    };

    resolver = { pkgs, ... }: {
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1 = interface [ a.resolver.v4 ] [ a.resolver.v6 ];
      networking.nameservers = [ "127.0.0.1" ];

      services.unbound = {
        enable = true;
        enableRootTrustAnchor = false;
        settings = {
          server = {
            interface = [
              "127.0.0.1"
              "::1"
            ];
            access-control = [
              "127.0.0.0/8 allow"
              "::1 allow"
            ];
            do-ip4 = true;
            do-ip6 = true;
            # Unbound serves RFC 6761's built-in static `test.` zone unless
            # explicitly disabled. Let this lab's stub-zone reach the
            # simulated parent authority instead.
            local-zone = [ ''"test." nodefault'' ];
          };
          stub-zone = [
            {
              name = "test.";
              stub-addr = [
                "${a.parent.v4}@53"
                "${a.parent.v6}@53"
              ];
              stub-first = false;
            }
          ];
        };
      };

      environment.etc."kaiba-test/ca.pem".source = "${testPki}/ca.pem";
      environment.systemPackages = [ pkgs.unbound ];
    };

    pi_001 = { ... }: {
      virtualisation.vlans = [
        1
        3
      ];
      networking.interfaces.eth1 =
        interface
          [ a.device.v4 a.deviceChanged.v4 ]
          [ a.device.v6 a.deviceChanged.v6 ];
      networking.interfaces.eth2 = interface [ a.deviceUpdate.v4 ] [ a.deviceUpdate.v6 ];
      networking.extraHosts = ''
        ${a.p0Update.v4} updates.kaiba.test
      '';
      environment.etc = {
        "kaiba-test/ca.pem".source = "${testPki}/ca.pem";
        "kaiba-test/device.pem".source = "${testPki}/device-001.pem";
        "kaiba-test/device-key.pem".source = "${testPki}/device-001-key.pem";
        "kaiba-test/device-002.pem".source = "${testPki}/device-002.pem";
        "kaiba-test/device-002-key.pem".source = "${testPki}/device-002-key.pem";
        "kaiba-test/rogue.pem".source = "${testPki}/rogue-device.pem";
        "kaiba-test/rogue-key.pem".source = "${testPki}/rogue-device-key.pem";
      };

      kaiba.deviceAgent = {
        enable = true;
        package = kaibaPackage;
        endpoint = "https://updates.kaiba.test:8443";
        addresses = [
          a.device.v4
          a.device.v6
        ];
        once = true;
        credentials = {
          clientCertificate = "${testPki}/device-001.pem";
          clientKey = "${testPki}/device-001-key.pem";
          serverCA = "${testPki}/ca.pem";
        };
      };
      # The scenario starts the defined service at a controlled point, after
      # establishing the initial transfer and delegation evidence.
      systemd.services.kaiba-agent.wantedBy = lib.mkForce [ ];

      services.nginx = {
        enable = true;
        virtualHosts."pi-001.kaiba.test" = {
          onlySSL = true;
          sslCertificate = "${testPki}/pi-001.pem";
          sslCertificateKey = "${testPki}/pi-001-key.pem";
          locations."/".return = "200 'kaiba pi-001\\n'";
        };
      };
    };
  };

  testScript = builtins.readFile ./scenario.py;
}
