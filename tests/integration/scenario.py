import hashlib
import ipaddress
import json
import os
import re
import shlex
from pathlib import Path


OUTPUT = Path(os.environ["out"]) / "raw"
EVIDENCE = OUTPUT / "evidence"
ZONES = OUTPUT / "zones"
OUTPUT.mkdir(parents=True, exist_ok=True)
EVIDENCE.mkdir(parents=True, exist_ok=True)
ZONES.mkdir(parents=True, exist_ok=True)

assertions = []
events = []
serials = []
answers = []
event_sequence = 0
active_evidence = None
ixfr_journal_cursors = {}
ixfr_serial_transition = None
stable_replay_precondition = None


class CheckFailure(Exception):
    def __init__(self, observed):
        super().__init__("assertion did not match its expected value")
        self.observed = observed


def normalized(text):
    clean = []
    for line in text.replace("\r\n", "\n").splitlines():
        if re.search(r"(Query time:|WHEN:|MSG SIZE|connection from)", line):
            continue
        line = re.sub(r"\bid:\s+\d+\b", "id: <normalized>", line)
        line = re.sub(r"@[0-9]{4,5}\b", "@<port>", line)
        line = re.sub(r"\b\d+(?:\.\d+)? seconds?\b", "<normalized-duration>", line)
        line = re.sub(r"\b\d+(?:\.\d+)?(?:us|ms|s)\b", "<normalized-duration>", line)
        line = re.sub(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            "<normalized-time>",
            line,
        )
        line = re.sub(r"\s+$", "", line)
        if line:
            clean.append(line)
    return "\n".join(clean) + ("\n" if clean else "")


def canonical_dns_records(text):
    records = sorted(
        " ".join(line.split())
        for line in normalized(text).splitlines()
        if line.strip()
    )
    return "\n".join(records) + ("\n" if records else "")


def evidence_path(phase, name, text):
    global active_evidence
    directory = EVIDENCE / phase
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    target.write_text(normalized(text), encoding="utf-8")
    relative = str(target.relative_to(OUTPUT))
    if active_evidence is not None and relative not in active_evidence:
        active_evidence.append(relative)
    return relative


def event(phase, actor, name, summary, evidence=None):
    global event_sequence
    event_sequence += 1
    events.append(
        {
            "sequence": event_sequence,
            "event": name,
            "phase": phase,
            "actor": actor,
            "summary": summary,
            "evidence": evidence or [],
        }
    )


def require(condition, observed):
    if not condition:
        raise CheckFailure(observed)
    return observed


def record(check_id, phase, description, expected, operation):
    global active_evidence
    event(phase, "test-driver", "assertion-start", description)
    captured_evidence = []
    active_evidence = captured_evidence
    try:
        observed, referenced_evidence = operation()
        referenced_evidence = list(
            dict.fromkeys(captured_evidence + list(referenced_evidence))
        )
        status = "passed"
    except CheckFailure as failure:
        observed = failure.observed
        referenced_evidence = captured_evidence
        status = "failed"
    except Exception as failure:
        observed = {"error": failure.__class__.__name__, "operation": "failed"}
        referenced_evidence = captured_evidence
        status = "failed"
    finally:
        active_evidence = None
    assertions.append(
        {
            "id": check_id,
            "phase": phase,
            "status": status,
            "description": description,
            "expected": expected,
            "observed": observed,
            "evidence": referenced_evidence,
        }
    )
    event(phase, "test-driver", "assertion-result", f"{check_id}: {status}", referenced_evidence)


def command(machine, argv):
    return machine.execute(" ".join(shlex.quote(str(arg)) for arg in argv), timeout=30)


def poll(machine, script, timeout=30):
    machine.wait_until_succeeds(script, timeout=timeout)


def direct_serial(machine, server, label, phase):
    status, output = command(
        machine,
        ["dig", f"@{server}", "kaiba.test.", "SOA", "+short", "+tcp"],
    )
    if status != 0 or not output.strip():
        raise CheckFailure({"server": label, "query": "failed"})
    fields = output.split()
    serial = int(fields[2])
    serials.append({"phase": phase, "server": label, "serial": serial})
    return serial, output


def direct_answer(
    machine, server, label, rrtype, phase, tcp=False, name="pi-001.kaiba.test."
):
    argv = ["dig", f"@{server}", name, rrtype, "+short"]
    if tcp:
        argv.append("+tcp")
    status, output = command(machine, argv)
    values = sorted(line.strip() for line in output.splitlines() if line.strip())
    if status != 0:
        raise CheckFailure({"server": label, "type": rrtype, "query": "failed"})
    answers.append(
        {
            "phase": phase,
            "server": label,
            "name": name,
            "type": rrtype,
            "values": values,
            "authoritative": True,
            "transport": "tcp" if tcp else "udp",
        }
    )
    return values, output


def canonical_zone(machine, label, phase):
    status, output = command(machine, ["knotc", "zone-read", "kaiba.test."])
    if status != 0:
        raise CheckFailure({"server": label, "zone_read": "failed"})
    records = sorted(
        " ".join(line.split())
        for line in normalized(output).splitlines()
        if line.strip()
    )
    canonical = "\n".join(records) + "\n"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    path = evidence_path(phase, f"{label}-canonical-zone.txt", canonical)
    return digest, path


def api_request(
    body,
    key,
    cert="/etc/kaiba-test/device.pem",
    key_file="/etc/kaiba-test/device-key.pem",
    precondition=None,
):
    argv = [
        "curl",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "3",
        "--max-time",
        "8",
        "--cacert",
        "/etc/kaiba-test/ca.pem",
        "--cert",
        cert,
        "--key",
        key_file,
        "--request",
        "PUT",
        "--header",
        "Content-Type: application/json",
        "--header",
        f"Idempotency-Key: {key}",
    ]
    if precondition is not None:
        header, value = precondition
        if header not in ["If-Match", "If-None-Match"]:
            raise ValueError("unsupported update precondition")
        argv.extend(["--header", f"{header}: {value}"])
    argv.extend(
        [
            "--data",
            json.dumps(body, sort_keys=True, separators=(",", ":")),
            "--write-out",
            "\n__HTTP_STATUS__=%{http_code}\n__ETAG__=%header{etag}\n",
            "https://updates.kaiba.test:8443/v1/devices/self/endpoints",
        ]
    )
    status, output = command(pi_001, argv)
    lines = output.rstrip("\n").splitlines()
    etag = lines[-1].removeprefix("__ETAG__=") if lines else ""
    http_status = lines[-2].removeprefix("__HTTP_STATUS__=") if len(lines) >= 2 else "000"
    response_body = "\n".join(lines[:-2])
    parsed = {}
    if response_body.startswith("{"):
        parsed = json.loads(response_body)
    return status, http_status, etag, parsed, output


def api_status():
    argv = [
        "curl",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "3",
        "--max-time",
        "8",
        "--cacert",
        "/etc/kaiba-test/ca.pem",
        "--cert",
        "/etc/kaiba-test/device.pem",
        "--key",
        "/etc/kaiba-test/device-key.pem",
        "--write-out",
        "\n__HTTP_STATUS__=%{http_code}\n__ETAG__=%header{etag}\n",
        "https://updates.kaiba.test:8443/v1/devices/self/status",
    ]
    status, output = command(pi_001, argv)
    lines = output.rstrip("\n").splitlines()
    etag = lines[-1].removeprefix("__ETAG__=") if lines else ""
    http_status = lines[-2].removeprefix("__HTTP_STATUS__=") if len(lines) >= 2 else "000"
    response_body = "\n".join(lines[:-2])
    parsed = json.loads(response_body) if response_body.startswith("{") else {}
    return status, http_status, etag, parsed, output


def wait_api_status(expected, timeout=30):
    argv = [
        "curl",
        "--silent",
        "--show-error",
        "--cacert",
        "/etc/kaiba-test/ca.pem",
        "--cert",
        "/etc/kaiba-test/device.pem",
        "--key",
        "/etc/kaiba-test/device-key.pem",
        "https://updates.kaiba.test:8443/v1/devices/self/status",
    ]
    request = " ".join(shlex.quote(item) for item in argv)
    poll(pi_001, f"{request} | jq -e '.status == \"{expected}\"'", timeout=timeout)
    return api_status()


BOOT_TIMEOUT_SECONDS = 300
booted = False
boot_stage = "start-all"
boot_machine = "all"
boot_unit = ""
try:
    start_all()
    for machine, label, unit in [
        (parent, "parent", "knot.service"),
        (p0, "p0", "knot.service"),
        (p1, "p1", "knot.service"),
        (public_a, "public-a", "knot.service"),
        (public_b, "public-b", "knot.service"),
        (p0, "p0", "kaiba-controller.service"),
        (resolver, "resolver", "unbound.service"),
        (pi_001, "pi-001", "nginx.service"),
    ]:
        boot_stage = "unit-readiness"
        boot_machine = label
        boot_unit = unit
        machine.wait_for_unit(unit, timeout=BOOT_TIMEOUT_SECONDS)
    for machine, label, server in [
        (p0, "p0", "198.51.100.10"),
        (p1, "p1", "198.51.100.11"),
        (public_a, "public-a", "192.0.2.11"),
        (public_b, "public-b", "192.0.2.12"),
    ]:
        boot_stage = "authoritative-soa"
        boot_machine = label
        boot_unit = "knot.service"
        poll(
            machine,
            f'test -n "$(dig @{server} kaiba.test. SOA +short +tcp +time=1 +tries=1)"',
            timeout=90,
        )
    for machine, label in [
        (p1, "p1"),
        (public_a, "public-a"),
        (public_b, "public-b"),
    ]:
        boot_stage = "initial-axfr"
        boot_machine = label
        boot_unit = "knot.service"
        poll(
            machine,
            "journalctl -u knot.service -o cat --no-pager | grep -Eiq 'AXFR, incoming.*finished'",
            timeout=90,
        )
    boot_stage = "publisher-readiness"
    boot_machine = "p0"
    boot_unit = "kaiba-publisher.service"
    p0.succeed("systemctl start kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=BOOT_TIMEOUT_SECONDS)
    booted = True
except Exception:
    pass


def check_bootstrap():
    observed = {"ready": booted}
    details = [
        f"ready={str(booted).lower()}",
        f"timeout_seconds={BOOT_TIMEOUT_SECONDS}",
    ]
    if not booted:
        observed.update(
            {
                "stage": boot_stage,
                "machine": boot_machine,
                "unit": boot_unit,
            }
        )
        details.extend(
            [
                f"stage={boot_stage}",
                f"machine={boot_machine}",
                f"unit={boot_unit}",
            ]
        )
    path = evidence_path("bootstrap", "readiness.txt", "\n".join(details) + "\n")
    require(booted, observed)
    return observed, [path]


record(
    "boot-001",
    "bootstrap",
    "All seven nodes and required services become ready",
    {"ready": True},
    check_bootstrap,
)


EXPECTED_PUBLIC_GLUE = {
    "ns1.kaiba.test": {
        "A": ["192.0.2.11"],
        "AAAA": ["2001:db8:10::11"],
    },
    "ns2.kaiba.test": {
        "A": ["192.0.2.12"],
        "AAAA": ["2001:db8:10::12"],
    },
}
EXPECTED_PUBLIC_GLUE_ADDRESSES = sorted(
    {
        address
        for records_by_type in EXPECTED_PUBLIC_GLUE.values()
        for addresses_by_type in records_by_type.values()
        for address in addresses_by_type
    }
)
HIDDEN_AUTHORITY_ADDRESSES = {
    "192.0.2.30",  # P0 public-observer interface
    "198.51.100.10",  # P0 origin
    "198.51.100.11",  # P1 origin
    "203.0.113.10",  # P0 update controller
    "2001:db8:10::30",  # P0 public-observer interface
    "2001:db8:20::10",  # P0 origin
    "2001:db8:20::11",  # P1 origin
    "2001:db8:30::10",  # P0 update controller
}


def parent_referral(tcp=False):
    argv = [
        "dig",
        "@192.0.2.10",
        "kaiba.test.",
        "NS",
        "+norecurse",
        "+noall",
        "+authority",
        "+additional",
    ]
    if tcp:
        argv.append("+tcp")
    status, output = command(resolver, argv)
    names = sorted(
        fields[-1].rstrip(".").lower()
        for line in output.splitlines()
        if len(fields := line.split()) >= 5 and fields[-2].upper() == "NS"
    )
    address_records = [
        (
            fields[0].rstrip(".").lower(),
            fields[-2].upper(),
            str(ipaddress.ip_address(fields[-1])),
        )
        for line in output.splitlines()
        if len(fields := line.split()) >= 5
        and fields[-2].upper() in ["A", "AAAA"]
    ]
    glue = {
        name: {
            rrtype: sorted(
                address
                for owner, record_type, address in address_records
                if owner == name and record_type == rrtype
            )
            for rrtype in ["A", "AAAA"]
        }
        for name in names
    }
    referral_addresses = sorted({address for _, _, address in address_records})
    return status, names, glue, referral_addresses, output


def check_delegation():
    status, names, glue, referral_addresses, output = parent_referral()
    path = evidence_path("delegation", "parent-ns.txt", canonical_dns_records(output))
    hidden_addresses = sorted(
        HIDDEN_AUTHORITY_ADDRESSES.intersection(referral_addresses)
    )
    observed = {
        "status": status,
        "nameservers": names,
        "glue": glue,
        "referral_addresses": referral_addresses,
        "hidden_addresses": hidden_addresses,
    }
    require(status == 0, observed)
    require(names == ["ns1.kaiba.test", "ns2.kaiba.test"], observed)
    require(glue == EXPECTED_PUBLIC_GLUE, observed)
    require(referral_addresses == EXPECTED_PUBLIC_GLUE_ADDRESSES, observed)
    require(not hidden_addresses, observed)
    require(not any("p0" in name or "p1" in name for name in names), observed)
    return observed, [path]


record(
    "dns-001",
    "delegation",
    "The parent delegates only to public secondaries with their exact dual-stack glue",
    {
        "nameservers": ["ns1.kaiba.test", "ns2.kaiba.test"],
        "glue": EXPECTED_PUBLIC_GLUE,
        "referral_addresses": EXPECTED_PUBLIC_GLUE_ADDRESSES,
        "hidden_addresses": [],
    },
    check_delegation,
)


def check_baseline():
    observed_serials = {}
    observed_device_answers = {}
    evidence = []
    for machine, server, label in [
        (p0, "198.51.100.10", "p0"),
        (p1, "198.51.100.11", "p1"),
        (resolver, "192.0.2.11", "public-a"),
        (resolver, "192.0.2.12", "public-b"),
    ]:
        value, output = direct_serial(machine, server, label, "baseline")
        observed_serials[label] = value
        evidence.append(evidence_path("baseline", f"{label}-soa.txt", output))
        observed_device_answers[label] = {}
        for rrtype in ["A", "AAAA"]:
            values, answer_output = direct_answer(
                machine, server, label, rrtype, "baseline"
            )
            observed_device_answers[label][rrtype] = values
            evidence.append(
                evidence_path(
                    "baseline",
                    f"{label}-pi-001-{rrtype.lower()}.txt",
                    answer_output,
                )
            )
    require(len(set(observed_serials.values())) == 1, observed_serials)
    observed = {
        "serials": observed_serials,
        "device_answers": observed_device_answers,
    }
    require(
        all(
            not answers_by_type["A"] and not answers_by_type["AAAA"]
            for answers_by_type in observed_device_answers.values()
        ),
        observed,
    )
    return observed, evidence


record(
    "dns-002",
    "baseline",
    "P0, P1, and both public secondaries converge before any device record exists",
    {"unique_serial_count": 1, "pi-001-A": [], "pi-001-AAAA": []},
    check_baseline,
)


def check_initial_axfr():
    observed = {}
    evidence = []
    for machine, label in [
        (p1, "p1"),
        (public_a, "public-a"),
        (public_b, "public-b"),
    ]:
        status, output = command(
            machine,
            ["journalctl", "-u", "knot.service", "-o", "cat", "--no-pager"],
        )
        matching = "\n".join(
            sorted(
                {
                    line
                    for line in output.splitlines()
                    if "AXFR, incoming" in line and "finished" in line
                }
            )
        )
        detected = status == 0 and bool(matching)
        evidence.append(
            evidence_path(
                "baseline",
                f"{label}-axfr-log.txt",
                f"server={label}\ntransfer=AXFR\nincoming_detected={str(detected).lower()}\n",
            )
        )
        observed[label] = detected
    require(all(observed.values()), observed)
    return observed, evidence


record(
    "dns-002a",
    "baseline",
    "Initial bootstrap is explicitly logged as AXFR on P1 and both public secondaries",
    {"p1": True, "public-a": True, "public-b": True},
    check_initial_axfr,
)


def check_transport(tcp):
    suffix = "tcp" if tcp else "udp"
    status, names, glue, referral_addresses, referral_output = parent_referral(tcp=tcp)
    evidence = [
        evidence_path(
            "transport",
            f"parent-referral-{suffix}.txt",
            canonical_dns_records(referral_output),
        )
    ]
    observed_answers = {}
    observed = {
        "transport": suffix,
        "parent_query_status": status,
        "referral_nameservers": names,
        "discovered_glue": glue,
        "referral_addresses": referral_addresses,
        "hidden_addresses": sorted(
            HIDDEN_AUTHORITY_ADDRESSES.intersection(referral_addresses)
        ),
        "answers": observed_answers,
    }
    require(status == 0, observed)
    require(names == ["ns1.kaiba.test", "ns2.kaiba.test"], observed)
    require(glue == EXPECTED_PUBLIC_GLUE, observed)
    require(referral_addresses == EXPECTED_PUBLIC_GLUE_ADDRESSES, observed)
    require(not observed["hidden_addresses"], observed)
    report_labels = {
        "ns1.kaiba.test": "public-a",
        "ns2.kaiba.test": "public-b",
    }
    for nameserver in names:
        # The authoritative destination is learned exclusively from the
        # parent's referral. No public-secondary address is hardcoded here.
        server = glue[nameserver]["A"][0]
        values, output = direct_answer(
            resolver,
            server,
            report_labels[nameserver],
            "A",
            "transport",
            tcp=tcp,
            name="ns1.kaiba.test.",
        )
        observed_answers[nameserver] = values
        evidence.append(
            evidence_path(
                "transport", f"{nameserver.replace('.', '-')}-{suffix}.txt", output
            )
        )
        require(values == ["192.0.2.11"], observed)
    return observed, evidence


record(
    "dns-003",
    "transport",
    "Following the simulated parent referral reaches both delegated public authorities over UDP",
    {
        "transport": "udp",
        "parent_query_status": 0,
        "referral_nameservers": ["ns1.kaiba.test", "ns2.kaiba.test"],
        "discovered_glue": EXPECTED_PUBLIC_GLUE,
        "referral_addresses": EXPECTED_PUBLIC_GLUE_ADDRESSES,
        "hidden_addresses": [],
        "answers": {
            "ns1.kaiba.test": ["192.0.2.11"],
            "ns2.kaiba.test": ["192.0.2.11"],
        },
    },
    lambda: check_transport(False),
)
record(
    "dns-004",
    "transport",
    "Following the simulated parent referral reaches both delegated public authorities over TCP",
    {
        "transport": "tcp",
        "parent_query_status": 0,
        "referral_nameservers": ["ns1.kaiba.test", "ns2.kaiba.test"],
        "discovered_glue": EXPECTED_PUBLIC_GLUE,
        "referral_addresses": EXPECTED_PUBLIC_GLUE_ADDRESSES,
        "hidden_addresses": [],
        "answers": {
            "ns1.kaiba.test": ["192.0.2.11"],
            "ns2.kaiba.test": ["192.0.2.11"],
        },
    },
    lambda: check_transport(True),
)


AUTHORITY_PROBES = [
    (resolver, "192.0.2.10", "parent", "test."),
    # P1 and public A use source addresses that are otherwise transfer-ACL
    # eligible, proving that anonymous AXFR still fails without its TSIG key.
    (p1, "198.51.100.10", "p0", "kaiba.test."),
    (public_a, "198.51.100.11", "p1", "kaiba.test."),
    (resolver, "192.0.2.11", "public-a", "kaiba.test."),
    (resolver, "192.0.2.12", "public-b", "kaiba.test."),
]


def dns_rcode(output):
    matches = re.findall(r"\bstatus:\s*([A-Z]+)\b", output)
    if matches:
        return matches[-1]
    # kdig reports failed transfer response codes in prose rather than in a
    # dig-style header, for example: server replied with error 'NOTAUTH'.
    matches = re.findall(r"server replied with error ['\"]([A-Z]+)['\"]", output)
    return matches[-1] if matches else ""


def check_recursion_refused():
    observed = {}
    evidence = []
    for machine, server, label, _ in AUTHORITY_PROBES:
        status, output = command(
            machine,
            [
                "dig",
                f"@{server}",
                "outside.invalid.",
                "A",
                "+recurse",
                "+comments",
                "+noquestion",
                "+noanswer",
                "+noauthority",
                "+noadditional",
                "+nostats",
                "+time=2",
                "+tries=1",
            ],
        )
        flag_matches = re.findall(r"\bflags:\s*([^;]*);", output)
        flags = set(flag_matches[-1].split()) if flag_matches else set()
        observed[label] = {
            "command_status": status,
            "rcode": dns_rcode(output),
            "recursion_available": "ra" in flags,
        }
        evidence.append(
            evidence_path("security", f"{label}-recursion-refused.txt", output)
        )
    require(
        all(
            item["command_status"] == 0
            and item["rcode"] == "REFUSED"
            and not item["recursion_available"]
            for item in observed.values()
        ),
        observed,
    )
    return observed, evidence


record(
    "sec-001",
    "security",
    "Parent, P0, P1, and both public authorities refuse recursive queries",
    {
        "parent": "REFUSED",
        "p0": "REFUSED",
        "p1": "REFUSED",
        "public-a": "REFUSED",
        "public-b": "REFUSED",
    },
    check_recursion_refused,
)


def check_axfr_refused():
    observed = {}
    evidence = []
    for machine, server, label, zone in AUTHORITY_PROBES:
        argv = [
            "kdig",
            zone,
            "AXFR",
            f"@{server}",
            "+timeout=2",
            "+retry=0",
            "+noall",
            "+header",
            "+answer",
            "+comments",
            "+nostats",
        ]
        status, output = machine.execute(
            " ".join(shlex.quote(item) for item in argv) + " 2>&1",
            timeout=30,
        )
        soa_records = len(
            re.findall(r"^\S+\s+\d+\s+IN\s+SOA\s", output, re.MULTILINE)
        )
        completed = soa_records >= 2 or "XFR size:" in output
        observed[label] = {
            "command_status": status,
            "rcode": dns_rcode(output),
            "completed_transfer": completed,
        }
        evidence.append(
            evidence_path("security", f"{label}-anonymous-axfr.txt", output)
        )
    require(
        all(
            item["command_status"] != 0
            and item["rcode"] == "NOTAUTH"
            and not item["completed_transfer"]
            for item in observed.values()
        ),
        observed,
    )
    return observed, evidence


record(
    "sec-002",
    "security",
    "Parent, P0, P1, and both public authorities refuse anonymous zone transfers",
    {
        "parent": "NOTAUTH with no completed transfer",
        "p0": "NOTAUTH with no completed transfer",
        "p1": "NOTAUTH with no completed transfer",
        "public-a": "NOTAUTH with no completed transfer",
        "public-b": "NOTAUTH with no completed transfer",
    },
    check_axfr_refused,
)


def check_read_only_authorities():
    script_template = (
        "server {server}\n"
        "zone kaiba.test.\n"
        "update add forbidden.kaiba.test. 300 A 192.0.2.250\n"
        "send\n"
    )
    observed = {}
    evidence = []
    for machine, server, label in [
        (p1, "198.51.100.11", "p1"),
        (resolver, "192.0.2.11", "public-a"),
        (resolver, "192.0.2.12", "public-b"),
    ]:
        before, _ = direct_serial(machine, server, label, "read-only-before")
        script = script_template.format(server=server)
        status, output = machine.execute(
            f"printf %s {shlex.quote(script)} | nsupdate -d -v 2>&1",
            timeout=30,
        )
        answer_status, forbidden = command(
            machine,
            ["dig", f"@{server}", "forbidden.kaiba.test.", "A", "+short"],
        )
        after, _ = direct_serial(machine, server, label, "read-only-after")
        observed[label] = {
            "exit_nonzero": status != 0,
            "forbidden_rr_absent": answer_status == 0 and not forbidden.strip(),
            "soa_unchanged": before == after,
        }
        evidence.append(
            evidence_path(
                "security",
                f"{label}-update-refused.txt",
                output
                + f"\nexit_nonzero={str(status != 0).lower()}\n"
                + f"forbidden_rr_absent={str(not forbidden.strip()).lower()}\n"
                + f"soa_unchanged={str(before == after).lower()}\n",
            )
        )
    require(
        all(
            item["exit_nonzero"] and item["forbidden_rr_absent"] and item["soa_unchanged"]
            for item in observed.values()
        ),
        observed,
    )
    return observed, evidence


record(
    "sec-004",
    "security",
    "P1 and both public secondaries reject anonymous RFC 2136 updates",
    {"exit_nonzero": True, "forbidden_rr_absent": True, "soa_unchanged": True},
    check_read_only_authorities,
)


def check_agent_update():
    p0.succeed("systemctl stop kaiba-publisher.service")
    status, output = command(pi_001, ["systemctl", "start", "kaiba-agent.service"])
    result_status, service_result = command(
        pi_001,
        ["systemctl", "show", "--property=Result", "--value", "kaiba-agent.service"],
    )
    path = evidence_path(
        "authorized-update",
        "agent.txt",
        output + f"service_result={service_result.strip()}\n",
    )
    _, accepted_http, accepted_etag, accepted_state, accepted_output = api_status()
    p0.succeed("systemctl start kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=30)
    poll(
        p0,
        "test \"$(dig @198.51.100.10 pi-001.kaiba.test A +short)\" = 192.0.2.101"
    )
    poll(
        public_a,
        "test \"$(dig @192.0.2.11 pi-001.kaiba.test A +short)\" = 192.0.2.101"
    )
    poll(
        public_b,
        "test \"$(dig @192.0.2.12 pi-001.kaiba.test A +short)\" = 192.0.2.101"
    )
    _, public_http, public_etag, public_state, public_output = wait_api_status(
        "publicly-observed"
    )
    status_paths = [
        evidence_path("authorized-update", "accepted-status.txt", accepted_output),
        evidence_path("authorized-update", "public-status.txt", public_output),
    ]
    observed = {
        "start_status": status,
        "service_result_status": result_status,
        "service_result": service_result.strip(),
        "accepted_http": accepted_http,
        "accepted_etag": accepted_etag,
        "accepted_state": accepted_state.get("status"),
        "public_http": public_http,
        "public_etag": public_etag,
        "public_state": public_state.get("status"),
        "published": True,
    }
    require(status == 0 and result_status == 0 and service_result.strip() == "success", observed)
    require(accepted_http == "200" and accepted_state.get("status") == "accepted", observed)
    require(public_http == "200" and public_state.get("status") == "publicly-observed", observed)
    require(accepted_etag == '"g-1"' and public_etag == accepted_etag, observed)
    return observed, [path] + status_paths


record(
    "api-001",
    "authorized-update",
    "The packaged device agent moves durable intent from accepted to publicly observed",
    {"accepted": True, "publicly_observed": True, "etag": '"g-1"'},
    check_agent_update,
)


def check_api_rejections():
    evidence = []
    before, _ = direct_serial(p0, "198.51.100.10", "p0", "security-before")
    _, current_http, current_etag, _, _ = api_status()
    malformed = {"addresses": [{"family": "ipv4", "address": "999.1.2.3"}]}
    cross_device = {
        "hostname": "pi-001.kaiba.test",
        "addresses": [{"family": "ipv4", "address": "192.0.2.102"}],
    }
    structural = {
        "addresses": [{"family": "ipv4", "address": "192.0.2.102"}],
        "records": [{"type": "NS", "value": "attacker.invalid"}],
    }
    statuses = {}
    for name, body, cert, key_file, precondition in [
        (
            "malformed",
            malformed,
            "/etc/kaiba-test/device.pem",
            "/etc/kaiba-test/device-key.pem",
            ("If-Match", current_etag),
        ),
        (
            "cross-device",
            cross_device,
            "/etc/kaiba-test/device-002.pem",
            "/etc/kaiba-test/device-002-key.pem",
            ("If-None-Match", "*"),
        ),
        (
            "structural",
            structural,
            "/etc/kaiba-test/device.pem",
            "/etc/kaiba-test/device-key.pem",
            ("If-Match", current_etag),
        ),
    ]:
        _, http_status, _, _, output = api_request(
            body,
            f"reject-{name}",
            cert,
            key_file,
            precondition=precondition,
        )
        statuses[name] = http_status
        evidence.append(evidence_path("security", f"api-{name}.txt", output))

    rogue_status, rogue_http, _, _, rogue_output = api_request(
        {"addresses": [{"family": "ipv4", "address": "192.0.2.102"}]},
        "reject-rogue",
        "/etc/kaiba-test/rogue.pem",
        "/etc/kaiba-test/rogue-key.pem",
        precondition=("If-None-Match", "*"),
    )
    statuses["rogue-certificate"] = rogue_http
    evidence.append(evidence_path("security", "api-rogue-certificate.txt", rogue_output))
    observed = {
        "status_get_http": current_http,
        "status_get_etag": current_etag,
        "http_statuses": statuses,
        "rogue_transport_status": rogue_status,
    }
    require(current_http == "200" and current_etag == '"g-1"', observed)
    require(statuses["malformed"] == "400", observed)
    require(statuses["cross-device"] == "400", observed)
    require(statuses["structural"] == "400", observed)
    require(rogue_status != 0 and rogue_http == "000", observed)
    after, _ = direct_serial(p0, "198.51.100.10", "p0", "security-after")
    observed["serial_before"] = before
    observed["serial_after"] = after
    require(before == after, observed)
    return observed, evidence


record(
    "sec-003",
    "security",
    "Malformed, cross-device, structural-record, and untrusted-certificate requests are rejected",
    {"application_rejections": "400", "untrusted_certificate": "TLS rejection"},
    check_api_rejections,
)


CURRENT_BODY = {
    "addresses": [
        {"family": "ipv4", "address": "192.0.2.101"},
        {"family": "ipv6", "address": "2001:db8:10::101"},
    ]
}


def check_idempotency():
    global stable_replay_precondition
    before, _ = direct_serial(p0, "198.51.100.10", "p0", "idempotency-before")
    _, get_status, current_etag, _, get_output = api_status()
    stable_replay_precondition = ("If-Match", current_etag)
    _, first_status, first_etag, first, first_output = api_request(
        CURRENT_BODY,
        "stable-replay-key",
        precondition=stable_replay_precondition,
    )
    _, second_status, second_etag, second, second_output = api_request(
        CURRENT_BODY,
        "stable-replay-key",
        precondition=stable_replay_precondition,
    )
    p0.succeed("systemctl restart kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=30)
    after, _ = direct_serial(p0, "198.51.100.10", "p0", "idempotency-after")
    paths = [
        evidence_path("idempotency", "precondition-get.txt", get_output),
        evidence_path("idempotency", "first.txt", first_output),
        evidence_path("idempotency", "replay.txt", second_output),
    ]
    observed = {
        "get_status": get_status,
        "request_precondition": current_etag,
        "first_status": first_status,
        "second_status": second_status,
        "response_etag": first_etag,
        "identical_response": first == second and first_etag == second_etag,
        "serial_before": before,
        "serial_after": after,
    }
    require(get_status == "200" and current_etag == '"g-1"', observed)
    require(first_status == "202" and second_status == "202", observed)
    require(first_etag == current_etag, observed)
    require(observed["identical_response"], observed)
    require(before == after, observed)
    return observed, paths


record(
    "api-002",
    "idempotency",
    "An idempotent replay with its original precondition returns the original generation without another DNS mutation",
    {"identical_response": True, "response_etag": '"g-1"', "soa_changed": False},
    check_idempotency,
)


def check_unchanged_renewal():
    before_serial, _ = direct_serial(
        p0, "198.51.100.10", "p0", "unchanged-renewal-before"
    )
    _, before_http, before_etag, before_state, before_output = api_status()
    p0.succeed(
        "cp /etc/kaiba-test/clock-renewal /var/lib/kaiba-controller/test-clock"
    )
    _, renewal_http, renewal_etag, renewal_state, renewal_output = api_request(
        CURRENT_BODY,
        "fresh-renewal-key",
        precondition=("If-Match", before_etag),
    )
    p0.succeed("systemctl restart kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=30)
    after_serial, _ = direct_serial(
        p0, "198.51.100.10", "p0", "unchanged-renewal-after"
    )
    lease_extended = renewal_state.get("lease_expires_at", "") > before_state.get(
        "lease_expires_at", ""
    )
    observed = {
        "before_http": before_http,
        "request_precondition": before_etag,
        "renewal_http": renewal_http,
        "renewal_etag": renewal_etag,
        "generation_unchanged": renewal_state.get("generation")
        == before_state.get("generation"),
        "lease_extended": lease_extended,
        "soa_unchanged": before_serial == after_serial,
    }
    paths = [
        evidence_path("idempotency", "before-fresh-renewal.txt", before_output),
        evidence_path("idempotency", "fresh-renewal.txt", renewal_output),
    ]
    require(before_http == "200" and renewal_http == "202", observed)
    require(before_etag == '"g-1"' and renewal_etag == before_etag, observed)
    require(observed["generation_unchanged"], observed)
    require(lease_extended, observed)
    require(observed["soa_unchanged"], observed)
    return observed, paths


record(
    "api-002a",
    "idempotency",
    "An unchanged renewal under a fresh key extends the lease without changing generation or DNS",
    {
        "lease_extended": True,
        "generation_unchanged": True,
        "renewal_etag": '"g-1"',
        "soa_unchanged": True,
    },
    check_unchanged_renewal,
)


def check_idempotency_conflict():
    precondition = stable_replay_precondition
    if precondition is None:
        raise CheckFailure({"original_precondition": "missing"})
    different = {"addresses": [{"family": "ipv4", "address": "192.0.2.102"}]}
    _, http_status, _, _, output = api_request(
        different,
        "stable-replay-key",
        precondition=precondition,
    )
    path = evidence_path("idempotency", "conflict.txt", output)
    observed = {
        "http_status": http_status,
        "request_precondition": precondition[1],
    }
    require(http_status == "409", observed)
    return observed, [path]


record(
    "api-003",
    "idempotency",
    "Reusing an idempotency key and its original precondition with a different address set is rejected",
    {"http_status": "409", "request_precondition": '"g-1"'},
    check_idempotency_conflict,
)


CHANGED_BODY = {
    "addresses": [
        {"family": "ipv4", "address": "192.0.2.102"},
        {"family": "ipv6", "address": "2001:db8:10::102"},
    ]
}


def capture_journal_cursor(machine, label):
    status, output = command(
        machine,
        [
            "journalctl",
            "-u",
            "knot.service",
            "-n",
            "0",
            "--show-cursor",
            "--no-pager",
        ],
    )
    match = re.search(r"^-- cursor: (.+)$", output, re.MULTILINE)
    if status != 0 or match is None:
        raise CheckFailure({"server": label, "journal_cursor": "missing"})
    return match.group(1)


def check_changed_update():
    global ixfr_journal_cursors, ixfr_serial_transition
    before, _ = direct_serial(p0, "198.51.100.10", "p0", "changed-before")
    _, get_http, current_etag, _, get_output = api_status()
    ixfr_journal_cursors = {
        "p1": capture_journal_cursor(p1, "p1"),
        "public-a": capture_journal_cursor(public_a, "public-a"),
        "public-b": capture_journal_cursor(public_b, "public-b"),
    }
    try:
        public_a.succeed("systemctl stop knot.service")
        public_b.succeed("systemctl stop knot.service")
        _, http_status, response_etag, response, output = api_request(
            CHANGED_BODY,
            "changed-address-key",
            precondition=("If-Match", current_etag),
        )
        path = evidence_path("changed-update", "controller-response.txt", output)
        poll(
            p0,
            "test \"$(dig @198.51.100.10 pi-001.kaiba.test A +short)\" = 192.0.2.102",
        )
        poll(
            p1,
            "test \"$(dig @198.51.100.11 pi-001.kaiba.test A +short)\" = 192.0.2.102",
        )
        _, origin_http, origin_etag, origin_state, origin_output = wait_api_status(
            "origin-applied"
        )
    finally:
        for machine, server in [
            (public_a, "192.0.2.11"),
            (public_b, "192.0.2.12"),
        ]:
            machine.succeed("systemctl start knot.service")
            machine.wait_for_unit("knot.service", timeout=60)
            poll(
                machine,
                f'test -n "$(dig @{server} kaiba.test. SOA +short +tcp +time=1 +tries=1)"',
                timeout=90,
            )
    for machine, server in [(public_a, "192.0.2.11"), (public_b, "192.0.2.12")]:
        poll(
            machine,
            f'test "$(dig @{server} pi-001.kaiba.test. A +short +time=1 +tries=1)" = 192.0.2.102',
            timeout=90,
        )
    _, public_http, public_etag, public_state, public_output = wait_api_status(
        "publicly-observed"
    )
    after, _ = direct_serial(p0, "198.51.100.10", "p0", "changed-after")
    ixfr_serial_transition = (before, after)
    status_paths = [
        evidence_path("changed-update", "precondition-get.txt", get_output),
        evidence_path("changed-update", "origin-applied-status.txt", origin_output),
        evidence_path("changed-update", "publicly-observed-status.txt", public_output),
    ]
    observed = {
        "get_http": get_http,
        "request_precondition": current_etag,
        "http_status": http_status,
        "response_etag": response_etag,
        "hostname": response.get("hostname"),
        "origin_http": origin_http,
        "origin_etag": origin_etag,
        "origin_state": origin_state.get("status"),
        "public_http": public_http,
        "public_etag": public_etag,
        "public_state": public_state.get("status"),
        "serial_before": before,
        "serial_after": after,
    }
    require(get_http == "200" and current_etag == '"g-1"', observed)
    require(http_status == "202", observed)
    require(
        response_etag == '"g-2"'
        and origin_etag == response_etag
        and public_etag == response_etag,
        observed,
    )
    require(response.get("hostname") == "pi-001.kaiba.test", observed)
    require(origin_http == "200" and origin_state.get("status") == "origin-applied", observed)
    require(public_http == "200" and public_state.get("status") == "publicly-observed", observed)
    require(after > before, observed)
    return observed, [path] + status_paths


record(
    "dns-005",
    "changed-update",
    "A changed complete address set advances the serial through origin-applied and publicly-observed states",
    {
        "hostname": "pi-001.kaiba.test",
        "response_etag": '"g-2"',
        "serial_advanced": True,
        "states": ["origin-applied", "publicly-observed"],
    },
    check_changed_update,
)


def check_convergence():
    observed_serials = {}
    observed_answers = {}
    observed_hashes = {}
    evidence = []
    for query_machine, server, control_machine, label in [
        (p0, "198.51.100.10", p0, "p0"),
        (p1, "198.51.100.11", p1, "p1"),
        (resolver, "192.0.2.11", public_a, "public-a"),
        (resolver, "192.0.2.12", public_b, "public-b"),
    ]:
        serial, soa_output = direct_serial(query_machine, server, label, "changed-update")
        values, answer_output = direct_answer(query_machine, server, label, "A", "changed-update")
        observed_serials[label] = serial
        observed_answers[label] = values
        evidence.append(evidence_path("changed-update", f"{label}-soa.txt", soa_output))
        evidence.append(evidence_path("changed-update", f"{label}-answer.txt", answer_output))
        digest, zone_path = canonical_zone(control_machine, label, "changed-update")
        observed_hashes[label] = digest
        evidence.append(zone_path)
    observed = {"serials": observed_serials, "answers": observed_answers, "zone_hashes": observed_hashes}
    require(len(set(observed_serials.values())) == 1, observed)
    require(all(value == ["192.0.2.102"] for value in observed_answers.values()), observed)
    require(len(set(observed_hashes.values())) == 1, observed)
    return observed, evidence


record(
    "dns-006",
    "changed-update",
    "P1 and both public secondaries converge with P0 by serial, answer, and canonical zone hash",
    {"unique_serial_count": 1, "unique_zone_hash_count": 1, "answer": ["192.0.2.102"]},
    check_convergence,
)


def check_ixfr_evidence():
    transition = ixfr_serial_transition
    if (
        set(ixfr_journal_cursors) != {"p1", "public-a", "public-b"}
        or transition is None
    ):
        raise CheckFailure({"journal_window": "missing"})
    serial_before, serial_after = transition
    observed = {}
    evidence = []
    ixfr_pattern = re.compile(
        r"\[kaiba\.test\.\] IXFR, incoming, remote (?P<source>\S+)@53"
        r"(?: TCP)?, key (?P<key>[^,\s]+), finished, remote serial "
        r"(?P<after>\d+)(?:,|$)"
    )
    transition_pattern = re.compile(
        r"\[kaiba\.test\.\] refresh, remote (?P<source>\S+)@53"
        r"(?: TCP)?, key (?P<key>[^,\s]+), zone updated, .*\bserial "
        r"(?P<before>\d+) -> (?P<after>\d+)(?:,|$)"
    )
    for machine, label, allowed_sources, expected_key in [
        (p1, "p1", ["198.51.100.10"], "kaiba-p1-transfer."),
        (
            public_a,
            "public-a",
            ["198.51.100.10", "198.51.100.11"],
            "kaiba-public-transfer.",
        ),
        (
            public_b,
            "public-b",
            ["198.51.100.10", "198.51.100.11"],
            "kaiba-public-transfer.",
        ),
    ]:
        status, output = command(
            machine,
            [
                "journalctl",
                "-u",
                "knot.service",
                "-o",
                "cat",
                "--no-pager",
                f"--after-cursor={ixfr_journal_cursors[label]}",
            ],
        )
        lines = output.splitlines()
        ixfr_by_identity = {}
        transition_by_identity = {}
        relevant_lines = []
        for line in lines:
            ixfr_match = ixfr_pattern.search(line)
            if (
                ixfr_match is not None
                and int(ixfr_match.group("after")) == serial_after
            ):
                identity = (
                    ixfr_match.group("source"),
                    ixfr_match.group("key"),
                )
                ixfr_by_identity.setdefault(identity, []).append(line)
                relevant_lines.append(line)
            transition_match = transition_pattern.search(line)
            if (
                transition_match is not None
                and int(transition_match.group("before")) == serial_before
                and int(transition_match.group("after")) == serial_after
            ):
                identity = (
                    transition_match.group("source"),
                    transition_match.group("key"),
                )
                transition_by_identity.setdefault(identity, []).append(line)
                relevant_lines.append(line)

        allowed_identities = [
            (source, expected_key) for source in allowed_sources
        ]
        ixfr_sources = [
            source
            for source, key in allowed_identities
            if ixfr_by_identity.get((source, key))
        ]
        transition_sources = [
            source
            for source, key in allowed_identities
            if transition_by_identity.get((source, key))
        ]
        matching_identities = [
            identity
            for identity in allowed_identities
            if ixfr_by_identity.get(identity)
            and transition_by_identity.get(identity)
        ]
        selected_identity = matching_identities[0] if matching_identities else None
        source = selected_identity[0] if selected_identity is not None else None
        complete_identities = set(ixfr_by_identity).intersection(
            transition_by_identity
        )
        unexpected_identities = sorted(
            complete_identities.difference(allowed_identities)
        )
        same_source = selected_identity is not None
        authorized = same_source and not unexpected_identities
        fallback_lines = sorted(
            {
                line
                for line in lines
                if "[kaiba.test.]" in line and "fallback to AXFR" in line
            }
        )
        fallback = bool(fallback_lines)
        observed[label] = {
            "allowed_sources": allowed_sources,
            "expected_key": expected_key,
            "source": source,
            "ixfr_sources": ixfr_sources,
            "transition_sources": transition_sources,
            "same_source": same_source,
            "authorized": authorized,
            "unexpected_identities": [
                {"source": item[0], "key": item[1]}
                for item in unexpected_identities
            ],
            "serial_before": serial_before,
            "serial_after": serial_after,
            "journal_status": status,
            "ixfr_finished": bool(ixfr_sources),
            "serial_transition": bool(transition_sources),
            "axfr_fallback": fallback,
        }
        matching = sorted(set(relevant_lines + fallback_lines))
        evidence.append(
            evidence_path(
                "changed-update",
                f"{label}-ixfr-log.txt",
                (
                    f"server={label}\n"
                    f"allowed_sources={','.join(allowed_sources)}\n"
                    f"expected_key={expected_key}\n"
                    f"source={source or 'none'}\n"
                    f"serial={serial_before}->{serial_after}\n"
                    f"same_source={str(same_source).lower()}\n"
                    f"authorized={str(authorized).lower()}\n"
                    + "\n".join(matching)
                    + ("\n" if matching else "")
                ),
            )
        )
    require(
        all(
            item["journal_status"] == 0
            and item["ixfr_finished"]
            and item["serial_transition"]
            and item["same_source"]
            and item["authorized"]
            and not item["axfr_fallback"]
            for item in observed.values()
        ),
        observed,
    )
    return observed, evidence


record(
    "dns-007",
    "changed-update",
    "The subsequent change is explicitly logged as IXFR on P1 and both public secondaries",
    {
        "p1": {
            "ixfr_finished": True,
            "serial_transition": True,
            "same_source": True,
            "authorized": True,
        },
        "public-a": {
            "ixfr_finished": True,
            "serial_transition": True,
            "same_source": True,
            "authorized": True,
        },
        "public-b": {
            "ixfr_finished": True,
            "serial_transition": True,
            "same_source": True,
            "authorized": True,
        },
    },
    check_ixfr_evidence,
)


def check_stale_replay():
    require(stable_replay_precondition is not None, {"original_precondition": "missing"})
    before, _ = direct_serial(p0, "198.51.100.10", "p0", "stale-replay-before")
    _, replay_http, replay_etag, replay, replay_output = api_request(
        CURRENT_BODY,
        "stable-replay-key",
        precondition=stable_replay_precondition,
    )
    _, stale_http, _, _, stale_output = api_request(
        CURRENT_BODY,
        "distinct-stale-key",
        precondition=stable_replay_precondition,
    )
    p0.succeed("systemctl restart kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=30)
    poll(
        public_a,
        "test \"$(dig @192.0.2.11 pi-001.kaiba.test A +short)\" = 192.0.2.102",
    )
    poll(
        public_b,
        "test \"$(dig @192.0.2.12 pi-001.kaiba.test A +short)\" = 192.0.2.102",
    )
    after, _ = direct_serial(p0, "198.51.100.10", "p0", "stale-replay-after")
    paths = [
        evidence_path("stale-replay", "old-key-replay.txt", replay_output),
        evidence_path("stale-replay", "distinct-stale-key.txt", stale_output),
    ]
    observed = {
        "replay_http_status": replay_http,
        "replay_etag": replay_etag,
        "replayed_generation": replay.get("generation"),
        "replayed_addresses": replay.get("addresses"),
        "distinct_stale_http_status": stale_http,
        "serial_before": before,
        "serial_after": after,
        "current_answer": "192.0.2.102",
    }
    require(
        replay_http == "202"
        and replay_etag == '"g-1"'
        and replay.get("generation") == 1,
        observed,
    )
    require(stale_http == "412", observed)
    require(before == after, observed)
    return observed, paths


record(
    "api-004",
    "stale-replay",
    "An exact older-key replay returns its original result, while a distinct stale write is rejected without reverting DNS",
    {
        "replay_http_status": "202",
        "replayed_generation": 1,
        "distinct_stale_http_status": "412",
        "soa_changed": False,
        "current_answer": "192.0.2.102",
    },
    check_stale_replay,
)


def check_https():
    resolver.succeed("systemctl restart unbound.service")
    resolver.wait_for_unit("unbound.service", timeout=30)
    poll(
        resolver,
        'test "$(dig @127.0.0.1 pi-001.kaiba.test. A +short +time=3 +tries=1)" = 192.0.2.102',
        timeout=90,
    )
    poll(
        resolver,
        'test "$(dig @127.0.0.1 pi-001.kaiba.test. AAAA +short +time=3 +tries=1)" = 2001:db8:10::102',
        timeout=90,
    )
    status4, output4 = command(
        resolver,
        [
            "curl",
            "-4",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
            "--cacert",
            "/etc/kaiba-test/ca.pem",
            "https://pi-001.kaiba.test/",
        ],
    )
    status6, output6 = command(
        resolver,
        [
            "curl",
            "-6",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
            "--cacert",
            "/etc/kaiba-test/ca.pem",
            "https://pi-001.kaiba.test/",
        ],
    )
    paths = [
        evidence_path("https", "ipv4.txt", output4),
        evidence_path("https", "ipv6.txt", output6),
    ]
    answers.append(
        {
            "phase": "https",
            "server": "pi-001",
            "name": "pi-001.kaiba.test.",
            "type": "HTTPS",
            "values": [normalized(output4).strip()],
            "authoritative": False,
            "transport": "https",
        }
    )
    observed = {"ipv4_status": status4, "ipv6_status": status6, "body": normalized(output4).strip()}
    require(status4 == 0 and status6 == 0, observed)
    require(normalized(output4).strip() == "kaiba pi-001", observed)
    require(normalized(output6).strip() == "kaiba pi-001", observed)
    return observed, paths


record(
    "https-001",
    "https",
    "Recursive DNS leads to certificate-validated HTTPS directly on the device over IPv4 and IPv6",
    {"body": "kaiba pi-001", "ipv4": "success", "ipv6": "success"},
    check_https,
)


def stop_p0_and_check_dns():
    p0.shutdown()
    values_a, output_a = direct_answer(resolver, "192.0.2.11", "public-a", "A", "p0-outage")
    values_b, output_b = direct_answer(resolver, "192.0.2.12", "public-b", "A", "p0-outage")
    paths = [
        evidence_path("p0-outage", "public-a.txt", output_a),
        evidence_path("p0-outage", "public-b.txt", output_b),
    ]
    role_status, role_output = command(
        p1,
        ["knotc", "conf-read", "zone[kaiba.test.].master"],
    )
    role_path = evidence_path("p0-outage", "p1-role.txt", role_output)
    observed = {
        "public-a": values_a,
        "public-b": values_b,
        "p1_master_configuration": normalized(role_output).strip(),
    }
    require(values_a == ["192.0.2.102"] and values_b == ["192.0.2.102"], observed)
    require(role_status == 0 and "primary" in role_output, observed)
    return observed, paths + [role_path]


record(
    "fail-001",
    "p0-outage",
    "Public DNS continues serving while P1 remains configured as a read-only secondary during P0 outage",
    {"answer": ["192.0.2.102"], "p1_promoted": False},
    stop_p0_and_check_dns,
)


def check_update_failure_during_outage():
    status, http_status, _, _, _output = api_request(
        CURRENT_BODY,
        "writer-down-key",
        precondition=("If-Match", '"g-2"'),
    )
    path = evidence_path(
        "p0-outage",
        "update-failure.txt",
        f"transport_exit_nonzero={status != 0}\nhttp_status={http_status}\n",
    )
    observed = {"transport_status": status, "http_status": http_status}
    require(status != 0 and http_status == "000", observed)
    return observed, [path]


record(
    "fail-002",
    "p0-outage",
    "A device receives a retryable transport failure instead of a false acknowledgment while P0 is down",
    {"acknowledged": False},
    check_update_failure_during_outage,
)


def check_p1_bootstrap():
    try:
        public_b.succeed("systemctl stop knot.service")
        public_b.succeed(
            "rm -rf /var/lib/knot/journal /var/lib/knot/timers /var/lib/knot/kaiba.test.zone"
        )
    finally:
        public_b.succeed("systemctl start knot.service")
        public_b.wait_for_unit("knot.service", timeout=60)
        poll(
            public_b,
            'test -n "$(dig @192.0.2.12 kaiba.test. SOA +short +tcp +time=1 +tries=1)"',
            timeout=90,
        )
    poll(
        public_b,
        'test "$(dig @192.0.2.12 pi-001.kaiba.test. A +short +time=1 +tries=1)" = 192.0.2.102',
        timeout=90,
    )
    values, output = direct_answer(resolver, "192.0.2.12", "public-b", "A", "p1-bootstrap")
    status, logs = command(
        public_b,
        ["journalctl", "-u", "knot.service", "-o", "cat", "--no-pager", "-n", "200"],
    )
    matching = "\n".join(
        sorted(
            {
                line
                for line in logs.splitlines()
                if "AXFR, incoming, remote 198.51.100.11@53" in line
            }
        )
    )
    from_p1 = bool(matching)
    path = evidence_path(
        "p1-bootstrap",
        "public-b.txt",
        (
            output
            + "transfer=AXFR\n"
            + "source=p1\n"
            + f"incoming_detected={str(from_p1).lower()}\n"
        ),
    )
    observed = {"answer": values, "service_log_status": status, "axfr_from_p1": from_p1}
    require(values == ["192.0.2.102"] and status == 0 and from_p1, observed)
    return observed, [path]


record(
    "fail-003",
    "p1-bootstrap",
    "A fresh public secondary can bootstrap from P1 while P0 is unavailable",
    {"answer": ["192.0.2.102"], "axfr_from_p1": True},
    check_p1_bootstrap,
)


def restore_public_authority(machine, server):
    machine.succeed("systemctl start knot.service")
    machine.wait_for_unit("knot.service", timeout=60)
    machine.succeed("systemctl is-active --quiet knot.service")
    poll(
        machine,
        f'test "$(dig @{server} pi-001.kaiba.test. A +short +norecurse +time=1 +tries=1)" = 192.0.2.102',
        timeout=90,
    )
    poll(
        machine,
        f'test -n "$(dig @{server} kaiba.test. SOA +short +tcp +norecurse +time=1 +tries=1)"',
        timeout=90,
    )
    answer_status, answer_output = command(
        machine,
        [
            "dig",
            f"@{server}",
            "pi-001.kaiba.test.",
            "A",
            "+norecurse",
            "+noall",
            "+comments",
            "+answer",
            "+time=1",
            "+tries=1",
        ],
    )
    soa_status, soa_output = command(
        machine,
        [
            "dig",
            f"@{server}",
            "kaiba.test.",
            "SOA",
            "+short",
            "+tcp",
            "+norecurse",
            "+time=1",
            "+tries=1",
        ],
    )
    soa_fields = soa_output.split()
    observed = {
        "unit_active": True,
        "authoritative_answer": "flags: qr aa" in answer_output
        and "192.0.2.102" in answer_output,
        "soa_serial": int(soa_fields[2]) if len(soa_fields) >= 3 else None,
    }
    require(answer_status == 0 and soa_status == 0, observed)
    require(observed["authoritative_answer"] and observed["soa_serial"] is not None, observed)
    return observed, "authoritative answer:\n" + answer_output + "SOA:\n" + soa_output


def query_with_public_authority_stopped(machine, server, label):
    status = -1
    output = ""
    paths = []
    try:
        machine.succeed("systemctl stop knot.service")
        resolver.succeed("systemctl restart unbound.service")
        resolver.wait_for_unit("unbound.service", timeout=30)
        recursive_query = (
            "dig @127.0.0.1 pi-001.kaiba.test. A +short +time=3 +tries=1"
        )
        poll(
            resolver,
            f'test "$({recursive_query})" = 192.0.2.102',
            timeout=90,
        )
        status, output = command(
            resolver,
            [
                "dig",
                "@127.0.0.1",
                "pi-001.kaiba.test.",
                "A",
                "+short",
                "+time=3",
                "+tries=1",
            ],
        )
    except Exception:
        status, output = command(
            resolver,
            [
                "dig",
                "@127.0.0.1",
                "pi-001.kaiba.test.",
                "A",
                "+short",
                "+time=3",
                "+tries=1",
            ],
        )
        raise
    finally:
        paths.append(
            evidence_path(
                "public-outage",
                f"{label}-stopped.txt",
                output
                + f"\nquery_status={status}\n"
                + "expected_fallback_answer=192.0.2.102\n",
            )
        )
        restored, restore_output = restore_public_authority(machine, server)
        paths.append(
            evidence_path(
                "public-outage", f"{label}-restored.txt", restore_output
            )
        )
    return status, output, restored, paths


def check_single_public_failure():
    status_a, output_a, restored_a, paths_a = query_with_public_authority_stopped(
        public_a, "192.0.2.11", "public-a"
    )
    status_b, output_b, restored_b, paths_b = query_with_public_authority_stopped(
        public_b, "192.0.2.12", "public-b"
    )

    paths = paths_a + paths_b
    observed = {
        "public-a-stopped": {"query_status": status_a, "answer": output_a.strip()},
        "public-b-stopped": {"query_status": status_b, "answer": output_b.strip()},
        "public-a-restored": restored_a,
        "public-b-restored": restored_b,
    }
    require(status_a == 0 and output_a.strip() == "192.0.2.102", observed)
    require(status_b == 0 and output_b.strip() == "192.0.2.102", observed)
    return observed, paths


record(
    "fail-004",
    "public-outage",
    "Recursive resolution succeeds with either public secondary unavailable, and each authority is verified after restoration",
    {
        "public-a-stopped": "192.0.2.102",
        "public-b-stopped": "192.0.2.102",
        "public-a-restored": True,
        "public-b-restored": True,
    },
    check_single_public_failure,
)


def check_p0_recovery():
    p0.start()
    p0.wait_for_unit("knot.service", timeout=60)
    p0.wait_for_unit("kaiba-controller.service", timeout=60)
    _, get_http, current_etag, _, get_output = api_status()
    _, http_status, response_etag, _, output = api_request(
        CURRENT_BODY,
        "recovery-update-key",
        precondition=("If-Match", current_etag),
    )
    p0.succeed("systemctl start kaiba-publisher.service")
    p0.wait_for_unit("kaiba-publisher.service", timeout=30)
    poll(
        p1,
        "test \"$(dig @198.51.100.11 pi-001.kaiba.test A +short)\" = 192.0.2.101",
        timeout=60,
    )
    poll(
        public_a,
        "test \"$(dig @192.0.2.11 pi-001.kaiba.test A +short)\" = 192.0.2.101"
    )
    poll(
        public_b,
        "test \"$(dig @192.0.2.12 pi-001.kaiba.test A +short)\" = 192.0.2.101"
    )
    serial_values = []
    for machine, server, label in [
        (p0, "198.51.100.10", "p0"),
        (p1, "198.51.100.11", "p1"),
        (resolver, "192.0.2.11", "public-a"),
        (resolver, "192.0.2.12", "public-b"),
    ]:
        value, _ = direct_serial(machine, server, label, "recovery")
        serial_values.append(value)
    paths = [
        evidence_path("recovery", "precondition-get.txt", get_output),
        evidence_path("recovery", "update-response.txt", output),
    ]
    observed = {
        "get_http": get_http,
        "request_precondition": current_etag,
        "http_status": http_status,
        "response_etag": response_etag,
        "serials": serial_values,
    }
    require(
        get_http == "200"
        and current_etag == '"g-2"'
        and http_status == "202"
        and response_etag == '"g-3"'
        and len(set(serial_values)) == 1,
        observed,
    )
    return observed, paths


record(
    "fail-005",
    "recovery",
    "P0 restart restores publication and every authoritative copy reconverges",
    {"http_status": "202", "response_etag": '"g-3"', "unique_serial_count": 1},
    check_p0_recovery,
)


def check_lease_expiry():
    p0.succeed(
        "cp /etc/kaiba-test/clock-expired /var/lib/kaiba-controller/test-clock"
    )
    poll(
        public_a,
        "test -z \"$(dig @192.0.2.11 pi-001.kaiba.test A +short)\"",
        timeout=90,
    )
    poll(
        public_b,
        "test -z \"$(dig @192.0.2.12 pi-001.kaiba.test A +short)\"",
        timeout=90,
    )
    poll(
        public_a,
        "test -z \"$(dig @192.0.2.11 pi-001.kaiba.test AAAA +short)\"",
        timeout=90,
    )
    poll(
        public_b,
        "test -z \"$(dig @192.0.2.12 pi-001.kaiba.test AAAA +short)\"",
        timeout=90,
    )
    values_a, output_a = direct_answer(resolver, "192.0.2.11", "public-a", "A", "lease-expiry")
    values_a6, output_a6 = direct_answer(resolver, "192.0.2.11", "public-a", "AAAA", "lease-expiry")
    values_b, output_b = direct_answer(resolver, "192.0.2.12", "public-b", "A", "lease-expiry")
    values_b6, output_b6 = direct_answer(resolver, "192.0.2.12", "public-b", "AAAA", "lease-expiry")
    paths = [
        evidence_path("lease-expiry", "public-a.txt", output_a + output_a6),
        evidence_path("lease-expiry", "public-b.txt", output_b + output_b6),
    ]
    observed = {
        "public-a": {"A": values_a, "AAAA": values_a6},
        "public-b": {"A": values_b, "AAAA": values_b6},
    }
    require(values_a == [] and values_a6 == [] and values_b == [] and values_b6 == [], observed)
    return observed, paths


record(
    "lease-001",
    "lease-expiry",
    "An unrenewed lease removes both address families and propagates the deletion",
    {"A": [], "AAAA": []},
    check_lease_expiry,
)


for machine, filename in [
    (p0, "final-p0.zone"),
    (p1, "final-p1.zone"),
    (public_a, "final-public-a.zone"),
    (public_b, "final-public-b.zone"),
]:
    try:
        status, output = command(machine, ["knotc", "zone-read", "kaiba.test."])
        if status == 0:
            (ZONES / filename).write_text(
                canonical_dns_records(output), encoding="utf-8"
            )
    except Exception:
        pass


claims = {
    "exercised": [
        {
            "id": "delegated-resolution",
            "statement": "Iterative resolution through the simulated parent delegation reaches only the redundant public authoritative secondaries over UDP and TCP.",
            "assertions": ["dns-001", "dns-003", "dns-004", "fail-004"],
        },
        {
            "id": "authenticated-publication",
            "statement": "An mTLS-authenticated device intent is durably projected through RFC 2136 and authenticated transfers.",
            "assertions": ["api-001", "dns-002a", "dns-005", "dns-006", "dns-007"],
        },
        {
            "id": "authorization-boundary",
            "statement": "Untrusted updates, recursive service, and anonymous transfers are rejected.",
            "assertions": ["sec-001", "sec-002", "sec-003", "sec-004", "api-002", "api-002a", "api-003", "api-004"],
        },
        {
            "id": "direct-device-https",
            "statement": "Resolved HTTPS terminates directly on the device over both address families.",
            "assertions": ["https-001"],
        },
        {
            "id": "read-availability",
            "statement": "P0 and public-secondary outages preserve authoritative read availability without promoting P1.",
            "assertions": ["fail-001", "fail-002", "fail-003", "fail-004", "fail-005"],
        },
        {
            "id": "lease-cleanup",
            "statement": "Unrenewed desired state becomes an explicit DNS tombstone rather than relying on TTL expiry.",
            "assertions": ["lease-001"],
        },
    ],
    "simulated": [
        {
            "id": "registrar-delegation",
            "statement": "The parent authority simulates the registry outcome of Namecheap CustomDNS delegation.",
        },
        {
            "id": "managed-provider",
            "statement": "Two Knot instances emulate a managed secondary-DNS provider's protocol boundary.",
        },
        {
            "id": "test-pki",
            "statement": "Private test PKI substitutes for production device provisioning and public Web PKI.",
        },
    ],
    "deferred": [
        {"id": "real-provider", "statement": "Real Namecheap and managed-provider APIs and SLAs are not exercised."},
        {"id": "internet-path", "statement": "ISP, modem, NAT, CGNAT, BGP, DDoS, and outside-in reachability are not exercised."},
        {"id": "public-acme-dnssec", "statement": "Public ACME issuance and DNSSEC are not implemented in this slice."},
        {"id": "writer-promotion", "statement": "Automatic P1 promotion, election, fencing, and split-brain recovery are deferred."},
        {"id": "control-plane-ha", "statement": "Redundant update gateways and replicated desired-state storage are deferred."},
        {"id": "fleet-scale", "statement": "Fleet-scale load, sharding, multi-zone publication, and geographic latency are deferred."},
        {
            "id": "device-platform",
            "statement": "Physical Raspberry Pi images, secure-boot mutation, persistent provisioning, production secrets, and monitoring are deferred; probe software verification is reported separately.",
        },
    ],
}

overall = "passed" if all(item["status"] == "passed" for item in assertions) else "failed"
result = {
    "schema_version": 1,
    "suite": "kaiba-dns-pilot",
    "overall": overall,
    "assertions": assertions,
    "claims": claims,
    "serials": serials,
    "answers": answers,
}

(OUTPUT / "result.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
with (OUTPUT / "events.jsonl").open("w", encoding="utf-8") as events_file:
    for item in events:
        events_file.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
