# pfSense Rule Audit

![CI](https://github.com/Omartheone10/pfsense-rule-audit/actions/workflows/test.yml/badge.svg)
![License](https://img.shields.io/github/license/Omartheone10/pfsense-rule-audit)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

Parse a pfSense `config.xml` export and flag firewall rules that warrant human review — each with a stable finding ID, a severity, and a numeric score for sorting.

Static parsing does not prove a firewall is secure. This tool produces **review candidates**, not verdicts: it reads the config file, nothing else, and never touches a live device.

## Why this exists

Manual security audits of pfSense rule sets are slow, repetitive, and error-prone — the same classes of mistake (an any-any pass on WAN, SSH left reachable from the internet, a rule shadowed into dead code) recur on every firewall. This tool automates the boring first pass with Python static analysis, so a human reviewer spends their time judging findings instead of hunting them. The check list comes from my CCNA/MTCNA network and security background: shadowed rules and exposed WAN management ports are the two failure classes I have seen do real damage.

## What it checks

| Finding ID | Severity | Score | What it looks for |
|---|---|---|---|
| `PF-WAN-001` | **CRITICAL** | 5 | WAN `pass` rule with `<source><any/></source>` and `<destination><any/></destination>` — a true any-any rule |
| `PF-WAN-002` | **HIGH** | 4 | WAN `pass` rule with destination port 22, 23, or 3389 — remote-management port exposed |
| `PF-WAN-003` | **HIGH** | 4 | WAN `pass` rule on port 80/443 whose destination address is public, missing, or unparseable — admin/service exposure toward a non-internal destination |
| `PF-PUB-001` | **LOW** | 2 | WAN `pass` rule on port 80/443 toward a private destination — published service, verify it is intended |
| `PF-SHADOW-001` | **LOW** | 2 | WAN rule positioned after a any-any WAN pass — unreachable in the live path, shadowed by it |
| `PF-LOG-001` | **MEDIUM** | 3 | `block` rule with no `<log/>` tag — blocked traffic you cannot review later |
| `PF-DOC-001` | **MEDIUM** | 3 | Rule with no `<descr>` tag on any interface — undocumented intent |
| `PF-STATE-001` | **LOW** | 2 | Rule with `<disabled/>` tag — cleanup candidate; flagged, then not evaluated further because it is not in the live path |

Notes on the contract:

- **Stable IDs.** Finding IDs never change between runs, so a finding can be referenced from a ticket, a report, or a client email and still mean the same thing next month.
- **Multiple findings per rule.** A rule that is both any-any and undocumented produces both `PF-WAN-001` and `PF-DOC-001`.
- **Severity and score.** CRITICAL/HIGH/MEDIUM/LOW with a numeric score (5–1 in the table) so results sort by risk without string comparison.
- **Shadowing scope, stated precisely.** `PF-SHADOW-001` detects WAN rules shadowed by an *earlier any-any pass* on WAN. It is not general pairwise shadow analysis — see Limitations.

Each finding is a dictionary with `rule_index` (1-based position in the config), `finding_id`, `severity`, `score`, `message`, and — where relevant — the rule's `action`.

## Example output

```text
[{'rule_index': 1, 'finding_id': 'PF-DOC-001', 'severity': 'MEDIUM', 'score': 3, 'message': 'Rule missing description'},
 {'rule_index': 5, 'finding_id': 'PF-WAN-001', 'severity': 'CRITICAL', 'score': 5, 'action': 'pass', 'message': 'True Any-Any rule on WAN'},
 {'rule_index': 9, 'finding_id': 'PF-WAN-002', 'severity': 'HIGH', 'score': 4, 'action': 'pass', 'message': 'Remote-management port exposed'},
 ...
]
```

Excerpt of a real run on [`sample_config.xml`](sample_config.xml); stdout prints the list on a single line, reformatted here across lines for readability. It is a Python list of dictionaries — not JSON yet; a JSON/pretty printer is on the roadmap. The full run on the sample returns **16 findings: 2 CRITICAL, 1 HIGH, 8 MEDIUM, 5 LOW**.

## Install

Python 3.8+. One runtime dependency:

```bash
pip install defusedxml
```

`defusedxml` is deliberate: a `config.xml` handed to you by a client is untrusted input, and stdlib `xml.etree` will happily expand entity bombs. Tests additionally need `pytest`.

## Usage

```bash
python parse_pfsense.py sample_config.xml
```

Failures are quiet-free and machine-friendly:

| Condition | Behavior |
|---|---|
| File does not exist | `Error: File <name> not found` on stderr, exit code 2 |
| Not valid XML | `Error: File <name> not a valid XML` on stderr, exit code 2 |
| Larger than 10 MiB | Rejected with an error, exit code 2 |
| Entity-expansion / XXE payloads | Neutralized by `defusedxml` before parsing |

## Sample config provenance

`sample_config.xml` is **synthetic, by design**: its rules were written one-by-one to trigger every finding ID — any-any passes, shadowed rules, exposed management ports, missing descriptions and logs. It is not a production config and contains no real addresses. `test_nat_fixture.xml` proves the parser handles configs that carry a `<nat>` section: NAT rules parse without crashing and without being misread as filter rules (the fixture yields exactly one finding — the missing description on its filter rule).

## Tests and CI

Nine tests, run by GitHub Actions on every push to `main` (Python 3.13), and locally with:

```bash
pytest -v
```

What the suite pins down:

- **Finding counts** on the sample: 16 total, and the exact per-severity split (2/1/8/5)
- **Critical semantics**: the two CRITICAL findings are exactly `(rule 5, PF-WAN-001)` and `(rule 7, PF-WAN-001)` — asserted by ID, not by position luck
- **Shadow detection** on a generated two-rule config (`tmp_path` fixture): one any-any pass, one rule behind it, exactly one shadow finding
- **NAT safety**: the `<nat>` fixture produces exactly one finding
- **Error paths**: a missing file raises `ValueError` rather than crashing with a traceback
- **Address parsing**: `172.160.1.1` on port 443 flags `PF-WAN-003` — 172.160.x.x looks like RFC1918 at a glance but is public space, and the `ipaddress` module (not a string check) is what catches it

## Limitations

Stated plainly, because an audit tool that overstates itself is worse than none:

- **Does not resolve pfSense aliases** to actual IPs/ports — a rule whose port is an alias name is not matched by the port checks.
- **Does not correlate with NAT / port-forwarding rules** — `<nat>` sections parse but are not audited yet.
- **Port checks use exact string matching** — ranges like `80:85` are missed.
- **Static XML only** — no live pfSense API access; you audit an export, not a running box.
- **Shadow detection is scoped** to WAN rules behind an earlier any-any pass, not general pairwise shadowing.
- **Output is a raw list repr** — machine-readable, not yet pretty.

Planned checks: duplicate rules, unused aliases, NAT entries without business purpose, VPN rules without source restrictions, and a JSON/pretty output mode.

## Engineering notes

- `defusedxml` over stdlib XML because client-supplied configs are untrusted input.
- `ipaddress` over string comparison because near-miss address space (172.160/16 vs 172.16/12) is exactly where string checks fail.
- Stable finding IDs because findings end up in tickets and client reports, where "the third item in yesterday's output" is not a reference.
- Non-zero exit codes on bad input so the tool composes with scripts and CI instead of printing tracebacks into them.

## License

MIT — see [LICENSE](LICENSE).
