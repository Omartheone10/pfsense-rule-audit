# pfSense Rule Audit

Parse a pfSense `config.xml` export and flag firewall rules that warrant human review.

Static parsing does not prove a firewall is secure. This tool finds review candidates.

---

## What it checks

| Check | Severity | What it looks for |
|---|---|---|
| Any-any pass on WAN | **CRITICAL** | WAN rule with `<source><any/></source>`, `<destination><any/></destination>`, and `type = pass` |
| Remote-management port on WAN | **HIGH** | WAN pass rule with destination port 22, 23, or 3389 |
| Missing rule description | **MEDIUM** | Rule with no `<descr>` tag on any interface |
| Missing logging on block rules | **MEDIUM** | `block` rule with no `<log/>` tag |
| Disabled rules | **LOW** | Rule with `<disabled/>` tag — cleanup candidate |
| WAN web service publication | **LOW** | WAN pass rule on port 80 or 443 targeting an internal address |

Each finding includes:
- `rule_index` — the rule's position in the config (1-based)
- `severity` — CRITICAL / HIGH / MEDIUM / LOW
- `score` — numeric 1–5 for sorting
- `message` — human-readable description

Multiple findings per rule are supported (e.g., a rule that is both any-any and missing a description).

---

## What it does NOT check yet

- Rule shadowing (planned)
- Duplicate rules (planned)
- Unused aliases (planned)
- NAT entries without business purpose (planned)
- VPN rules without source restrictions (planned)
- Logging inconsistencies beyond missing `<log/>` on block rules (planned)

---

## Install

No dependencies beyond the Python standard library. Requires Python 3.8+.

---

## Usage

```bash
python parse_pfsense.py sample_config.xml