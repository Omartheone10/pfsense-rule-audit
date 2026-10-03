# pfsense-rule-audit

Parse pfSense/OPNsense `config.xml` and flag firewall rules worth reviewing.

## What it checks
- Any-any pass rules on WAN (CRITICAL)
- Admin services exposed on WAN — port 22, 80, 443 (HIGH)
- Missing rule descriptions (MEDIUM)
- Missing logging on block rules (MEDIUM)
- Disabled rules (LOW)

## What it does NOT check yet
- Rule shadowing (planned)
- Duplicate rules (planned)
- Unused aliases (planned)
- NAT entries without business purpose (planned)
- VPN rules without source restrictions (planned)

Static parsing does not prove a firewall is secure. This tool finds review candidates only.

## Install