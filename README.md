# pfsense-rule-audit

Parse pfSense/OPNsense config.xml and flag firewall rules worth reviewing.

## What it checks
- Any-any pass rules on WAN
- Rule shadowing
- Disabled rules

## What it does NOT check
Static parsing does not prove a firewall is secure. This tool finds review candidates only.

## Install
pip install lxml

## Usage
python parse_pfsense.py sample_config.xml