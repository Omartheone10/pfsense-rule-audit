import ipaddress
import argparse
import defusedxml.ElementTree as ET
import os
import sys

def audit(config_path):
    try:
        file_size = os.path.getsize(config_path)

        if file_size > (10 * 1024 * 1024):
            raise ValueError(f"File {config_path} exceeds the 10 MiB limit.")

        tree = ET.parse(config_path)
    except FileNotFoundError:
        raise ValueError(f"File {config_path} not found")
    except ET.ParseError:
        raise ValueError(f"File {config_path} not a valid XML")

    root = tree.getroot()
    findings = []
    rule_index = 1
    seen_wan_any_any = False

    # Find all the 'rule' one by one
    for rule in root.findall('./filter/rule'):

        # Finding if a rule is already disabled
        disabled_rule = rule.find('disabled')
        if disabled_rule is not None:
            finding = {
                "rule_index": rule_index,
                "finding_id": "PF-STATE-001",
                "severity": 'LOW',
                "score": 2,
                "message": "Rule is disabled - consider cleanup"
            }
            findings.append(finding)
            rule_index += 1
            continue

        rule_type = rule.find('type')
        if rule_type is not None:
            rule_type_name = rule_type.text
            rule_log = rule.find('log')
            if (rule_log is None) and (rule_type_name == 'block'):
                finding = {
                    "rule_index": rule_index,
                    "finding_id": "PF-LOG-001",
                    "severity": "MEDIUM",
                    "score": 3,
                    "message": 'Rule missing log'
                }
                findings.append(finding)

        # Finding if a rule missing the description tag
        descr = rule.find('descr')
        if descr is None:
            finding = {
                "rule_index": rule_index,
                "finding_id": "PF-DOC-001",
                "severity": "MEDIUM",
                "score": 3,
                "message": "Rule missing description"
            }
            findings.append(finding)

        # Find the interface tag
        interface = rule.find('interface')
        if interface is not None:
            interface_name = interface.text
            if interface_name == 'wan':
                if seen_wan_any_any == True:
                    finding = {
                        "rule_index": rule_index,
                        "finding_id": "PF-SHADOW-001",
                        "severity": "LOW",
                        "score": 2,
                        "message": "Rule is shadowed by previous Any-Any rule"
                    }
                    findings.append(finding)
                # Find source tag's child element any
                source_any = rule.find('source/any')

                # Find destination tag's child element any
                dest_any = rule.find('destination/any')
                rule_type = rule.find('type')
                if rule_type is not None:
                    rule_type_name = rule_type.text
                    # Flag true any-any rules (source any + dest any + action pass)
                    if (source_any is not None) and (rule_type_name == 'pass') and (dest_any is not None):
                        # Creating a dictionary
                        finding = {
                            "rule_index": rule_index,
                            "finding_id": "PF-WAN-001",
                            "severity": "CRITICAL",
                            "score": 5,
                            "action": rule_type_name,
                            "message": "True Any-Any rule on WAN"
                        }
                        findings.append(finding)

                        seen_wan_any_any = True

                    port = ""
                    port = rule.find('destination/port')
                    if port is not None:
                        port_number = port.text

                        if rule_type_name == "pass":
                            if port_number == '22' or port_number == '23' or port_number == '3389':
                                finding = {
                                    "rule_index": rule_index,
                                    "finding_id": "PF-WAN-002",
                                    "severity": "HIGH",
                                    "score": 4,
                                    "action": rule_type_name,
                                    "message": "Remote-management port exposed"
                                }
                                findings.append(finding)

                            else:
                                if port_number == '80' or port_number == '443':
                                    destination = rule.find('destination/address')
                                    if destination is None or destination.text is None:
                                        destination_ip = ""
                                    else:
                                        destination_ip = destination.text

                                    try:
                                        is_priv = ipaddress.ip_address(destination_ip).is_private
                                    except ValueError:
                                        is_priv = False

                                    if is_priv:
                                        finding = {
                                            "rule_index": rule_index,
                                            "finding_id": "PF-PUB-001",
                                            "severity": "LOW",
                                            "score": 2,
                                            "action": rule_type_name,
                                            "message": "Published service - verify intended"
                                        }
                                        findings.append(finding)

                                    else:
                                        finding = {
                                            "rule_index": rule_index,
                                            "finding_id": "PF-WAN-003",
                                            "severity": "HIGH",
                                            "score": 4,
                                            "action": rule_type_name,
                                            "message": "Admin service exposed on WAN"
                                        }
                                        findings.append(finding)

        rule_index += 1
    return findings

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config')
    args = parser.parse_args()

    try:
        findings = audit(args.config)
        print(findings)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)



