import xml.etree.ElementTree as ET


def audit(config_path):
    tree = ET.parse(config_path)
    root = tree.getroot()
    findings = []
    # Find all the 'rule' one by one
    rule_index = 1
    for rule in root.findall('./filter/rule'):

        rule_type = rule.find('type')
        if rule_type is not None:
            rule_type_name = rule_type.text
            rule_log = rule.find('log')
            if rule_log is None and rule_type_name == 'block':
                finding = {
                    "rule_index": rule_index,
                    "severity": "MEDIUM",
                    "score": 3,
                    "message": 'Rule missing log'
                }
                findings.append(finding)

        # Finding if a rule is already disabled
        disabled_rule = rule.find('disabled')
        if disabled_rule is not None:
            finding = {
                "rule_index": rule_index,
                "severity": 'LOW',
                "score": 2,
                "message": "Rule is disabled - consider cleanup"
            }
            findings.append(finding)

        # Finding if a rule missing the description tag
        descr = rule.find('descr')
        if descr is None:
            finding = {
                "rule_index": rule_index,
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
                # Find source tag's child element any
                source_any = rule.find('source/any')

                # Find destination tag's child element any
                dest_any = rule.find('destination/any')
                rule_type = rule.find('type')
                if rule_type is not None:
                    rule_type_name = rule_type.text
                    # Flag true any-any rules (source any + dest any + action pass)
                    if source_any is not None and rule_type_name == 'pass' and dest_any is not None:
                        # Creating a dictionary
                        finding = {
                            "rule_index": rule_index,
                            "severity": "CRITICAL",
                            "score": 5,
                            "action": rule_type_name,
                            "message": "True Any-Any rule on WAN"
                        }
                        findings.append(finding)

                    port = rule.find('destination/port')
                    if port is not None:
                        port_number = port.text
                        if (
                                port_number == "22" or port_number == "80" or port_number == "443") and rule_type_name == "pass":
                            finding = {
                                "rule_index": rule_index,
                                "severity": "HIGH",
                                "score": 4,
                                "message": "Admin service exposed on WAN"
                            }
                            findings.append(finding)

        rule_index += 1
    return findings


if __name__ == '__main__':
    findings = audit("sample_config.xml")
    print(findings)

    



