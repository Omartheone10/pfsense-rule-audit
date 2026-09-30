import xml.etree.ElementTree as ET
tree = ET.parse('sample_config.xml')
root = tree.getroot()

findings = []
# Find all the 'rule' one by one
rule_index = 1
for rule in root.findall('.//rule'):

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
                    print(finding)
                print( interface_name , rule_type_name )
    rule_index += 1


print(findings)


