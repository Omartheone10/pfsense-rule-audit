import xml.etree.ElementTree as ET
tree = ET.parse('sample_config.xml')
root = tree.getroot()

findings = []

# going through each rule one by one
for rule in root.findall('.//rule'):
    interface = rule.find('interface')
    if interface is not None:
        interface_name = interface.text
        if interface_name == 'wan':
            source_any = rule.find('source/any')
            destination_any = rule.find('destination/any')
            rule_type = rule.find('type')
            if rule_type is not None:
                rule_type_name = rule_type.text
            if rule_type_name == 'pass' and source_any is not None and destination_any is not None :
                    finding = {
                            'Severity' : 'CRITICAL',
                            'Action'   : rule_type_name,
                            'vulnerability' : 'any/any'
                            }
                    print(finding)
                    findings.append(finding)
                
    print(interface_name, rule_type_name)
    
print(findings)