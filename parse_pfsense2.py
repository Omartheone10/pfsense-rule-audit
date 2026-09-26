import xml.etree.ElementTree as ET
tree = ET.parse('sample_config.xml')
root =tree.getroot()

for rule in root.findall('.//rule'):
    interface = rule.find('interface')
    if interface is not None:
        interface_name = interface.text
        if interface_name == 'wan':
            source_any = rule.find('source/any')
            if source_any is not None:
                print('CRITICAL: WAN rule allows ANY source')
            rule_type = rule.find('type')
            if rule_type is not None:
                rule_type_name = rule_type.text
                print( interface_name , rule_type_name )




