import xml.etree.ElementTree as ET
etree = ET.parse('sample_config.xml')
root =etree.getroot()

for rule in root.findall('.//rule'):
    i_face = rule.find('interface')
    if i_face is not None:
        i_faceText = i_face.text
        if i_faceText == 'wan':
            i_type = rule.find('type')
            if i_type is not None:
                i_typeText = i_type.text
                print( i_faceText , i_typeText )




