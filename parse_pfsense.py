import xml.etree.ElementTree as ET

tree = ET.parse("sample_config.xml")
root = tree.getroot()

alias_map = {}
for alias in root.findall(".//alias"):
    name = alias.findtext("name", default="?")
    addrs = alias.findtext("address", default="?")
    alias_map[name] = addrs


for rule in root.findall(".//rule"):
    iface = rule.findtext("interface", default="?")
    action = rule.findtext("type", default="?")
    source_tag = rule.find("source")
    if source_tag.find("any") is not None:
        source = "ANY"
    else:
        source = source_tag.findtext("address", default="?")


    dest_tag = rule.find("destination")
    if dest_tag.find("any") is not None:
        dest_addr = "ANY"
        dest_port = "ANY"
    else:
        dest_addr = dest_tag.findtext("address", default="?")
        dest_port = dest_tag.findtext("port", default="?")

    if dest_addr in alias_map:
        dest_addr = alias_map[dest_addr]

    # --- AUDIT CHECK ---
    if action == "pass" and iface == "wan" and source == "ANY" and dest_addr == "ANY":
        print("CRITICAL FINDING: any-any pass on WAN!")

    print(action, source, dest_addr, dest_port)