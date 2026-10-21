import pytest
from parse_pfsense import audit

def test_total_findings_count():
    result = audit('sample_config.xml')
    assert len(result) == 16

def test_high_severity_finding_count():
    result = audit("sample_config.xml")
    high_findings = [f for f in result if f["severity"] == "HIGH"]
    assert len(high_findings) == 1

def test_critical_findings_count():
    result = audit("sample_config.xml")
    critical_findings = [ f for f in result if f["severity"] == "CRITICAL"]
    
    # Extract the rule number and finding ID into a list of tuples
    finding_pairs = [(f["rule_index"], f["finding_id"]) for f in critical_findings]

    # Assert the exact matches exist
    assert (5, "PF-WAN-001") in finding_pairs
    assert (7, "PF-WAN-001") in finding_pairs

    # Keep the count check to be safe
    assert len(critical_findings) == 2

def test_medium_findings_count():
    result = audit("sample_config.xml")
    medium_findings = [f for f in result if f["severity"] == "MEDIUM"]
    assert len(medium_findings) == 8

def test_low_findings_count():
    result = audit("sample_config.xml")
    low_findings = [f for f in result if f["severity"] == "LOW"]
    assert len(low_findings) == 5

def test_nat_fixture_xml():
    result = audit("test_nat_fixture.xml")
    assert len(result) == 1

@pytest.fixture
def shadow_xml(tmp_path):
    file_name = tmp_path / "shadow_test.xml"

    file_name.write_text("""<pfsense>
        <filter>
        <rule>
          <interface>wan</interface>
          <type>pass</type>
          <source><any/></source>
          <destination><any/></destination>
        </rule>
        <rule>
          <interface>wan</interface>
          <type>pass</type>
          <source><address>192.168.1.50</address></source>
          <destination><any/></destination>
        </rule>
      </filter>
    </pfsense>""")

    return str(file_name)

def test_shadow_detection(shadow_xml):
    result = audit(shadow_xml)
    shadow_findings = [f for f in result if "shadow" in f["message"].lower()]
    assert len(shadow_findings) == 1

