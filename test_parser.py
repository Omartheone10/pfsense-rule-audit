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
def shadow_xml():
    file_name = "shadow_test.xml"
    with open(file_name, "w") as f:
        f.write("""<pfsense>
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

    return file_name


def test_shadow_detection(shadow_xml):
    result = audit(shadow_xml)
    shadow_findings = [f for f in result if "shadow" in f["message"].lower()]
    assert len(shadow_findings) == 1

