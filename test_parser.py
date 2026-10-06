from parse_pfsense import audit

def test_total_findings_count():
    result = audit('sample_config.xml')
    assert len(result) == 13


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
    assert len(low_findings) == 2

def test_nat_fixture_xml():
    result = audit("test_nat_fixture.xml")
    assert len(result) == 1
    