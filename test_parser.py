from parse_pfsense import audit

def test_total_findings_count():
    result = audit('sample_config.xml')
    assert len(result) == 13


def test_high_severity_finding_count():
    result = audit("sample_config.xml")
    high_findings = [f for f in result if f["severity"] == "HIGH"]
    assert len(high_findings) == 2
