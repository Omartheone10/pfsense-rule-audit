from parse_pfsense import audit

def test_total_findings_count():
    result = audit('sample_config.xml')
    assert len(result) == 13
    