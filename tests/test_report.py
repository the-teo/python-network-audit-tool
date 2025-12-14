import json

from scanner.report import generate_text_report, generate_json_report


def test_generate_text_report():
    target = 'example.com'
    open_ports = [22, 80]
    services = {
        22: {'service': 'SSH', 'banner': 'SSH-2.0-OpenSSH_7.4'},
        80: {'service': 'HTTP', 'banner': None},
    }
    txt = generate_text_report(target, open_ports, services)
    assert 'Scan report for example.com' in txt
    assert '22/tcp: SSH' in txt


def test_generate_json_report():
    target = '127.0.0.1'
    open_ports = [8080]
    services = {8080: {'service': 'HTTP-alt', 'banner': 'GET /'}}
    js = generate_json_report(target, open_ports, services)
    obj = json.loads(js)
    assert obj['target'] == target
    assert '8080' in obj['services']
