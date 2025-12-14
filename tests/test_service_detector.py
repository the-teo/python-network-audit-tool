from scanner.service_detector import detect_services


def test_detect_services_empty():
    res = detect_services('127.0.0.1', [])
    assert res == {}


def test_detect_services_known_port():
    # Even if the port isn't open locally, the service name mapping should appear
    res = detect_services('127.0.0.1', [80])
    assert 80 in res
    assert res[80]['service'] == 'HTTP'
