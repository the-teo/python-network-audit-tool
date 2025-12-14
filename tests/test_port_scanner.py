import socket
import threading
import time
import pytest

from scanner.port_scanner import check_port, scan_ports


class SimpleTCPServer(threading.Thread):
    def __init__(self, host='127.0.0.1'):
        super().__init__(daemon=True)
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass


@pytest.fixture
def tcp_server():
    server = SimpleTCPServer()
    server.start()
    # give the thread a moment
    time.sleep(0.05)
    yield server
    server.stop()
    time.sleep(0.05)


def test_check_port_open_and_closed(tcp_server):
    # open port should be detected
    assert check_port('127.0.0.1', tcp_server.port, timeout=1.0) is True

    # find a free port that is closed
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    closed_port = s.getsockname()[1]
    s.close()
    assert check_port('127.0.0.1', closed_port, timeout=0.2) is False


def test_scan_ports_detects_open(tcp_server):
    results = scan_ports('127.0.0.1', [tcp_server.port, 65530], timeout=0.5)
    assert tcp_server.port in results
