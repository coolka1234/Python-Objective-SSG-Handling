import ipaddress
import pytest
from SSHLogEntry import SSHLogEntry

def test_time_extraction():
    log_entry = SSHLogEntry("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2")
    assert log_entry.time == "06:55:48"

@pytest.mark.parametrize("log, expected", [
    ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2", ["173.234.31.186"]),
    ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 666.777.88.213 port 38926 ssh2", None),
    ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from port 38926 ssh2", None)
])
def test_ipv4_extraction(log, expected):
    log_entry = SSHLogEntry(log)
    if expected is not None:
        expected = [ipaddress.ip_address(ip) for ip in expected]
    assert log_entry.get_ipv4s() == expected