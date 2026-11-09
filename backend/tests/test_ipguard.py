import pytest

from app.targets.ipguard import classify, is_forbidden

HARD = ["127.0.0.1", "::1", "0.0.0.0", "::", "169.254.169.254", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1",
        "240.0.0.1", "255.255.255.255", "fd00:ec2::254", "100.100.100.200", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        "::ffff:169.254.169.254", "2002:7f00:1::", "2002:0a00:0001::", "64:ff9b::7f00:1", "64:ff9b::a00:1"]
PRIVATE = ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12:3456::1",
           "198.18.0.1"]
PUBLIC = ["93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:93.184.216.34",
          "2002:5db8:d822::1"]


@pytest.mark.parametrize("ip", HARD)
def test_hard_forbidden_never_overridable(ip):
    assert classify(ip)[0] == "hard"
    assert is_forbidden(ip, allow_private=True)


@pytest.mark.parametrize("ip", PRIVATE)
def test_private_only_with_override(ip):
    assert classify(ip)[0] == "private"
    assert is_forbidden(ip) and is_forbidden(ip, allow_private=True) is None


@pytest.mark.parametrize("ip", PUBLIC)
def test_public_allowed(ip):
    assert is_forbidden(ip) is None
