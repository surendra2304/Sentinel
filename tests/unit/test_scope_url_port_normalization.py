import pytest

from sentinel.core.scope.resolver import ScopeResolver, TargetResolutionError


def test_http_default_port_is_removed():
    target = ScopeResolver.normalize_target("http://example.test:80/health")
    assert target.value == "http://example.test/health"


def test_https_default_port_is_removed():
    target = ScopeResolver.normalize_target("https://example.test:443/health")
    assert target.value == "https://example.test/health"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.test:443/health", "http://example.test:443/health"),
        ("https://example.test:80/health", "https://example.test:80/health"),
        ("https://example.test:8443/health", "https://example.test:8443/health"),
    ],
)
def test_non_default_ports_are_preserved(url, expected):
    assert ScopeResolver.normalize_target(url).value == expected


def test_port_zero_is_rejected():
    with pytest.raises(TargetResolutionError):
        ScopeResolver.normalize_target("http://example.test:0/health")
