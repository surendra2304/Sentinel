"""Unit tests for Continuous TLS Certificate Expiration & DNS Drift Daemon."""

import asyncio
import socket
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import SeverityLevel
from sentinel.monitoring.continuous import ContinuousMonitor
from sentinel.monitoring.tls_dns_daemon import (
    DNSDriftMonitor,
    TLSCertificateChecker,
    TLSDNSMonitoringDaemon,
)


def _create_mock_writer(mock_ssl_sock):
    writer = MagicMock()
    writer.get_extra_info.return_value = mock_ssl_sock
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return writer


@pytest.mark.asyncio
async def test_tls_certificate_checker_healthy():
    checker = TLSCertificateChecker(timeout=2.0)
    now = datetime.now(UTC)
    expiry = now + timedelta(days=90)
    not_after_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = (now - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_peercert = {
        "notAfter": not_after_str,
        "notBefore": not_before_str,
        "subjectAltName": (("DNS", "friday-universe.duckdns.org"), ("DNS", "sentinel.local")),
    }

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = mock_peercert
    mock_writer = _create_mock_writer(mock_ssl_sock)

    with patch("asyncio.open_connection", AsyncMock(return_value=(AsyncMock(), mock_writer))):
        result = await checker.check_certificate("friday-universe.duckdns.org")
        assert result.status == "HEALTHY"
        assert result.severity == SeverityLevel.LOW
        assert result.days_remaining in (89, 90)
        assert not result.is_expired
        assert "sentinel.local" in result.san_list


@pytest.mark.asyncio
async def test_tls_certificate_checker_expiring_imminent_and_expired():
    checker = TLSCertificateChecker(timeout=2.0)
    now = datetime.now(UTC)

    # 1. Expiring in 4 days -> CRITICAL / EXPIRING_IMMINENT
    exp_4d = (now + timedelta(days=4)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_peercert = {"notAfter": exp_4d, "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT")}
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = mock_peercert
    mock_writer = _create_mock_writer(mock_ssl_sock)

    with patch("asyncio.open_connection", AsyncMock(return_value=(AsyncMock(), mock_writer))):
        res_4d = await checker.check_certificate("friday-universe.duckdns.org")
        assert res_4d.status == "EXPIRING_IMMINENT"
        assert res_4d.severity == SeverityLevel.CRITICAL

    # 2. Expired 2 days ago -> CRITICAL / EXPIRED
    exp_past = (now - timedelta(days=2)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_peercert_past = {"notAfter": exp_past, "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT")}
    mock_ssl_sock_past = MagicMock()
    mock_ssl_sock_past.getpeercert.return_value = mock_peercert_past
    mock_writer_past = _create_mock_writer(mock_ssl_sock_past)

    with patch("asyncio.open_connection", AsyncMock(return_value=(AsyncMock(), mock_writer_past))):
        res_past = await checker.check_certificate("friday-universe.duckdns.org")
        assert res_past.status == "EXPIRED"
        assert res_past.severity == SeverityLevel.CRITICAL
        assert res_past.is_expired is True


@pytest.mark.asyncio
async def test_tls_certificate_checker_connection_error():
    checker = TLSCertificateChecker(timeout=2.0)
    with patch("asyncio.open_connection", AsyncMock(side_effect=OSError("Connection refused"))):
        res_err = await checker.check_certificate("unreachable.host")
        assert res_err.status == "ERROR"
        assert res_err.severity == SeverityLevel.HIGH
        assert "Connection refused" in (res_err.error_message or "")


@pytest.mark.asyncio
async def test_dns_drift_monitor_query_and_evaluation():
    dns_mon = DNSDriftMonitor(timeout=2.0)

    # Mock getaddrinfo for A and AAAA
    async def mock_getaddrinfo(host, port, family=0):
        if family == socket.AF_INET:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 0))]
        return []

    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", side_effect=mock_getaddrinfo):
        records = await dns_mon.query_records("friday-universe.duckdns.org")
        assert records["A"] == ["192.168.1.100"]
        assert records["AAAA"] == []

    # Evaluation: No drift
    baseline_match = {"A": ["192.168.1.100"]}
    no_drift = dns_mon.evaluate_drift("friday-universe.duckdns.org", records, baseline_match)
    assert not no_drift.drift_detected
    assert no_drift.severity == SeverityLevel.LOW

    # Evaluation: Drift detected on A record
    baseline_drift = {"A": ["10.0.0.1"]}
    drift_res = dns_mon.evaluate_drift("friday-universe.duckdns.org", records, baseline_drift)
    assert drift_res.drift_detected is True
    assert drift_res.severity == SeverityLevel.HIGH
    assert any("A record drifted" in d for d in drift_res.drift_details)


@pytest.mark.asyncio
async def test_tls_dns_daemon_check_cycle():
    custom_monitor = ContinuousMonitor()
    cert_checker = TLSCertificateChecker()
    dns_monitor = DNSDriftMonitor()

    daemon = TLSDNSMonitoringDaemon(
        monitored_domains=["friday-universe.duckdns.org"],
        interval_seconds=60.0,
        monitor=custom_monitor,
        cert_checker=cert_checker,
        dns_monitor=dns_monitor,
    )

    daemon.add_target("api.friday-universe.duckdns.org")
    assert "api.friday-universe.duckdns.org" in daemon.monitored_domains

    # Pre-register baseline for domain to detect drift
    custom_monitor.register_asset_from_scan(
        "friday-universe.duckdns.org",
        {"dns_records": {"A": ["1.2.3.4"]}},
    )

    # Mock cert returning 5 days remaining (CRITICAL)
    now = datetime.now(UTC)
    expiry = now + timedelta(days=5)
    not_after_str = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    mock_peercert = {"notAfter": not_after_str, "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT")}
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = mock_peercert
    mock_writer = _create_mock_writer(mock_ssl_sock)

    # Mock DNS returning different IP [5.6.7.8] (causing A drift)
    async def mock_getaddrinfo(host, port, family=0):
        if family == socket.AF_INET:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 0))]
        return []

    loop = asyncio.get_running_loop()
    with (
        patch("asyncio.open_connection", AsyncMock(return_value=(AsyncMock(), mock_writer))),
        patch.object(loop, "getaddrinfo", side_effect=mock_getaddrinfo),
    ):
        summary = await daemon.run_check_cycle()
        assert summary["alerts_generated"] >= 1
        assert "friday-universe.duckdns.org" in summary["targets"]

        # Alerts should be stored in monitor
        assert len(custom_monitor.alerts) >= 1
        types = {a.drift_type for a in custom_monitor.alerts}
        assert "tls_certificate_expiration" in types or "dns_record_drift" in types


@pytest.mark.asyncio
async def test_tls_dns_daemon_start_and_stop():
    daemon = TLSDNSMonitoringDaemon(interval_seconds=10.0)
    with patch.object(daemon, "run_check_cycle", AsyncMock(return_value={"alerts_generated": 0})):
        task = daemon.start()
        assert daemon.is_running is True
        await asyncio.sleep(0.05)
        await daemon.stop()
        assert daemon.is_running is False
        assert task.done()
