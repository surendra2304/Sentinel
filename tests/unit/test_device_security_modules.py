import json
import zipfile

import pytest

from sentinel.core.models import (
    ActionRequest,
)
from sentinel.modules.endpoint.adapters import EndpointAssessmentAdapter
from sentinel.modules.mobile.adapters import (
    AndroidAPKStaticAnalysisAdapter,
    iOSIPAStaticAnalysisAdapter,
)
from sentinel.modules.wireless.adapters import (
    WirelessConfigAssessmentAdapter,
)

# ---------------------------------------------------------------------------
# 1. Test Fixtures: APK Manifest Zip & IPA Info.plist
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_apk_file(tmp_path):
    apk_file = tmp_path / "test_vulnerable_app.apk"
    manifest_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.sentinel.testapp">
        <uses-permission android:name="android.permission.READ_SMS" />
        <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
        <application
            android:debuggable="true"
            android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" />
        </application>
    </manifest>
    """
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
    return str(apk_file)


# ---------------------------------------------------------------------------
# 2. Device Security Adapters Unit Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wireless_config_and_inventory():
    # 1. Wireless AP Config Assessment
    adp_wifi = WirelessConfigAssessmentAdapter()
    req_wifi = ActionRequest(
        id="act-wifi",
        task_id="task-wifi-test",
        agent="wireless_agent",
        action_type="wireless.config_audit",
        target_refs=["ap-router-01"],
        parameters={
            "config_data": {
                "ssid": "Corp-Insecure-AP",
                "security_mode": "OPEN",
                "wps_enabled": True,
                "management_on_wireless": True,
            }
        },
    )
    res_wifi, raw_wifi, _ = await adp_wifi.run(req_wifi)
    assert res_wifi.success is True
    data_wifi = json.loads(raw_wifi.decode("utf-8"))
    assert len(data_wifi["findings"]) >= 3
    assert any("Insecure Wireless Encryption" in f["title"] for f in data_wifi["findings"])
    assert any("WPS Enabled" in f["title"] for f in data_wifi["findings"])


@pytest.mark.asyncio
async def test_mobile_apk_and_ipa_static_analysis(mock_apk_file):
    # 1. Android APK Static Analysis
    adp_apk = AndroidAPKStaticAnalysisAdapter()
    req_apk = ActionRequest(
        id="act-apk",
        task_id="task-mobile-test",
        agent="mobile_agent",
        action_type="mobile.apk_analyze",
        target_refs=["test_app.apk"],
        parameters={"apk_path": mock_apk_file},
    )
    res_apk, raw_apk, _ = await adp_apk.run(req_apk)
    assert res_apk.success is True
    data_apk = json.loads(raw_apk.decode("utf-8"))
    assert data_apk["is_debuggable"] is True
    assert data_apk["uses_cleartext_traffic"] is True
    assert any("READ_SMS" in f["title"] for f in data_apk["findings"])

    # 2. iOS IPA Info.plist Static Review
    adp_ipa = iOSIPAStaticAnalysisAdapter()
    req_ipa = ActionRequest(
        id="act-ipa",
        task_id="task-mobile-test",
        agent="mobile_agent",
        action_type="mobile.ipa_analyze",
        target_refs=["test_ios_app.ipa"],
        parameters={
            "plist_data": {
                "CFBundleIdentifier": "com.sentinel.iosapp",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            }
        },
    )
    res_ipa, raw_ipa, _ = await adp_ipa.run(req_ipa)
    assert res_ipa.success is True
    data_ipa = json.loads(raw_ipa.decode("utf-8"))
    assert any("NSAllowsArbitraryLoads" in f["title"] for f in data_ipa["findings"])


@pytest.mark.asyncio
async def test_endpoint_assessment_adapter():
    adp_ep = EndpointAssessmentAdapter()
    req_ep = ActionRequest(
        id="act-ep",
        task_id="task-ep-test",
        agent="endpoint_agent",
        action_type="endpoint.posture_assess",
        target_refs=["localhost"],
    )
    res_ep, raw_ep, _ = await adp_ep.run(req_ep)
    assert res_ep.success is True
    data_ep = json.loads(raw_ep.decode("utf-8"))
    assert data_ep["process_count"] > 0
    assert len(data_ep["os"]) > 0
