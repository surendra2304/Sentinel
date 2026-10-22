"""Production API image exposes the React dashboard alongside the JSON API."""

import re

from fastapi.testclient import TestClient

from sentinel.apps.api.main import SENTINEL_DASHBOARD_INDEX, app


def test_browser_root_opens_bundled_dashboard_and_keeps_api_root_json():
    client = TestClient(app)

    browser_root = client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    dashboard = client.get("/dashboard/", headers={"accept": "text/html"})
    if SENTINEL_DASHBOARD_INDEX.is_file():
        assert browser_root.status_code == 307
        assert browser_root.headers["location"] == "/dashboard/"
        assert dashboard.status_code == 200
        assert "Sentinel — Security Control Room" in dashboard.text
        asset = re.search(r'src="(/assets/[^\"]+\.js)"', dashboard.text)
        assert asset, "The built dashboard script should be referenced by its static HTML"
        asset_response = client.get(asset.group(1))
        assert asset_response.status_code == 200
        assert "createRoot" in asset_response.text
    else:
        # Python-only CI jobs do not build the frontend; production Docker does.
        assert browser_root.status_code == 503
        assert dashboard.status_code == 503
        assert "dashboard is not installed" in dashboard.text

    api_root = client.get("/", headers={"accept": "application/json"})
    assert api_root.status_code == 200
    assert api_root.json()["service"] == "SENTINEL"
    assert client.get("/health").status_code == 200
