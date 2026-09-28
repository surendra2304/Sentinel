"""Production API image exposes the React dashboard alongside the JSON API."""

import re

from fastapi.testclient import TestClient

from sentinel.apps.api.main import SENTINEL_DASHBOARD_INDEX, app


def test_browser_root_opens_bundled_dashboard_and_keeps_api_root_json():
    assert SENTINEL_DASHBOARD_INDEX.is_file(), "Build apps/dashboard before serving the API image"
    client = TestClient(app)

    browser_root = client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert browser_root.status_code == 307
    assert browser_root.headers["location"] == "/dashboard/"

    dashboard = client.get("/dashboard/", headers={"accept": "text/html"})
    assert dashboard.status_code == 200
    assert "Sentinel — Security Control Room" in dashboard.text
    asset = re.search(r'src="(/assets/[^\"]+\.js)"', dashboard.text)
    assert asset, "The built dashboard script should be referenced by its static HTML"
    asset_response = client.get(asset.group(1))
    assert asset_response.status_code == 200
    assert "createRoot" in asset_response.text

    api_root = client.get("/", headers={"accept": "application/json"})
    assert api_root.status_code == 200
    assert api_root.json()["service"] == "SENTINEL"
    assert client.get("/health").status_code == 200
