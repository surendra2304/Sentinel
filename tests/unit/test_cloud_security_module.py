import json

import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.cloud.adapters import (
    AWSCloudAdapter,
    AzureCloudAdapter,
    CloudProviderAdapter,
    GCPCloudAdapter,
    redact_credentials,
)


def test_cloud_adapters_are_strictly_read_only():
    """Verify that CloudProviderAdapter interface and implementations contain NO mutation/write methods."""
    prohibited_prefixes = ["create", "update", "delete", "write", "modify", "put", "patch", "remove", "destroy"]

    for adapter_cls in [CloudProviderAdapter, AWSCloudAdapter, AzureCloudAdapter, GCPCloudAdapter]:
        methods = [m for m in dir(adapter_cls) if not m.startswith("_")]
        for m in methods:
            for bad in prohibited_prefixes:
                assert not m.startswith(bad), f"Prohibited write/mutation method '{m}' found on read-only adapter {adapter_cls.__name__}!"


def test_credential_redaction_scrubber():
    """Verify sensitive AWS/Azure/GCP credentials and keys are recursively sanitized."""
    sensitive_payload = {
        "account_id": "123456789012",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "access_token": "eyJhbGciOi...",
        "auth_header": "Bearer secrettoken123",
        "nested": {
            "api_key": "secret-12345",
            "arn": "arn:aws:iam::123456789012:user/AKIAIOSFODNN7EXAMPLE",
        },
    }

    clean = redact_credentials(sensitive_payload)

    assert clean["aws_secret_access_key"] == "[REDACTED_CREDENTIAL]"
    assert clean["access_token"] == "[REDACTED_CREDENTIAL]"
    assert clean["auth_header"] == "[REDACTED_CREDENTIAL]"
    assert clean["nested"]["api_key"] == "[REDACTED_CREDENTIAL]"
    assert "[REDACTED_AWS_KEY]" in clean["nested"]["arn"]


@pytest.mark.asyncio
async def test_aws_cloud_adapter_posture_assessment():
    aws_adp = AWSCloudAdapter()
    req = ActionRequest(
        id="act-aws-posture",
        task_id="task-cloud-test",
        agent="cloud_agent",
        action_type="cloud.aws_posture_assess",
        target_refs=["arn:aws:iam::123456789012:root"],
        parameters={
            "credentials": {
                "account_id": "123456789012",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "SecretPassword123!",
                "inventory": {
                    "s3_buckets": [
                        {
                            "name": "public-open-s3-bucket",
                            "arn": "arn:aws:s3:::public-open-s3-bucket",
                            "block_public_access": False,
                            "is_public": True,
                        }
                    ],
                    "iam_policies": [
                        {
                            "name": "StarAdminPolicy",
                            "arn": "arn:aws:iam::123456789012:policy/StarAdminPolicy",
                            "has_star_wildcard": True,
                        }
                    ],
                    "cloudtrail": {"multi_region_enabled": False},
                },
            }
        },
    )

    res, raw_bytes, _ = await aws_adp.run(req)
    assert res.success is True
    data = json.loads(raw_bytes.decode("utf-8"))

    # Assert findings were produced
    assert data["findings_count"] >= 3
    assert any("S3 Bucket" in f["title"] for f in data["findings"])
    assert any("IAM Policy" in f["title"] for f in data["findings"])
    assert any("CloudTrail" in f["title"] for f in data["findings"])

    # Assert credentials did NOT leak into evidence
    assert "SecretPassword123!" not in raw_bytes.decode("utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_bytes.decode("utf-8")


@pytest.mark.asyncio
async def test_azure_and_gcp_cloud_adapter_posture_assessment():
    # 1. Azure Cloud Adapter Run
    azure_adp = AzureCloudAdapter()
    req_az = ActionRequest(
        id="act-az-01",
        task_id="task-az-01",
        agent="cloud_agent",
        action_type="cloud.azure_posture_assess",
        target_refs=["/subscriptions/sub-001"],
        parameters={
            "credentials": {
                "subscription_id": "sub-1234-5678",
                "client_secret": "SuperSecretKey!",
            }
        }
    )
    res_az, raw_az, _ = await azure_adp.run(req_az)
    assert res_az.success is True
    data_az = json.loads(raw_az.decode("utf-8"))
    assert data_az["findings_count"] >= 1
    assert data_az["findings"][0]["rule_id"] == "AZ-BLOB-001"
    assert "SuperSecretKey!" not in raw_az.decode("utf-8")

    # 2. GCP Cloud Adapter Run
    gcp_adp = GCPCloudAdapter()
    req_gcp = ActionRequest(
        id="act-gcp-01",
        task_id="task-gcp-01",
        agent="cloud_agent",
        action_type="cloud.gcp_posture_assess",
        target_refs=["projects/sentinel-sec-test"],
        parameters={
            "credentials": {
                "project_id": "sentinel-sec-test",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
            }
        }
    )
    res_gcp, raw_gcp, _ = await gcp_adp.run(req_gcp)
    assert res_gcp.success is True
    data_gcp = json.loads(raw_gcp.decode("utf-8"))
    assert data_gcp["findings_count"] >= 1
    assert data_gcp["findings"][0]["rule_id"] == "GCP-GCS-001"
    assert "-----BEGIN RSA PRIVATE KEY-----" not in raw_gcp.decode("utf-8")