"""Unit tests for the secret detection agent."""
import pytest
from app.services.analysis.agents.secret_detector import SecretDetectorAgent


@pytest.fixture
def agent():
    return SecretDetectorAgent()


def test_detects_aws_key(agent, tmp_path):
    js_file = tmp_path / "app.js"
    fake_aws_key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    js_file.write_text(f'const key = "{fake_aws_key}"; fetch("/api");', encoding="utf-8")

    resource = {"url": "https://example.com/app.js", "resource_type": "js", "file_path": str(js_file)}
    findings = agent._regex_scan(js_file.read_text(), resource["url"])

    assert len(findings) >= 1
    assert any("AWS" in f.title for f in findings)
    assert findings[0].severity == "critical"
    assert findings[0].cwe_id == 798


def test_detects_jwt(agent, tmp_path):
    js_file = tmp_path / "app.js"
    js_file.write_text(
        'const token = "'
        + (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            + "."
            + "eyJzdWIiOiIxMjM0In0"
            + "."
            + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        + '";',
        encoding="utf-8"
    )
    findings = agent._regex_scan(js_file.read_text(), "https://example.com/app.js")
    assert any(f.vulnerability_type.value == "jwt_weakness" for f in findings)


def test_skips_placeholder(agent, tmp_path):
    js_file = tmp_path / "app.js"
    js_file.write_text('const key = "your_api_key_here"; const key2 = "CHANGEME";', encoding="utf-8")
    findings = agent._regex_scan(js_file.read_text(), "https://example.com/app.js")
    assert len(findings) == 0


def test_detects_google_api_key(agent, tmp_path):
    js_file = tmp_path / "maps.js"
    fake_google_key = "AI" + "za" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
    js_file.write_text(f'initMap("{fake_google_key}")', encoding="utf-8")
    findings = agent._regex_scan(js_file.read_text(), "https://example.com/maps.js")
    assert len(findings) >= 1
    assert any("Google" in f.title for f in findings)
