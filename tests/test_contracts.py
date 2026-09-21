"""Contract tests: the two frozen schemas validate and round-trip."""
from vibetest.schemas.artifacts import Artifact
from vibetest.schemas.findings import Evidence, Finding, Severity


def test_artifact_roundtrip(mock_artifact):
    blob = mock_artifact.model_dump_json()
    again = Artifact.model_validate_json(blob)
    assert again.target_url == mock_artifact.target_url
    assert again.pages[0].status_code == 200


def test_finding_validation_and_roundtrip():
    f = Finding(
        detector_id="headers",
        category="missing-security-header",
        severity=Severity.MEDIUM,
        title="Missing security header: content-security-policy",
        evidence=[Evidence(url="http://localhost:8000/", detail="response missing `content-security-policy`")],
        remediation_hint="Add a CSP header.",
    )
    assert f.confidence == 1.0
    assert f.explanation is None
    again = Finding.model_validate_json(f.model_dump_json())
    assert again.title == f.title
    assert again.severity is Severity.MEDIUM
