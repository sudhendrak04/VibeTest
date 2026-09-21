import pytest

from vibetest.schemas.artifacts import Artifact, PageSnapshot


@pytest.fixture
def mock_artifact() -> Artifact:
    """A realistic fake Artifact (page missing all security headers).

    Builder B builds detectors against this from day 1 — no crawler needed.
    """
    return Artifact(
        target_url="http://localhost:8000/",
        pages=[
            PageSnapshot(
                url="http://localhost:8000/",
                status_code=200,
                headers={"content-type": "text/html; charset=utf-8"},
                html="<html><head><title>demo</title></head><body>hello</body></html>",
            )
        ],
    )
