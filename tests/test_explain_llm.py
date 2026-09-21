"""LLM explanation layer tests with a fake Ollama HTTP client (no network)."""
import httpx

from vibetest.config import Settings
from vibetest.reporting.explain import apply_explanations
from vibetest.schemas.findings import Finding, Severity

BASE_FINDING = dict(
    detector_id="headers",
    category="missing-security-header",
    cwe_id="CWE-693",
    owasp_2025="A02:2025",
    severity=Severity.MEDIUM,
    title="Missing security header: content-security-policy",
    remediation_hint="Add a CSP header.",
)

LLM_TEXT = "The model says: fix the header."


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "error",
                request=httpx.Request("GET", "http://test"),
                response=httpx.Response(self.status_code),
            )

    def json(self) -> dict:
        return self._payload


class FakeOllama:
    """Duck-typed stand-in for httpx.Client pointed at Ollama."""

    def __init__(
        self,
        models: tuple[str, ...] = ("qwen3:8b",),
        content: str = '{"explanation": "' + LLM_TEXT + '"}',
        fail_get: bool = False,
        fail_post: bool = False,
    ):
        self.models = list(models)
        self.content = content
        self.fail_get = fail_get
        self.fail_post = fail_post
        self.posts: list[dict] = []

    def get(self, url: str) -> FakeResponse:
        if self.fail_get:
            raise httpx.ConnectError("connection refused")
        return FakeResponse(200, {"models": [{"name": m} for m in self.models]})

    def post(self, url: str, json: dict | None = None) -> FakeResponse:
        if self.fail_post:
            raise httpx.ConnectError("connection refused")
        self.posts.append(json or {})
        return FakeResponse(200, {"message": {"role": "assistant", "content": self.content}})

    def close(self) -> None:  # pragma: no cover — injected clients are not closed
        pass


def _finding() -> Finding:
    return Finding(**BASE_FINDING)


def _settings(tmp_path) -> Settings:
    return Settings(llm_cache_path=str(tmp_path / "cache.json"))


def test_ollama_mode_uses_model_output(tmp_path):
    f = _finding()
    client = FakeOllama()
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert f.explanation == LLM_TEXT
    assert len(client.posts) == 1
    assert client.posts[0]["model"] == "qwen3:8b"
    assert client.posts[0]["options"]["temperature"] == 0
    assert client.posts[0]["format"]["required"] == ["explanation"]


def test_ollama_unavailable_falls_back_to_template(tmp_path):
    f = _finding()
    client = FakeOllama(fail_get=True)
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert "What this means" in f.explanation
    assert client.posts == []


def test_model_not_installed_falls_back_to_template(tmp_path):
    f = _finding()
    client = FakeOllama(models=("some-other-model:7b",))
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert "What this means" in f.explanation
    assert client.posts == []


def test_fallback_model_used_when_primary_missing(tmp_path):
    f = _finding()
    client = FakeOllama(models=("phi4-mini",))
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert f.explanation == LLM_TEXT
    assert client.posts[0]["model"] == "phi4-mini"


def test_cache_satisfies_findings_when_ollama_is_down(tmp_path):
    settings = _settings(tmp_path)
    apply_explanations([_finding()], mode="ollama", settings=settings, client=FakeOllama())
    # Second run: Ollama is now DOWN, but the per-finding cache must still work.
    f2 = _finding()
    offline = FakeOllama(fail_get=True)
    apply_explanations([f2], mode="ollama", settings=settings, client=offline)
    assert f2.explanation == LLM_TEXT
    assert offline.posts == []


def test_invalid_model_output_falls_back_to_template(tmp_path):
    f = _finding()
    client = FakeOllama(content="this is not json")
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert "What this means" in f.explanation


def test_post_failure_falls_back_to_template(tmp_path):
    f = _finding()
    client = FakeOllama(fail_post=True)
    apply_explanations([f], mode="ollama", settings=_settings(tmp_path), client=client)
    assert "What this means" in f.explanation
