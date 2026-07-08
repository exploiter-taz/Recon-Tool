"""Unit tests for TechDetectModule -- run in isolation, no engine required."""

from unittest.mock import MagicMock, patch

from core.context import Context
from modules.active.techdetect import TechDetectModule


def _make_context(target: str = "example.com") -> Context:
    return Context(target=target)


def test_validate_true_with_target():
    module = TechDetectModule()
    ctx = _make_context()
    assert module.validate(ctx) is True


def test_validate_false_with_empty_target():
    module = TechDetectModule()
    ctx = _make_context(target="")
    assert module.validate(ctx) is False


def test_name_and_description():
    module = TechDetectModule()
    assert module.name == "techdetect"
    assert isinstance(module.description, str) and module.description.endswith(".")


@patch("modules.active.techdetect.shutil.which", return_value=None)
def test_run_whatweb_skips_when_not_installed(mock_which):
    module = TechDetectModule()
    result = module._run_whatweb("example.com")
    assert result is None


@patch("modules.active.techdetect.requests.get")
def test_run_fallback_detects_wordpress(mock_get):
    mock_response = MagicMock()
    mock_response.headers = {"Server": "nginx"}
    mock_response.text = "<html>wp-content/themes/example</html>"
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    module = TechDetectModule()
    result = module._run_fallback("https://example.com")

    assert result is not None
    assert result["server"] == "nginx"
    assert "WordPress" in result["cms"]


@patch("modules.active.techdetect.requests.get")
def test_run_fallback_handles_request_exception(mock_get):
    import requests

    mock_get.side_effect = requests.RequestException("connection failed")

    module = TechDetectModule()
    result = module._run_fallback("https://unreachable.example")

    assert result is None


def test_run_writes_technologies_into_context():
    module = TechDetectModule()
    ctx = _make_context()

    with patch.object(module, "_run_whatweb", return_value=None), \
         patch.object(module, "_run_wappalyzer", return_value=None), \
         patch.object(module, "_run_fallback", return_value={"source": "fallback"}):
        module.run(ctx)

    assert ctx.technologies == [{"source": "fallback"}]


def test_run_sets_none_when_all_sources_fail():
    module = TechDetectModule()
    ctx = _make_context()

    with patch.object(module, "_run_whatweb", return_value=None), \
         patch.object(module, "_run_wappalyzer", return_value=None), \
         patch.object(module, "_run_fallback", return_value=None):
        module.run(ctx)

    assert ctx.technologies is None


def test_resolve_base_url_uses_https_when_443_open():
    module = TechDetectModule()
    ctx = _make_context()
    ctx.open_ports = [443]
    assert module._resolve_base_url(ctx) == "https://example.com"


def test_resolve_base_url_uses_http_when_only_80_open():
    module = TechDetectModule()
    ctx = _make_context()
    ctx.open_ports = [80]
    assert module._resolve_base_url(ctx) == "http://example.com"


def test_resolve_base_url_defaults_to_https_with_no_port_data():
    module = TechDetectModule()
    ctx = _make_context()
    assert module._resolve_base_url(ctx) == "https://example.com"