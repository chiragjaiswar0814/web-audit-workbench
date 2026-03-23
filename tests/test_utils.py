import pytest

from app.utils import normalize_http_url


def test_normalize_http_url_ok_https():
    assert normalize_http_url("https://example.com") == "https://example.com/"


def test_normalize_http_url_ok_path():
    assert normalize_http_url("http://example.com/a") == "http://example.com/a"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://example.com",
        "example.com",
        "http://",
        "https://user:pass@example.com/",
    ],
)
def test_normalize_http_url_rejects(value):
    with pytest.raises(ValueError):
        normalize_http_url(value)
