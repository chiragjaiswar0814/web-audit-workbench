from app.scanner import _parse_set_cookie_headers


def test_parse_set_cookie_headers_basic():
    cookies = _parse_set_cookie_headers(
        [
            "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            "pref=1; Path=/",
        ]
    )
    assert any(c["name"] == "sid" and c["secure"] and c["httponly"] and c["samesite"] == "Lax" for c in cookies)
    assert any(c["name"] == "pref" for c in cookies)
