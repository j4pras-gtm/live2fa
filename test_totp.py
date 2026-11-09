from app.totp import generate_totp


def test_rfc6238_sha1_vector():
    # RFC 6238 Appendix B, 59 seconds, 8 digits.
    secret = "12345678901234567890".encode().hex()
    # The RFC vector is hex key; convert it to Base32 for the public API.
    import base64
    b32 = base64.b32encode(bytes.fromhex(secret)).decode().rstrip("=")
    code, remaining = generate_totp(b32, now=59, digits=8)
    assert code == "94287082"
    assert remaining == 1


def test_default_six_digit_code():
    code, remaining = generate_totp("JBSWY3DPEHPK3PXP", now=59)
    assert len(code) == 6
    assert 1 <= remaining <= 30
