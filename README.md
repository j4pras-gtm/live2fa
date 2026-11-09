# Private TOTP API

A small RFC 6238-compatible service for applications that need to obtain a current six-digit TOTP code. It supports Base32 secrets and `otpauth://totp/...` URIs.

## Security model

Run this service on a private network or behind a trusted HTTPS reverse proxy. Every request requires the `X-API-Key` header. The API accepts the TOTP secret in the JSON body, never in the URL. Do not expose it publicly, and configure your proxy and application logs not to record request bodies or headers.

This implementation does not persist secrets and does not log them. The host process and application calling it still need to be trusted because a TOTP secret can generate valid login codes.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export TOTP_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn app.main:app --reload
```

## Call it

```bash
curl -s http://127.0.0.1:8000/v1/totp \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: replace-with-your-key' \
  -d '{"secret":"JBSWY3DPEHPK3PXP"}'
```

Example response:

```json
{"code":"123456","expires_in":17}
```

The code and expiry vary with the current time. The default is six digits, SHA-1, and a 30-second period; these can be overridden when the issuer uses different TOTP settings.

## Docker

```bash
docker build -t private-totp-api .
docker run --rm -p 8000:8000 -e TOTP_API_KEY='replace-with-a-long-random-value' private-totp-api
```

## Tests

```bash
pytest -q
```
