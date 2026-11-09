from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr

from .totp import generate_totp

app = FastAPI(title="Private TOTP API", version="1.0.0")


class TOTPRequest(BaseModel):
    secret: SecretStr = Field(..., description="Base32 TOTP secret or otpauth://totp URI")
    digits: Literal[6, 7, 8] = 6
    period: int = Field(30, ge=15, le=300)
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"


class TOTPResponse(BaseModel):
    code: str
    expires_in: int


def _check_api_key(provided: str | None) -> None:
    expected = os.getenv("TOTP_API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="TOTP_API_KEY is not configured")
    if not provided or not __import__("hmac").compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/totp", response_model=TOTPResponse)
def totp(request: TOTPRequest, x_api_key: str | None = Header(default=None)) -> TOTPResponse:
    _check_api_key(x_api_key)
    try:
        code, expires_in = generate_totp(
            request.secret.get_secret_value(),
            digits=request.digits,
            period=request.period,
            algorithm=request.algorithm,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return TOTPResponse(code=code, expires_in=expires_in)
