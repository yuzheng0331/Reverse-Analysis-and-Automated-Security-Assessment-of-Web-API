import json
from handlers.base import CryptoContext
from handlers.operations import HMACSha256Operation, RSAEncryptOperation

pub = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----"""

ctx = CryptoContext(plaintext="A" * 300)
ctx.extra_params["public_key"] = pub
rsa_res = RSAEncryptOperation().execute(ctx)

hctx = CryptoContext(plaintext={"username": "u", "password": "p"})
hctx.key = "k"
h_res = HMACSha256Operation().execute(hctx)

out = {
    "rsa_success": rsa_res.success,
    "rsa_error": rsa_res.error,
    "rsa_chunked": (rsa_res.metadata or {}).get("chunked"),
    "hmac_success": h_res.success,
    "hmac_len": len(h_res.output or ""),
}

print(json.dumps(out, ensure_ascii=False))

