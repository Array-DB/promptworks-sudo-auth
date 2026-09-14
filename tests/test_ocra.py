#!/usr/bin/env python3
"""Small interoperability test for the OCRA encoding used by PromptWorks v3.3."""
import hashlib, hmac

def ocra_numeric(key_hex: str, suite: str, challenge: str, digits: int) -> str:
    qhex = format(int(challenge, 10), "X").ljust(256, "0")
    q = bytes.fromhex(qhex)
    msg = suite.encode("ascii") + b"\x00" + q
    digestmod = hashlib.sha256 if "SHA256" in suite else hashlib.sha1
    digest = hmac.new(bytes.fromhex(key_hex), msg, digestmod).digest()
    off = digest[-1] & 0x0F
    binary = ((digest[off] & 0x7F) << 24) | (digest[off+1] << 16) | (digest[off+2] << 8) | digest[off+3]
    return f"{binary % (10**digits):0{digits}d}"

# RFC 6287 Appendix C.1 vectors for OCRA-1:HOTP-SHA1-6:QN08.
seed20 = "3132333435363738393031323334353637383930"
expected = ["237653", "243178", "653583", "740991", "608993"]
for i, want in enumerate(expected):
    got = ocra_numeric(seed20, "OCRA-1:HOTP-SHA1-6:QN08", str(i) * 8, 6)
    assert got == want, (i, got, want)

# Deterministic project-suite regression vector.
assert ocra_numeric("00" * 32, "OCRA-1:HOTP-SHA256-8:QN12", "482716305941", 8) == "47987413"
print("OCRA vectors: OK")
