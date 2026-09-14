#!/usr/bin/env python3
import hashlib
import hmac


def derive(master_hex, pairing_id, host_id, device_id, phone_fp, host_fp):
    payload = "\n".join([
        "promptworks-offline-pair-v1",
        pairing_id,
        host_id,
        device_id,
        phone_fp,
        host_fp,
    ]).encode()
    return hmac.new(bytes.fromhex(master_hex), payload, hashlib.sha256).hexdigest()


def main():
    master = "00" * 32
    common = dict(
        pairing_id="pwbind_00112233445566778899aabbccddeeff",
        host_id="laptop-deadbeef00",
        device_id="dev_1234",
        phone_fp="11" * 32,
        host_fp="22" * 32,
    )
    a = derive(master, **common)
    assert len(a) == 64
    b = derive(master, **{**common, "device_id": "dev_other"})
    c = derive(master, **{**common, "phone_fp": "33" * 32})
    d = derive(master, **{**common, "host_fp": "44" * 32})
    assert len({a, b, c, d}) == 4, "binding changes must derive different runtime keys"
    print("single-device binding derivation tests: OK")


if __name__ == "__main__":
    main()
