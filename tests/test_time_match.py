#!/usr/bin/env python3
import hmac, hashlib

LABEL='PromptWorks-TimeMatch-v1'

def code(key: bytes, host: str, epoch: int, number: str, decision: str) -> str:
    msg='\n'.join([LABEL,host,str(epoch),number,decision]).encode()
    d=hmac.new(key,msg,hashlib.sha256).digest()
    off=d[-1]&0x0f
    binary=((d[off]&0x7f)<<24)|(d[off+1]<<16)|(d[off+2]<<8)|d[off+3]
    return f'{binary%100_000_000:08d}'

key=bytes(range(32))
a=code(key,'host-abc',123456,'427','approve')
d=code(key,'host-abc',123456,'427','deny')
assert len(a)==8 and a.isdigit()
assert len(d)==8 and d.isdigit()
assert a != d
assert code(key,'host-abc',123456,'427','approve') == a
assert code(key,'host-abc',123457,'427','approve') != a
assert code(key,'host-abc',123456,'428','approve') != a
assert code(key,'host-def',123456,'427','approve') != a
print('time-match vectors: OK', a, d)
