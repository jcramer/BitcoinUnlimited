from ctypes import *

import pdb

try:
    cashlib = CDLL("libbitcoincash.so") # ,mode=1) # RTLD_GLOBAL)
except OSError:
    import os
    dir_path = os.path.dirname(os.path.realpath(__file__))
    cashlib = CDLL(dir_path + os.sep + "libbitcoincash.so")

class Error(BaseException):
    pass

def bin2hex(data):
    assert type(data) is bytes, "cashlib.bintohex requires parameter of type bytes"
    l = len(data)
    result = create_string_buffer(2*l + 1)
    if cashlib.Bin2Hex(data, l, result, 2*l + 1):
        return result.value.decode("utf-8")
    raise Error("cashlib bin2hex error")

def signtx(txbin, inputIdx, inputAmount, prevoutScript, sigHashType, key):
    if type(txbin) != bytes:
        txbin = txbin.serialize()
    result = create_string_buffer(100)
    siglen = cashlib.SignTx(txbin, len(txbin), inputIdx, inputAmount, prevoutScript, len(prevoutScript), sigHashType, key, result, 100)
    print("siglen", siglen)
    if siglen==0:
        raise Error("cashlib signtx error")
    return result.raw[0:siglen]

def randombytes(length):
    result = create_string_buffer(length)
    worked = cashlib.RandomBytes(result, length)
    if worked != length:
        raise Error("cashlib randombytes error")
    return result.value

def pubkey(key):
    result = create_string_buffer(65)
    l = cashlib.GetPubKey(key, result, 65)
    return result.raw[0:l]

def spendscript(*data):
    ret = []
    for d in data:
        assert type(d) is bytes
        l = len(d)
        if l == 0:  # push empty value onto the stack
            ret.append(bytes([0]))
        elif l <= 0x4b:
            ret.append(bytes([l]))  # 1-75 bytes push # of bytes as the opcode
            ret.append(d)
        elif l < 256:
            ret.append(bytes([76])) # PUSHDATA1
            ret.append(bytes([l]))
            ret.append(d)
        elif l < 65536:
            ret.append(bytes([77])) # PUSHDATA2
            ret.append(bytes([l&255,l>>8])) # little endian
            ret.append(d)
        else:  # bigger values won't fit on the stack anyway
            assert 0, "cannot push %d bytes" % l
    return b"".join(ret)

def Test():
    assert bin2hex(b"123") == "313233"
    assert len(randombytes(10)) == 10
    assert randombytes(16) != randombytes(16)
