import struct

MAP_ENCODE = (
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
    b"HIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
)
MAP_DECODE = {c: idx for (idx, c) in enumerate(MAP_ENCODE)}


class Z85Exception(Exception):
    pass


def z85_decode(msg: bytes) -> bytes:
    if isinstance(msg, str):
        msg = msg.encode("ascii")
    if len(msg) % 5 != 0:
        raise Z85Exception("message must be a multiple of 5 bytes")
    buf = bytearray(len(msg) * 4 // 5)
    copy_to = 0
    idx = 0
    val = 0
    try:
        for char in msg:
            val += MAP_DECODE[char]
            idx += 1
            if idx == 5:
                copy_next = copy_to + 4
                buf[copy_to:copy_next] = val.to_bytes(4, "big")
                copy_to = copy_next
                idx = 0
                val = 0
            else:
                val *= 85
    except KeyError:
        raise Z85Exception("invalid input")
    return bytes(buf)


def z85_encode(msg: bytes) -> bytes:
    if isinstance(msg, str):
        msg = msg.encode("ascii")
    if len(msg) % 4 != 0:
        raise Z85Exception("message must be a multiple of 4 bytes")
    buf = bytearray(len(msg) * 5 // 4)
    idx = 4
    for (val,) in struct.iter_unpack(">L", msg):
        for _ in range(4):
            buf[idx] = MAP_ENCODE[val % 85]
            idx -= 1
            val //= 85
        buf[idx] = MAP_ENCODE[val]
        idx += 9
    return bytes(buf)


if __name__ == "__main__":
    assert z85_decode("HelloWorld") == b"\x86\x4F\xD2\x6F\xB5\x59\xF7\x5B"
    assert z85_encode(b"\x86\x4F\xD2\x6F\xB5\x59\xF7\x5B") == b"HelloWorld"
