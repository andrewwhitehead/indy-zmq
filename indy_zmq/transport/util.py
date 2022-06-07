import asyncio

from typing import Sequence, Union

from .error import ZmqError


def enc_frame_length(body: bytes, *, command: bool) -> bytes:
    bodylen = len(body)
    flags = 4 if command else 0
    if bodylen <= 255:
        return bytes((flags, bodylen))
    return bytes((flags + 2,)) + bodylen.to_bytes(8, "big")


async def read_message(reader: asyncio.StreamReader, *, command: bool):
    bodylen = await reader.read(2)
    if not bodylen:
        return b""
    if len(bodylen) != 2:
        raise ZmqError("disconnected")
    is_cmd = bodylen[0] & 4 != 0
    if is_cmd != command:
        raise ZmqError("invalid command flag")
    is_long = bodylen[0] & 2 != 0
    if is_long:
        lenbuf = bytearray(8)
        lenbuf[0] = bodylen[1]
        bodylen_ext = await reader.read(7)
        if len(bodylen_ext) != 7:
            raise ZmqError("disconnected")
        lenbuf[1:] = bodylen_ext
        bodylen = int.from_bytes(lenbuf, "big")
        # FIXME reasonable limit on length?
    else:
        bodylen = bodylen[1]
    body = await reader.read(bodylen)
    if len(body) != bodylen:
        raise ZmqError("disconnected")
    return body


def encode_metadata(metadata: dict) -> bytes:
    result = bytearray()
    for (k, v) in metadata.items():
        if isinstance(k, str):
            k = k.encode("ascii")
        if isinstance(v, str):
            v = v.encode("ascii")
        result.append(len(k))
        result.extend(k)
        result.extend(len(v).to_bytes(4, "big"))
        result.extend(v)
    return bytes(result)


def decode_metadata(metadata: bytes) -> dict:
    result = {}
    while len(metadata):
        key_end = metadata[0] + 1
        k = metadata[1:key_end]
        value_start = key_end + 4
        vlen = metadata[key_end:value_start]
        if len(vlen) != 4:
            raise ZmqError("invalid metadata")
        vlen = int.from_bytes(vlen, "big")
        value_end = value_start + vlen
        result[k] = metadata[value_start:value_end]
        metadata = metadata[value_end:]
    return result


class MessageBuilder:
    def __init__(self, size: int):
        self.data = bytearray(size)
        self.pos = 0

    def skip(self, length: int):
        self.pos += length

    def push(self, value: int):
        self.data[self.pos] = value
        self.pos += 1

    def write(self, data: Union[bytes, Sequence[int]]):
        start = self.pos
        end = start + len(data)
        self.data[start:end] = data
        self.pos = end

    def complete(self) -> bytearray:
        if self.pos != len(self.data):
            raise ZmqError("message buffer size error")
        return self.data

    def __bytes__(self) -> bytes:
        return bytes(self.complete())
