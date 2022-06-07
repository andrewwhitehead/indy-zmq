import asyncio

from typing import Union

import libnacl as nacl

from .error import ConnectionError, ZmqError
from .util import MessageBuilder, enc_frame_length, read_message
from .z85 import z85_decode

CLIENT_NONCE = b"CurveZMQMESSAGEC"
SERVER_NONCE = b"CurveZMQMESSAGES"


class ZmqSocket:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        meta: dict,
        xkey: bytes,
        server: bool,
    ):
        self._reader = reader
        self._writer = writer
        self._meta = meta
        self._xkey = xkey
        self._nonce = 2
        self._server = server

    @property
    def remote_metadata(self) -> dict:
        return self._meta

    @property
    def remote_identity(self) -> bytes:
        ident = self._meta.get(b"Identity")
        if ident:
            ident = z85_decode(ident)
        return ident

    @property
    def remote_socket_type(self) -> bytes:
        self._meta.get(b"Socket-Type")

    async def receive(self) -> bytes:
        parts = None
        while True:
            try:
                body = await read_message(self._reader, command=False)
            except ZmqError as ex:
                writer = self._writer
                self._writer = None
                writer.close()
                try:
                    await writer.wait_closed()
                finally:
                    raise ConnectionError(str(ex))
            if not body and not parts:
                return None
            if len(body) < 33 or body[:8] != b"\x07MESSAGE":
                raise ConnectionError("invalid response message")
            nonce = (CLIENT_NONCE if self._server else SERVER_NONCE) + body[8:16]
            message_plain = nacl.crypto_box_open_afternm(body[16:], nonce, self._xkey)
            more = message_plain[0] & 1
            message_plain = message_plain[1:]
            if more:
                if not parts:
                    parts = [message_plain]
                else:
                    parts.append(message_plain)
            else:
                if parts:
                    parts.append(message_plain)
                    return b"".join(parts)
                else:
                    return message_plain

    async def send(self, message: Union[str, bytes]):
        if not self._writer:
            raise ConnectionError("disconnected")
        if isinstance(message, str):
            message = message.encode("utf-8")
        message_nonce = self._nonce.to_bytes(8, "big")
        self._nonce += 1
        nonce = (SERVER_NONCE if self._server else CLIENT_NONCE) + message_nonce
        message_data = bytearray(len(message) + 1)
        message_data[1:] = message
        message_box = nacl.crypto_box_afternm(message_data, bytes(nonce), self._xkey)
        message = MessageBuilder(32 + len(message))
        message.write(b"\x07MESSAGE")
        message.write(message_nonce)
        message.write(message_box)
        message = message.complete()
        self._writer.write(enc_frame_length(message, command=False))
        self._writer.write(message)
        await self._writer.drain()

    async def close(self):
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
