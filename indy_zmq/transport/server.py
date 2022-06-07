import asyncio
import os

from typing import Callable

import libnacl as nacl

from .error import ConnectionError, ZmqError
from .socket import ZmqSocket
from .util import (
    MessageBuilder,
    decode_metadata,
    enc_frame_length,
    encode_metadata,
    read_message,
)
from .z85 import z85_encode


class ZmqServer:
    def __init__(self, handler: Callable, keypair=None):
        self.handler = handler
        self.ident_pk, self.ident_sk = keypair or nacl.crypto_box_keypair()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            socket = await self._connect(reader, writer)
            await self.handler(socket)
        finally:
            writer.close()

    async def run(self, host: str, port: int):
        server = await asyncio.start_server(self.handle_client, host, port)
        async with server:
            await server.serve_forever()

    async def _connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> ZmqSocket:
        version = b"\x03\x00"
        mechanism = b"CURVE" + bytes(15)

        greeting = MessageBuilder(64)
        greeting.write(b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x7f")  # signature
        greeting.write(version)
        greeting.write(mechanism)
        greeting.push(1)  # as_server flag
        greeting.skip(31)
        greeting = greeting.complete()
        writer.write(greeting)
        await writer.drain()

        data = await reader.read(12)
        if len(data) != 12:
            raise ConnectionError("disconnected")
        if data[0] != 255 or data[-3] != 127:
            raise ConnectionError("invalid greeting")
        check_version = data[-2:]
        if check_version != version:
            raise ConnectionError(f"unexpected version: {check_version}")

        data = await reader.read(52)
        if len(data) != 52:
            raise ConnectionError("disconnected")
        check_mechanism = data[:20]
        if check_mechanism != mechanism:
            raise ConnectionError(f"unexpected mechanism: {check_mechanism}")

        hello = await read_message(reader, command=True)
        if len(hello) != 200 or hello[:8] != b"\x05HELLO\x01\x00":
            raise ConnectionError("invalid hello packet")
        client_eph_pk = hello[80:112]
        nonce_full = b"CurveZMQHELLO---" + hello[112:120]
        try:
            signed = nacl.crypto_box_open(
                hello[120:200], nonce_full, client_eph_pk, self.ident_sk
            )
            if signed != bytes(64):
                raise ConnectionError("invalid signature")
        except nacl.CryptError:
            raise ConnectionError("decryption error in hello") from None

        ephemeral_pk, ephemeral_sk = nacl.crypto_box_keypair()
        welcome_nonce = os.urandom(16)
        welcome = MessageBuilder(168)
        welcome.write(b"\x07WELCOME")
        welcome.write(welcome_nonce)
        cookie = os.urandom(96)  # supposed to encode ephemeral private key
        welcome.write(
            nacl.crypto_box(
                ephemeral_pk + cookie,
                b"WELCOME-" + welcome_nonce,
                client_eph_pk,
                self.ident_sk,
            )
        )
        welcome = welcome.complete()
        writer.write(enc_frame_length(welcome, command=True))
        writer.write(welcome)

        initiate = await read_message(reader, command=True)
        if len(initiate) < 257 or initiate[:9] != b"\x08INITIATE":
            raise ConnectionError("invalid initiate packet")
        xkey = nacl.crypto_box_beforenm(client_eph_pk, ephemeral_sk)
        try:
            init_boxed = nacl.crypto_box_open_afternm(
                initiate[113:], b"CurveZMQINITIATE" + initiate[105:113], xkey
            )
        except nacl.CryptError:
            raise ConnectionError("decryption error in initiate") from None
        client_pk = init_boxed[:32]
        try:
            client_metadata = decode_metadata(init_boxed[128:])
        except ZmqError:
            raise ConnectionError("invalid client metadata") from None
        try:
            vouch = nacl.crypto_box_open(
                init_boxed[48:128],
                b"VOUCH---" + init_boxed[32:48],
                client_pk,
                ephemeral_sk,
            )
        except nacl.CryptError:
            raise ConnectionError("decryption error in vouch") from None
        if vouch != client_eph_pk + self.ident_pk:
            raise ConnectionError("invalid vouch contents")
        # FIXME check identity in metadata

        metadata = encode_metadata(
            {b"Socket-Type": "ROUTER", b"Identity": z85_encode(self.ident_pk)}
        )
        ready = MessageBuilder(30 + len(metadata))
        ready_nonce = b"CurveZMQREADY---\x00\x00\x00\x00\x00\x00\x00\x01"
        ready.write(b"\x05READY")
        ready.write(ready_nonce[16:24])
        ready.write(nacl.crypto_box_afternm(metadata, ready_nonce, xkey))
        ready = ready.complete()
        writer.write(enc_frame_length(ready, command=True))
        writer.write(ready)
        await writer.drain()

        socket = ZmqSocket(reader, writer, client_metadata, xkey, True)
        ident = socket.remote_identity
        if ident and ident != client_pk:
            raise ConnectionError("client identity mismatch")
        return socket
