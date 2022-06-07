import asyncio
import os

import libnacl as nacl

from .error import ConnectionError, ZmqError
from .socket import ZmqSocket
from .util import (
    MessageBuilder,
    enc_frame_length,
    decode_metadata,
    encode_metadata,
    read_message,
)
from .z85 import z85_encode


class ZmqClient:
    def __init__(self, keypair=None):
        self.ident_pk, self.ident_sk = keypair or nacl.crypto_box_keypair()

    async def connect(self, host: str, port: int, curve_pk: bytes = None) -> ZmqSocket:
        reader, writer = await asyncio.open_connection(host, port)
        if len(curve_pk) != 32:
            raise ZmqError("invalid curve_pk: must be 32 bytes in length")

        # ZMTP: https://rfc.zeromq.org/spec/23/
        # CurveZMQ: https://rfc.zeromq.org/spec/26/

        version = b"\x03\x00"
        mechanism = b"CURVE" + bytes(15)

        greeting = MessageBuilder(64)
        greeting.write(b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x7f")  # signature
        greeting.write(version)
        greeting.write(mechanism)
        greeting.push(0)  # as_server flag
        greeting.skip(31)
        writer.write(greeting.complete())
        await writer.drain()

        data = await reader.read(10)
        if len(data) != 10:
            raise ConnectionError("disconnected")
        if data[0] != 255 or data[-1] != 127:
            raise ConnectionError("invalid greeting")

        data = await reader.read(54)
        if len(data) != 54:
            raise ConnectionError("disconnected")
        check_version, check_mechanism = data[0:2], data[2:22]
        if check_version != version:
            raise ConnectionError(f"unexpected version: {check_version}")
        if check_mechanism != mechanism:
            raise ConnectionError(f"unexpected mechanism: {check_mechanism}")

        ephemeral_pk, ephemeral_sk = nacl.crypto_box_keypair()
        hello_nonce = os.urandom(8)
        hello_signature = nacl.crypto_box(
            bytes(64),
            b"CurveZMQHELLO---" + hello_nonce,
            curve_pk,
            ephemeral_sk,
        )

        hello = MessageBuilder(200)
        hello.write(b"\x05HELLO\x01\x00")
        hello.skip(72)
        hello.write(ephemeral_pk)
        hello.write(hello_nonce)
        hello.write(hello_signature)
        hello = hello.complete()
        writer.write(enc_frame_length(hello, command=True))
        writer.write(hello)

        try:
            welcome = await read_message(reader, command=True)
        except ZmqError as ex:
            raise ConnectionError(str(ex)) from None
        if not welcome:
            raise ConnectionError("disconnected")
        if len(welcome) != 168 or welcome[:8] != b"\x07WELCOME":
            raise ConnectionError("invalid welcome packet")
        welcome_nonce = welcome[8:24]
        welcome_box = welcome[24:168]
        try:
            welcome_info = nacl.crypto_box_open(
                welcome_box, b"WELCOME-" + welcome_nonce, curve_pk, ephemeral_sk
            )
        except nacl.CryptError:
            raise ConnectionError("decryption error in welcome") from None
        server_eph_pk = welcome_info[:32]
        server_cookie = welcome_info[32:]

        vouch_nonce = os.urandom(16)
        vouch_box = nacl.crypto_box(
            ephemeral_pk + curve_pk,
            b"VOUCH---" + vouch_nonce,
            server_eph_pk,
            self.ident_sk,
        )
        vouch = vouch_nonce + vouch_box
        metadata = encode_metadata(
            {"Socket-Type": "DEALER", "Identity": z85_encode(self.ident_pk)}
        )
        xkey = nacl.crypto_box_beforenm(server_eph_pk, ephemeral_sk)
        # fixed nonce value (1) - counter is used for message nonces
        init_nonce = b"CurveZMQINITIATE\x00\x00\x00\x00\x00\x00\x00\x01"
        init_box = nacl.crypto_box_afternm(
            self.ident_pk + vouch + metadata,
            init_nonce,
            xkey,
        )
        initiate = MessageBuilder(113 + len(init_box))
        initiate.write(b"\x08INITIATE")
        initiate.write(server_cookie)
        initiate.write(init_nonce[16:24])
        initiate.write(init_box)
        initiate = initiate.complete()
        writer.write(enc_frame_length(initiate, command=True))
        writer.write(initiate)

        try:
            ready = await read_message(reader, command=True)
        except ZmqError as ex:
            raise ConnectionError(str(ex)) from None
        if not ready:
            raise ConnectionError("disconnected")
        if len(ready) < 30 or ready[:6] != b"\x05READY":
            raise ConnectionError("invalid ready packet")
        ready_nonce = ready[6:14]
        try:
            ready_meta = nacl.crypto_box_open_afternm(
                ready[14:], b"CurveZMQREADY---" + ready_nonce, xkey
            )
        except nacl.CryptError:
            raise ConnectionError("decryption error in ready") from None
        meta = decode_metadata(ready_meta)

        socket = ZmqSocket(reader, writer, meta, xkey, False)
        ident = socket.remote_identity
        if ident and ident != curve_pk:
            raise ConnectionError("server identity mismatch")
        return socket
