import asyncio
import json

from typing import Union

import base58

import libnacl as nacl

from .transport.client import ZmqClient
from .transport.error import ConnectionError
from .transport.socket import ZmqSocket


def verkey_to_pk(verkey):
    return nacl.crypto_sign_ed25519_pk_to_curve25519(verkey)


class IndyClient:
    def __init__(
        self, host: str, port: Union[int, str], dest_pk: str, client_keypair=None
    ):
        if isinstance(port, str):
            port = int(port)
        self._host = host
        self._port = port
        self._client = ZmqClient(client_keypair)
        self._curve_pk = verkey_to_pk(base58.b58decode(dest_pk))
        self._pending = {}
        self._polling: asyncio.Task = None
        self._socket: ZmqSocket = None

    async def _connect(self) -> "IndyClient":
        self._socket = await self._client.connect(
            self._host, self._port, self._curve_pk
        )
        self._polling = asyncio.create_task(self._poll())
        return self

    def __aenter__(self):
        return self._connect()

    async def __aexit__(self, exc_type, exc, tb):
        if self._polling:
            self._polling.cancel()
            self._polling = None
        if self._socket:
            socket = self._socket
            self._socket = None
            await socket.close()

    async def request(self, message: dict) -> "IndyClientResponse":
        if not self._socket:
            raise ConnectionError("not connected")
        if not message or "reqId" not in message:
            raise ConnectionError("missing reqId for request")
        if message["reqId"] in self._pending:
            raise ConnectionError("duplicate reqId")
        response = IndyClientResponse(message["reqId"])
        self._pending[message["reqId"]] = response
        message = json.dumps(message).encode("utf-8")
        await self._socket.send(message)
        return response

    @property
    def socket(self) -> ZmqSocket:
        return self._socket

    async def _poll(self):
        try:
            while True:
                message = await self._socket.receive()
                if not message:
                    break
                try:
                    response = json.loads(message)
                except json.JSONDecodeError as ex:
                    raise ConnectionError("invalid response") from ex
                if not isinstance(response, dict) or "op" not in response:
                    raise ConnectionError("invalid response")
                op = response["op"]
                if op == "REQACK" and "reqId" in response:
                    pending = self._pending.get(response["reqId"])
                    if pending:
                        pending.set_acked()
                elif op == "REQNACK" and "reqId" in response:
                    pending = self._pending.pop(response["reqId"], None)
                    if pending:
                        pending.set_exception(ConnectionError(response.get("reason")))
                    else:
                        raise ConnectionError(response.get("reason"))
                elif op == "REPLY" and "result" in response:
                    result = response["result"]
                    if "reqId" not in result:
                        raise ConnectionError("invalid response")
                    pending = self._pending.pop(result["reqId"], None)
                    if pending:
                        pending.set_result(result)
                    else:
                        raise ConnectionError("invalid response")
                else:
                    print("unhandled operation:", op)
        except ConnectionError as ex:
            for message in self._pending.values():
                message.set_exception(ex)
            self._pending.clear()
        finally:
            for message in self._pending.values():
                message.set_exception(ConnectionError("disconnected"))
            self._pending.clear()
            if self._socket:
                await self._socket.close()
                self._socket = None


class IndyClientResponse:
    def __init__(self, reqId: int):
        self.reqId = reqId
        self._body: dict = None
        self._complete: bool = False
        self._exception: Exception = None
        self._status = "sent"
        self._waiter = asyncio.Event()

    async def result(self) -> dict:
        if not self._complete:
            await self._waiter.wait()
        if self._exception:
            raise self._exception
        return self._body

    def exception(self) -> Exception:
        return self._exception

    def is_complete(self) -> bool:
        return self._complete

    def set_acked(self):
        self._status = "acked"

    def set_exception(self, exception: Exception):
        self._exception = exception
        self._waiter.set()

    def set_result(self, result: dict):
        self._body = result
        self._waiter.set()
