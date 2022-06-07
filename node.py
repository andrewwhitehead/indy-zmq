"""
Test script for booting the equivalent of a plenum Node
with no metrics or inter-node communication, and no
real support for ledger requests.
"""

import asyncio
import sys
import tempfile
import unittest.mock

import base58
import zmq

sys.modules["rocksdb"] = unittest.mock.MagicMock()

from plenum.common.metrics_collector import NullMetricsCollector
from plenum.common.stacks import ClientZStack
from stp_core.config import ZMQ_CLIENT_QUEUE_SIZE
from stp_core.crypto.util import randomSeed
from stp_core.network.auth_mode import AuthMode
from stp_core.types import HA

# requires jsonpickle, importlib_metadata, psutil


class Server:
    def __init__(self, host, port):
        self.seed = randomSeed()
        self.metrics = NullMetricsCollector()
        self.name = "clientStack"
        self.timer = None
        self.tempdir = tempfile.TemporaryDirectory()

        self.pubkey, self.verkey = ClientZStack.initLocalKeys(
            self.name, self.tempdir.name, self.seed, override=True
        )
        print(
            "Using verkey:",
            base58.b58encode(bytes.fromhex(self.verkey)).decode("ascii"),
        )

        stackParams = {
            "name": self.name,
            "ha": HA(host, port),
            "main": True,
            "auth_mode": AuthMode.ALLOW_ANY.value,
            "queue_size": ZMQ_CLIENT_QUEUE_SIZE,
            "basedirpath": self.tempdir.name,
        }
        kwargs = dict(
            stackParams=stackParams,
            msgHandler=self.handle_client_msg,
            # TODO, Reject is used when dynamic validation fails, use Reqnack
            msgRejectHandler=self.reject_client_msg_handler,
            metrics=self.metrics,
            timer=self.timer,
            seed=self.seed,
        )
        self.clientstack = ClientZStack(**kwargs)

    async def start(self):
        self.clientstack.start()
        self.clientstack.listener.setsockopt(zmq.CONNECT_TIMEOUT, 1)
        while True:
            await self.clientstack.service(None)
            self.clientstack.serviceClientStack()

    def handle_client_msg(self, wrapped):
        (msg, from_ident) = wrapped
        req_id = msg.get("reqId", 1)
        self.clientstack.send({"op": "REQACK", "reqId": req_id}, from_ident)
        self.clientstack.send({"op": "REPLY", "result": {"reqId": req_id}}, from_ident)

    def reject_client_msg_handler(self, reason, frm):
        print(f"reject message: {reason} {frm}")
        # self.clientstack.transmitToClient(Reject("", "", reason), frm)


if __name__ == "__main__":
    server = Server("0.0.0.0", 9702)
    asyncio.run(server.start())
