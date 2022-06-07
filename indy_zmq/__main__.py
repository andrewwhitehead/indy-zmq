import asyncio
import json
import sys

import base58


from .client import IndyClient
from .keys import create_server_keys
from .transport.server import ZmqServer
from .transport.socket import ZmqSocket


async def test_client_request(client: IndyClient):
    async with client:
        message_data = {
            "reqId": 123,
            "identifier": "LibindyDid111111111111",
            "operation": {"data": 1, "ledgerId": 1, "type": "3"},
            "protocolVersion": 2,
        }
        response = await client.request(message_data)
        print(await response.result())


async def test_server_handler(socket: ZmqSocket):
    while True:
        msg = await socket.receive()
        if not msg:
            break
        msg = json.loads(msg)
        req_id = msg.get("reqId", 1)
        await socket.send(json.dumps({"op": "REQACK", "reqId": req_id}))
        await socket.send(json.dumps({"op": "REPLY", "result": {"reqId": req_id}}))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Missing required arguments (action)")
    action = sys.argv[1]
    if action == "client":
        if len(sys.argv) < 5:
            raise SystemExit("Missing required arguments (host, port, verkey)")
        (host, port, verkey) = sys.argv[2:5]
        client = IndyClient(host, port, verkey)
        asyncio.run(test_client_request(client))
    elif action == "server":
        if len(sys.argv) < 4:
            raise SystemExit("Missing required arguments (host, port)")
        (host, port) = sys.argv[2:4]
        (ident_pk, _), curve_keys = create_server_keys()
        print("server ident:", base58.b58encode(ident_pk).decode("ascii"))
        server = ZmqServer(test_server_handler, curve_keys)
        asyncio.run(server.run(host, port))
    else:
        raise SystemExit(f"Unsupported action {action}")
