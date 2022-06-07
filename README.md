## Indy ZMQ tools

**Sample commands:**

Run a client request against a Node or pseudo-Node server:

```py
python -m indy_zmq client <host> <port> <verkey>
```

The host, port, and verkey correspond to the `client_ip`, `client_port`, and `dest` attributes in the pool genesis transactions. The client request is a basic `GET_TXN` for the first ledger transaction.

Run a pseudo Node server (testing native Python zmq server):

```py
python -m indy_zmq server 0.0.0.0 9702
```

Run a pseudo Node server (using Plenum):

```py
python node.py
```
