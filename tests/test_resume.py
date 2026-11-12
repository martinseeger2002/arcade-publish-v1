"""A run stopped between a broadcast and its journal entry sends nothing twice when resumed, with no
wallet history to search (a chain Arcade V1.0 borrows answers listtransactions with [])."""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from arcade.rpc import RpcError  # noqa: E402
from test_offline import KEY  # noqa: E402
from v1publish import chains  # noqa: E402
from v1publish.publisher import Publisher, _txid_of  # noqa: E402


class Crash(Exception):
    pass


class FakeV1:
    """Just enough of V1.0's Core RPC for a borrowed chain: coins of the address, broadcasts kept."""

    def __init__(self, address):
        self.address = address
        self.sent = {}            # txid -> raw
        self.crash_after_send = False
        self.coins = [{"txid": hashlib.sha256(bytes([i])).hexdigest(), "vout": 0, "amount": 500.0,
                       "address": address} for i in range(3)]

    def call(self, method, *params):
        if method == "validateaddress":
            return {"isvalid": True, "iswatchonly": True}
        if method == "listunspent":
            return self.coins
        if method == "listtransactions":
            return []
        if method == "sendrawtransaction":
            txid = _txid_of(params[0])
            self.sent[txid] = params[0]
            if self.crash_after_send:
                raise Crash()
            return txid
        if method == "getrawtransaction":
            if params[0] in self.sent:
                return {"txid": params[0], "confirmations": 1}
            raise RpcError(-5, "No such mempool or blockchain transaction")
        if method == "gettxout":
            return None
        raise RpcError(-32601, method)


class Resume(unittest.TestCase):
    def setUp(self):
        self.p = chains.for_chain("doge", 1_000_000, 1_000_000)
        self.rpc = FakeV1(KEY.address(self.p))
        self.dir = tempfile.mkdtemp()

    def pub(self):
        return Publisher(self.rpc, self.p, KEY, self.dir)

    def test_single(self):
        self.rpc.crash_after_send = True
        with self.assertRaises(Crash):
            self.pub().inscribe(b"hello", "text/plain", name="a.txt")
        self.assertEqual(len(self.rpc.sent), 1)
        self.rpc.crash_after_send = False
        out = self.pub().inscribe(b"hello", "text/plain", name="a.txt")
        self.assertEqual(len(self.rpc.sent), 1, "sent again")
        self.assertEqual(out["id"], next(iter(self.rpc.sent)))

    def test_piece(self):
        body = os.urandom(30_000)            # several pieces
        pub = self.pub()
        # Crash right after the second broadcast (the split, then piece 0).
        calls = {"n": 0}
        real = self.rpc.call

        def call(method, *params):
            if method == "sendrawtransaction":
                calls["n"] += 1
                if calls["n"] == 2:
                    self.rpc.crash_after_send = True
            try:
                return real(method, *params)
            finally:
                self.rpc.crash_after_send = False
        self.rpc.call = call
        with self.assertRaises(Crash):
            pub.inscribe(body, "application/octet-stream", name="b.bin")
        self.assertEqual(len(self.rpc.sent), 2)
        out = self.pub().inscribe(body, "application/octet-stream", name="b.bin")
        journal = json.load(open(os.path.join(self.dir, hashlib.sha256(body).hexdigest() + ".json")))
        self.assertGreater(out["chunks"], 2)
        self.assertEqual(len(self.rpc.sent), 1 + out["chunks"], "a piece went out twice")
        self.assertEqual(sorted(out["txids"]), sorted(t for t in self.rpc.sent if t != journal["split"]))


if __name__ == "__main__":
    unittest.main()
