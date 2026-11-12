"""Offline checks (no V1.0, nothing sent): python3 -m unittest discover -s tests"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

from arcade import funding, inscribe  # noqa: E402
from arcade.script import b58check_decode  # noqa: E402
from arcade.txbuild import p2pkh_script  # noqa: E402
from v1publish import chains  # noqa: E402
from v1publish.publisher import Key, PublishError, build, payload_outputs  # noqa: E402

# Arcade V1.0's own address versions (crates/arcade-chain/src/params.rs: p2pkh_version, p2sh_version).
V1_VERSIONS = {
    "peptest": (0x71, 0xC4), "pep": (56, 22), "dgb": (30, 63), "dgbtest": (126, 140), "kot": (46, 45),
    "flop": (35, 22), "ltc": (48, 50), "ltctest": (111, 58), "doge": (30, 22), "btc": (0, 5),
    "wjk": (73, 5), "shic": (63, 22), "bel": (25, 30), "lky": (47, 5), "jkc": (16, 5),
}

KEY = Key(int.from_bytes(hashlib.sha256(b"arcade-publish test key").digest(), "big"))


def coin(params, value=50 * 10**8, n=0):
    return {"txid": hashlib.sha256(bytes([n])).hexdigest(), "vout": n, "value": value,
            "address": KEY.address(params)}


def verify(unsigned):
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), KEY.pubkey)
    for h in unsigned.sighashes:
        sig = KEY.sign(bytes.fromhex(h))[:-1]
        pub.verify(sig, bytes.fromhex(h), ec.ECDSA(utils.Prehashed(hashes.SHA256())))


class Chains(unittest.TestCase):
    def test_every_v1_chain_is_known(self):
        self.assertEqual(set(chains.KEYS), set(V1_VERSIONS))

    def test_versions_match_v1(self):
        for key, (p2pkh, p2sh) in V1_VERSIONS.items():
            p = chains.params(key)
            self.assertEqual((p.pubkeyhash_version, p.scripthash_version), (p2pkh, p2sh), key)
            self.assertEqual(b58check_decode(KEY.address(p))[0], p2pkh, key)
            self.assertTrue(p.class_b, key)

    def test_fees_come_from_v1(self):
        p = chains.for_chain("dgb", 1_000_000, 5_460)
        self.assertEqual((p.min_fee_per_kb, p.dust_limit), (1_000_000, 5_460))

    def test_unknown_chain(self):
        with self.assertRaises(ValueError):
            chains.params("nope")


class Building(unittest.TestCase):
    def test_small_inscription_on_every_chain(self):
        for key in chains.KEYS:
            p = chains.for_chain(key, 1_000_000, 1_000_000)
            plan = inscribe.plan(b"hello from arcade-publish", "text/plain")
            outs = payload_outputs(p, KEY.address(p), KEY.pubkey, plan.payloads[0])
            u = build(p, KEY.address(p), [coin(p)], outs, p.min_fee_per_kb, "test")
            self.assertGreater(u.fee, 0, key)
            self.assertEqual(u.outputs[-1][1], p2pkh_script(KEY.address(p)), key)   # change comes back
            verify(u)

    def test_class_b_inscription(self):
        p = chains.for_chain("peptest", 1_000_000, 1_000_000)
        plan = inscribe.plan(os.urandom(2000), "application/octet-stream")
        outs = payload_outputs(p, KEY.address(p), KEY.pubkey, plan.payloads[0])
        self.assertEqual(outs[0][1], p2pkh_script(p.marker))      # the Class B marker is paid first
        verify(build(p, KEY.address(p), [coin(p)], outs, p.min_fee_per_kb))

    def test_kotia_carries_its_transaction_time(self):
        p = chains.for_chain("kot", 10_000, 100_000)
        u = build(p, KEY.address(p), [coin(p)], [(10**8, p2pkh_script(KEY.address(p)))], p.min_fee_per_kb)
        self.assertIsNotNone(u.ntime)
        raw = bytes.fromhex(u.raw)
        self.assertEqual(int.from_bytes(raw[4:8], "little"), u.ntime)
        assembled = bytes.fromhex(funding.assemble(u, [KEY.sign(bytes.fromhex(h)).hex() for h in u.sighashes],
                                                   KEY.pubkey))
        self.assertEqual(int.from_bytes(assembled[4:8], "little"), u.ntime)

    def test_other_chains_have_no_time(self):
        p = chains.for_chain("doge", 1_000_000, 1_000_000)
        u = build(p, KEY.address(p), [coin(p)], [(10**8, p2pkh_script(KEY.address(p)))], p.min_fee_per_kb)
        self.assertIsNone(u.ntime)
        self.assertEqual(bytes.fromhex(u.raw)[4], 1)          # straight to the input count

    def test_not_enough_coins(self):
        p = chains.for_chain("peptest", 1_000_000, 1_000_000)
        with self.assertRaises(PublishError):
            build(p, KEY.address(p), [coin(p, value=1000)], [(10**8, p2pkh_script(KEY.address(p)))], 1_000_000)


if __name__ == "__main__":
    unittest.main()
