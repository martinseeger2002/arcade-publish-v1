"""Publishing an inscription through Arcade V1.0: plan, coins, sign, send.

The publisher of the original Dogecoin Arcade (arcade/publish.py), pointed at
Arcade V1.0 on the same computer instead of a coin node. V1.0 answers the
Core JSON-RPC calls it makes (listunspent, sendrawtransaction,
getrawtransaction, gettxout, decoderawtransaction, listtransactions) for every
chain it keeps, at POST /chain/<key>, with the cookie in <V1 home>/.cookie.
The key stays here: transactions are built and signed in this process and
handed to V1.0 to broadcast. V1.0's wallet is never used.

What has gone out is written in a journal keyed by the file's sha256, so a
run that stops is picked up where it stopped and no piece is paid for twice.

Shape of a run (one file):

1. `inscribe.plan` says how many transactions and what each carries.
2. One transaction: its payload outputs (Class C in an OP_RETURN where it
   fits, Class B marker + multisig outputs otherwise) paid from the address's
   coins, change back to the sender. Broadcast; done.
3. Several: a SPLIT first -- one output per piece -- broadcast and waited
   for (one block), then every piece, each spending its own output, all
   broadcast at once. The inscription's id is the txid of piece 0, which
   carries the manifest.

Transfers, for a program that pays people (a game's bank): a token send, a
managed token's grant, an inscription handed on. Each is named by an INTENT
(unique to it), read back before it is trusted and journaled with its signed
bytes before the broadcast, so an intent is paid at most once.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable

from arcade import fees
from arcade import funding
from arcade import inscribe as inscribelib
from arcade import inscriptions as inscriptionlib
from arcade import media
from arcade import payload as P
from arcade import tokens as tokenlib
from arcade.config import Params
from arcade.encoding import MAX_CLASS_B_PAYLOAD, encode_class_b, encode_class_c, max_class_c_payload
from arcade.messaging import sender as sendermod
from arcade.rpc import RpcClient, RpcError, RpcTransportError  # noqa: F401  (callers tell the two apart)
from arcade.script import b58check_decode, b58check_encode, hash160
from arcade.txbuild import build_raw_tx, multisig_script, op_return_script, p2pkh_script

#: The secp256k1 group order: a secret is 1 .. N-1, and a signature's s is kept
#: in the low half (BIP-62), which is what the network relays.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Confirmations a split needs before its pieces go out.
SPLIT_CONFIRMATIONS = 1


class PublishError(Exception):
    """Something that stops a publication, said in words a person can act on."""


class Key:
    """A secp256k1 secret, held here, that signs for one address.

    Read from a file holding the secret as 64 hex digits (mode 0600), the way
    `referee.key` is kept. The same key makes the same address on every chain
    but for the version byte, so one file serves testnet and mainnet.
    """

    def __init__(self, secret: int):
        if not 1 <= secret < N:
            raise PublishError("that is not a secp256k1 secret")
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.derive_private_key(secret, ec.SECP256K1())

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Key":
        text = Path(path).read_text().strip()
        try:
            return cls(int(text, 16))
        except ValueError:
            raise PublishError(f"{path} does not hold a 64-hex-digit secret") from None

    @property
    def pubkey(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return self._key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    def address(self, params: Params) -> str:
        return b58check_encode(params.pubkeyhash_version, hash160(self.pubkey))

    def sign(self, digest: bytes, sighash_type: int = funding.SIGHASH_ALL) -> bytes:
        """DER, low-S, and the sighash byte: what a scriptSig carries."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        der = self._key.sign(bytes(digest), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        if s > N // 2:
            s = N - s
        return utils.encode_dss_signature(r, s) + bytes([sighash_type])


def payload_outputs(params: Params, address: str, pubkey: bytes, body: bytes,
                    wrap: bool = True) -> list[tuple[int, bytes]]:
    """The outputs that carry one inscription body, in whichever class fits.

    The body is wrapped in `AnyData` (type 200) here and nowhere else -- the
    rule `_class_c_or_b` keeps for the interface, kept for the same reason: an
    unwrapped body reads as an Omni header the token engine stops on, and a
    body wrapped twice is paid for and never appears. `wrap=False` is for a
    body that already IS an Omni message (a token send or grant), exactly as
    `_class_c_or_b` has it.
    """
    payload = P.AnyData(data=body).encode() if wrap else body
    if len(payload) <= max_class_c_payload():
        return [(0, op_return_script(encode_class_c(payload)))]
    if not getattr(params, "class_b", True):
        raise PublishError(f"{params.label} carries arcade data in an OP_RETURN only (no Class B): at most "
                           f"{max_class_c_payload()} bytes per transaction, and this needs {len(payload)}")
    if len(payload) > MAX_CLASS_B_PAYLOAD:
        raise PublishError(f"a body of {len(payload)} bytes does not fit one transaction "
                           f"(at most {MAX_CLASS_B_PAYLOAD}); the plan should have split it")
    outputs = [(sendermod.OUTPUT_VALUE, p2pkh_script(params.marker))]
    for group in encode_class_b(address, pubkey, payload):
        outputs.append((sendermod.OUTPUT_VALUE, multisig_script(list(group.keys), group.required)))
    return outputs


class Coins:
    """What a run knows about coins that the source does not yet: between a
    broadcast and its block the source still lists the coin just spent and not
    the change that came back."""

    def __init__(self, address: str):
        self.address = address
        self.spent: set[tuple[str, int]] = set()
        self.extra: list[dict] = []

    def watch(self) -> None:
        pass

    def listed(self) -> list[dict]:
        raise NotImplementedError

    def unspent(self) -> list[dict]:
        coins = self.listed()
        have = {(c["txid"], c["vout"]) for c in coins}
        coins += [dict(c) for c in self.extra if (c["txid"], c["vout"]) not in have]
        return [c for c in coins if (c["txid"], c["vout"]) not in self.spent]

    def confirmed(self) -> list[dict]:
        """Only coins already in a block: a transfer never spends change that is
        still waiting for one, so no chain of unconfirmed transactions grows
        and none is refused as too long (bank_rpc_plan.md 3a)."""
        return [c for c in self.listed() if (c["txid"], c["vout"]) not in self.spent]

    def note(self, unsigned: funding.Unsigned, txid: str) -> None:
        """A transaction went out: its inputs are gone, its change is ours."""
        for coin in unsigned.inputs:
            self.spent.add((coin["txid"], coin["vout"]))
        for n, (value, script) in enumerate(unsigned.outputs):
            if script == p2pkh_script(self.address) and value > 0:
                self.extra.append({"txid": txid, "vout": n, "value": value, "address": self.address})


class NodeCoins(Coins):
    """An address's confirmed coins, as Arcade V1.0's address index lists them
    (V1.0 reports every address as watched; `importaddress` is accepted and
    does nothing).

    `watch` imports the address watch-only (idempotent; the first time the
    node rescans, which on testnet is minutes and on regtest nothing).
    Between a broadcast and its block the node still lists the coin just
    spent and not the change that came back, so `spent` and `extra` carry
    what this run knows and the wallet does not yet.
    """

    def __init__(self, rpc: RpcClient, address: str):
        super().__init__(address)
        self.rpc = rpc

    def watch(self, rescan: bool = True) -> None:
        try:
            info = self.rpc.call("validateaddress", self.address)
        except RpcError:
            info = {}
        if info.get("iswatchonly") or info.get("ismine"):
            return
        self.rpc.call("importaddress", self.address, "arcade-publish", rescan)

    def listed(self, minconf: int = 1) -> list[dict]:
        rows = self.rpc.call("listunspent", minconf, 9_999_999, [self.address])
        return [{"txid": str(r["txid"]), "vout": int(r["vout"]),
                 "value": int(round(float(r["amount"]) * fees.COIN)),
                 "address": self.address} for r in rows]


def choose(coins: list[dict], target: int) -> list[dict]:
    """Coins worth at least `target`: the smallest sufficient one first, else
    the largest until there is enough (the rule `funding.choose` follows, so a
    split wallet is not collapsed back into one coin)."""
    big_enough = [c for c in coins if c["value"] >= target]
    ordered = (sorted(big_enough, key=lambda c: c["value"]) if big_enough
               else sorted(coins, key=lambda c: -c["value"]))
    chosen, total = [], 0
    for coin in ordered:
        chosen.append(coin)
        total += coin["value"]
        if total >= target:
            return chosen
    raise PublishError(f"not enough confirmed coins at this address: {total / fees.COIN:.8f} "
                       f"here, {target / fees.COIN:.8f} needed")


def build(params: Params, address: str, coins: list[dict], outputs: list[tuple[int, bytes]], rate: int,
          what: str = "") -> funding.Unsigned:
    """`funding.build`, paid out of coins V1.0 named, on the chain `params` describes:
    its fee rate and dust limit, and its transaction time where it has one (Kotia)."""
    rate = fees.rate_for(params, rate)
    dust = fees.dust_limit(params)
    ntime = funding.tx_time(params)
    spend = sum(value for value, _ in outputs)
    guess = funding.price(1, outputs, rate, change=True, params=params)
    chosen = choose(coins, spend + guess)
    fee = funding.price(len(chosen), outputs, rate, change=True, params=params)
    if sum(c["value"] for c in chosen) < spend + fee:
        chosen = choose(coins, spend + fee)
        fee = funding.price(len(chosen), outputs, rate, change=True, params=params)
    total = sum(c["value"] for c in chosen)
    change = total - spend - fee
    outs = list(outputs)
    if change >= dust:
        outs.append((change, p2pkh_script(address)))
    else:
        fee += max(0, change)
        change = 0
    raw = build_raw_tx([(c["txid"], c["vout"]) for c in chosen], outs, ntime=ntime)
    script = p2pkh_script(address)
    hashes = [funding.sighash(chosen, outs, n, script, ntime=ntime).hex() for n in range(len(chosen))]
    return funding.Unsigned(raw=raw, inputs=chosen, outputs=outs, sighashes=hashes,
                            fee=fee, change=change, what=what, ntime=ntime)


class Journal:
    """What has gone out for one file, by its sha256: survives a stop."""

    def __init__(self, home: Path, digest: str):
        self.path = Path(home) / f"{digest}.json"
        self.data: dict[str, Any] = {"sha256": digest, "tag": "", "split": "", "pieces": {}, "txids": []}
        if self.path.exists():
            self.data.update(json.loads(self.path.read_text()))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1))
        os.replace(tmp, self.path)


#: The most a transfer may pay the network. A transfer is a few hundred bytes
#: at the minimum rate, about 0.01; a fee a hundred times that is a build gone
#: wrong, and nothing is signed for it.
MAX_TRANSFER_FEE = fees.COIN


class TransferJournal:
    """Every transfer this address has signed, one JSON line each, by intent.

    The line -- the intent's key, the txid and the SIGNED bytes -- is written
    and fsynced BEFORE the broadcast. So a run that stops anywhere leaves one
    of two things: no line (nothing went out), or a line whose bytes are
    exactly what went out or would have. Asked again for the same intent,
    `Publisher.transfer` sends those same bytes again rather than build new
    ones: the same inputs, so the network takes them at most once, whatever
    happened before. A line marked `refused` is one the node turned down and
    that is not in its mempool or a block; that intent may be built afresh.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.by_key: dict[str, dict] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue                  # a line torn by a crash mid-write was never fsynced: nothing went out
                if rec.get("refused"):
                    self.by_key.pop(rec.get("k"), None)
                elif rec.get("k"):
                    self.by_key[rec["k"]] = rec

    def get(self, key: str) -> dict | None:
        return self.by_key.get(key)

    def write(self, rec: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if rec.get("refused"):
            self.by_key.pop(rec["k"], None)
        else:
            self.by_key[rec["k"]] = rec


def intent_key(intent: str) -> str:
    """The journal's key for one intent: the whole of it, hashed -- the kind,
    the token or piece, the amount, the recipient and the caller's own job id.
    Never the content alone (two players paid the same 5 GOLD are two intents)."""
    if not intent or not intent.strip():
        raise PublishError("a transfer needs an intent: what it is for, unique to it (a job id)")
    return hashlib.sha256(intent.encode()).hexdigest()


class Publisher:
    """One address publishing inscriptions on one chain through Arcade V1.0."""

    def __init__(self, rpc: RpcClient, params: Params, key: Key, journal: str | os.PathLike,
                 rate: int = fees.MIN_FEE_PER_KB, say: Callable[[str], None] | None = None):
        self.rpc, self.params, self.key = rpc, params, key
        self.address = key.address(params)
        self.coins: Coins = NodeCoins(rpc, self.address)
        self.journal_home = Path(journal)
        self.transfers = TransferJournal(self.journal_home / "transfers.jsonl")
        self.rate = fees.rate_for(params, rate)
        self.say = say or (lambda s: None)

    # ---------------------------------------------------------------- one transaction
    def _send(self, unsigned: funding.Unsigned) -> str:
        sigs = [self.key.sign(bytes.fromhex(h)).hex() for h in unsigned.sighashes]
        raw = funding.assemble(unsigned, sigs, self.key.pubkey)
        txid = str(self.rpc.call("sendrawtransaction", raw))
        self.coins.note(unsigned, txid)
        return txid

    def _known(self, journal: "Journal", slot: str) -> str:
        """The transaction noted for `slot` before it was broadcast, when the chain knows it (in a block
        or waiting): a run stopped between the broadcast and the journal entry finds it here and sends
        nothing again. Asked by its own txid, so it works where no wallet history can be listed (a
        chain Arcade V1.0 borrows)."""
        prior = journal.data.get("sending", {}).get(slot, "")
        if prior and self._confirmations(prior) is not None:
            self.say(f"{slot}: already sent as {prior}")
            return prior
        return ""

    def _send_noted(self, journal: "Journal", slot: str, unsigned: funding.Unsigned) -> str:
        """Sign, note the txid in the journal, then broadcast (the txid is known before anything goes out)."""
        sigs = [self.key.sign(bytes.fromhex(h)).hex() for h in unsigned.sighashes]
        raw = funding.assemble(unsigned, sigs, self.key.pubkey)
        txid = _txid_of(raw)
        journal.data.setdefault("sending", {})[slot] = txid
        journal.save()
        self.rpc.call("sendrawtransaction", raw)
        self.coins.note(unsigned, txid)
        return txid

    def _confirmations(self, txid: str) -> int | None:
        """How deep a transaction is, None if the node has no record of it."""
        try:
            tx = self.rpc.call("getrawtransaction", txid, True)
        except RpcError:
            return None
        return int(tx.get("confirmations") or 0)

    def wait_for(self, txid: str, confirmations: int = SPLIT_CONFIRMATIONS,
                 timeout: float = 3600.0, poll: float = 5.0,
                 while_waiting: Callable[[], None] | None = None) -> None:
        """Until `txid` is `confirmations` deep. `while_waiting` is for a
        regtest, where nothing is mined unless the caller mines it."""
        t0 = time.time()
        while True:
            deep = self._confirmations(txid)
            if deep is None:
                raise PublishError(f"the node has lost {txid}: it was broadcast and is neither in "
                                   f"its mempool nor in a block. Nothing more has been sent.")
            if deep >= confirmations:
                return
            if time.time() - t0 > timeout:
                raise PublishError(f"{txid} has not been mined in {timeout:.0f} s; run again to resume")
            if while_waiting:
                while_waiting()
            time.sleep(poll)

    # ---------------------------------------------------------------- the inscription
    def inscribe(self, content: bytes, content_type: str = "", json_text: str = "", name: str = "",
                 while_waiting: Callable[[], None] | None = None) -> dict:
        """Put one file on the chain. Returns {id, txids, chunks, resumed}.

        Asked again with the same bytes it finishes what the journal says is
        unfinished and sends nothing twice; asked with a file already fully
        sent it answers the same ids and sends nothing.
        """
        if not content:
            raise PublishError("there is nothing to inscribe")
        digest = hashlib.sha256(content).hexdigest()
        journal = Journal(self.journal_home, digest)
        import mimetypes
        kind = (media.standard_type(content_type, name) or media.standard_type(mimetypes.guess_type(name)[0] or "")
                or "application/octet-stream")   # a .json name is a JSON file, not a blob (0.8.86's data modules)
        if not journal.data["tag"]:
            journal.data["tag"] = secrets.token_bytes(8).hex()
            journal.data["name"] = name
            journal.save()
        plan = inscribelib.plan(content, kind, json_text, inscription_id=bytes.fromhex(journal.data["tag"]))
        resumed = bool(journal.data["txids"] or journal.data["split"])
        if len(journal.data["txids"]) == plan.chunks:
            return {"id": journal.data["txids"][0], "txids": list(journal.data["txids"]),
                    "chunks": plan.chunks, "resumed": True}

        self.coins.watch()
        if plan.chunks == 1:
            txid = self._known(journal, "single")
            if not txid:
                outputs = payload_outputs(self.params, self.address, self.key.pubkey, plan.payloads[0])
                unsigned = build(self.params, self.address, self.coins.unspent(), outputs, self.rate, f"inscribe {name or kind}")
                txid = self._send_noted(journal, "single", unsigned)
            journal.data["txids"] = [txid]
            journal.save()
            self.say(f"inscribed {name or kind}: {txid}")
            return {"id": txid, "txids": [txid], "chunks": 1, "resumed": False}

        piece = inscribelib.piece_size(plan)
        if not journal.data["split"] or self._confirmations(journal.data["split"]) is None:
            known = self._known(journal, "split")
            if not known:
                split = build(self.params, self.address, self.coins.unspent(),
                              [(piece, p2pkh_script(self.address))] * plan.chunks, self.rate,
                              f"split into {plan.chunks} outputs, to inscribe {name or kind}")
                known = self._send_noted(journal, "split", split)
            journal.data["split"] = known
            journal.data["pieces"] = {}
            journal.save()
            self.say(f"split {name or kind} into {plan.chunks} pieces: {journal.data['split']}")
        self.wait_for(journal.data["split"], while_waiting=while_waiting)

        for n, body in enumerate(plan.payloads):
            if str(n) in journal.data["pieces"]:
                continue
            slot = f"piece {n} of {journal.data['split']}"
            known = self._known(journal, slot)
            if known:
                journal.data["pieces"][str(n)] = known
                journal.save()
                continue
            coin = {"txid": journal.data["split"], "vout": n, "value": piece, "address": self.address}
            outputs = payload_outputs(self.params, self.address, self.key.pubkey, body)
            what = f"piece {n + 1} of {plan.chunks} of {name or kind}"
            if getattr(self.params, "tx_time", False):
                # funding.build_one does not write a transaction time yet (Kotia): the same one-coin spend here.
                unsigned = build(self.params, self.address, [coin], outputs, self.rate, what)
            else:
                unsigned = funding.build_one(self.params, self.address, coin, outputs, self.rate, what)
            try:
                txid = self._send_noted(journal, slot, unsigned)
            except RpcError as exc:
                # The output is already spent: this piece went out in a run whose
                # journal entry never got written. Find it rather than pay again --
                # but only a spend that carries THIS piece. The arcade running on the
                # same key spends the split's outputs too (2026-10-19: its mesh
                # announcement took part 5's first coin, and that announcement was
                # filed as the piece, so the Doginal Frogs root never assembled).
                txid, spent = self._already_sent(journal.data["split"], n, body)
                if not txid and spent:
                    others = [c for c in self.coins.unspent() if c["txid"] != journal.data["split"]]
                    txid = self._send(build(self.params, self.address, others, outputs, self.rate,
                                            f"piece {n + 1} of {plan.chunks} of {name or kind}, "
                                            "its coin spent by another sender"))
                if not txid:
                    raise PublishError(f"piece {n + 1} could not be sent ({exc}); nothing further sent") from exc
            journal.data["pieces"][str(n)] = txid
            journal.save()
            self.say(f"piece {n + 1} of {plan.chunks}: {txid}")
        txids = [journal.data["pieces"][str(n)] for n in range(plan.chunks)]
        journal.data["txids"] = txids
        journal.save()
        return {"id": txids[0], "txids": txids, "chunks": plan.chunks, "resumed": resumed}

    def _already_sent(self, split: str, vout: int, body: bytes) -> tuple[str, bool]:
        """(the txid that spent output `vout` of the split carrying `body`, whether the output is spent).

        ("", True) is an output somebody else spent: the piece still has to go out, on another coin."""
        try:
            out = self.rpc.call("gettxout", split, vout, True)
        except RpcError:
            return "", False
        if out is not None:
            return "", False
        # Spent. The wallet has the address watch-only, so the spending transaction is in its list.
        try:
            for row in self.rpc.call("listtransactions", "*", 500, 0, True):
                txid = str(row.get("txid") or "")
                if not txid:
                    continue
                tx = self.rpc.call("getrawtransaction", txid, True)
                for vin in tx.get("vin", []):
                    if vin.get("txid") == split and int(vin.get("vout", -1)) == vout:
                        return (txid if self._carries(tx, body) else ""), True
        except RpcError:
            pass
        return "", True

    def _carries(self, tx: dict, body: bytes) -> bool:
        """Whether a transaction's data outputs say `body` (wrapped as payload_outputs wraps it)."""
        from arcade import tx as txlib
        want = P.AnyData(data=body).encode()
        try:
            outputs = txlib._parsed_outputs(tx, self.params)
            got = txlib.extract_payload(outputs, txlib.detect_class(outputs, self.params.marker), self.address)
        except Exception:                                  # noqa: BLE001 -- not ours, or not readable: not it
            return False
        return got[:len(want)] == want and not any(got[len(want):])

    # ---------------------------------------------------------------- transfers (D-195)
    def transfer_token(self, property_id: int, amount: int, to: str, intent: str, dry: bool = False) -> dict:
        """Send `amount` base units of a token this address holds: an Omni Simple Send."""
        return self.transfer(intent, tokenlib.send_payload(int(property_id), int(amount)), to, wrap=False,
                             what=f"send {amount} of token {property_id} to {to}", dry=dry)

    def grant_token(self, property_id: int, amount: int, to: str, intent: str, note: str = "",
                    dry: bool = False) -> dict:
        """Issue `amount` new base units of a managed token this address issued, to `to`."""
        return self.transfer(intent, tokenlib.grant_payload(int(property_id), int(amount), note), to, wrap=False,
                             what=f"grant {amount} of token {property_id} to {to}", dry=dry)

    def transfer_nft(self, inscription: str, to: str, intent: str, dry: bool = False) -> dict:
        """Hand an inscription to `to`: the arcade's Transfer, named by the creating txid."""
        try:
            txid = bytes.fromhex(inscription)
        except ValueError:
            txid = b""
        if len(txid) != 32:
            raise PublishError(f"{inscription!r} is not an inscription id (its creating txid, 64 hex digits)")
        return self.transfer(intent, inscriptionlib.Transfer(txid=txid).encode(), to, wrap=True,
                             what=f"send inscription {inscription[:16]} to {to}", dry=dry)

    def transfer(self, intent: str, body: bytes, to: str, wrap: bool, what: str, dry: bool = False) -> dict:
        """One payload to one recipient: built, read back, journaled, broadcast.

        The shape is the interface's (`/account/token/send`, `/account/nft/send`):
        the payload's outputs, then the recipient's dust LAST, which is the
        output the engine's reference rule resolves to; change back here. Paid
        from confirmed coins only. Before anything is journaled the signed
        transaction is read back with the index's own reader (`tx.extract`) and
        must say: this address sent it, `to` is the reference, these exact
        payload bytes, every input this address's own, a fee in bounds.

        Returns {txid, fee, what, resumed}. An intent asked for again returns
        what it sent the first time, and if the node has lost that transaction
        sends the very same bytes again -- never new ones.
        """
        key = intent_key(intent)
        rec = self.transfers.get(key)
        if rec:
            return self._resume(rec)
        try:
            version, _ = b58check_decode(to)
        except Exception:
            version = None
        if version != self.params.pubkeyhash_version:
            raise PublishError(f"{to!r} is not a {self.params.name} address that can be paid")
        if to == self.address:
            raise PublishError("that is this address's own; a transfer to itself moves nothing")
        payload = P.AnyData(data=body).encode() if wrap else body
        self.coins.watch()
        outputs = payload_outputs(self.params, self.address, self.key.pubkey, body, wrap)
        outputs.append((sendermod.OUTPUT_VALUE, p2pkh_script(to)))
        unsigned = build(self.params, self.address, self.coins.confirmed(), outputs, self.rate, what)
        sigs = [self.key.sign(bytes.fromhex(h)).hex() for h in unsigned.sighashes]
        raw = funding.assemble(unsigned, sigs, self.key.pubkey)
        fee = self._check(raw, unsigned, payload, to)
        txid = _txid_of(raw)
        out = {"txid": txid, "fee": fee, "what": what, "resumed": False}
        if dry:
            return {**out, "dry": True}
        self._send_journaled(key, intent, unsigned, raw, txid, to, what)
        return out

    def _send_journaled(self, key: str, intent: str, unsigned: funding.Unsigned, raw: str, txid: str,
                        to: str, what: str) -> None:
        """The journal line first (fsynced), then the broadcast."""
        self.transfers.write({"k": key, "intent": intent, "txid": txid, "raw": raw, "to": to,
                              "what": what, "at": time.time()})
        try:
            self.rpc.call("sendrawtransaction", raw)
        except RpcError as exc:
            # The node answered, and said no. Unless it already has this very
            # transaction (an "already in the mempool"), nothing went out: the
            # coins were confirmed and unspent a moment ago, so this is a
            # policy refusal, and the intent may be built again.
            if self._confirmations(txid) is None:
                self.transfers.write({"k": key, "txid": txid, "refused": f"{exc.code}: {exc.message}"[:300],
                                      "at": time.time()})
                raise PublishError(f"the node refused to {what}: {exc.message}. Nothing went out.") from exc
        self.coins.note(unsigned, txid)
        self.say(f"{what}: {txid}")

    def _resume(self, rec: dict) -> dict:
        """An intent already journaled: its transaction, or the same bytes again."""
        txid = rec["txid"]
        out = {"txid": txid, "fee": None, "what": rec.get("what", ""), "resumed": True}
        if self._confirmations(txid) is not None:
            return out
        # The node has no record of it: the run stopped between the journal and
        # the broadcast, or it fell out of the mempool. The same signed bytes go
        # out again -- the same inputs, so they can be taken at most once.
        try:
            self.rpc.call("sendrawtransaction", rec["raw"])
        except RpcError as exc:
            if self._confirmations(txid) is not None:
                return out
            # Its coins are gone some other way, or the node will not take it.
            # Whether anything was paid is now a question for a person: nothing
            # new is ever built for this intent.
            raise PublishError(f"{txid} was signed for this intent and the node will not take it again "
                               f"({exc.message}); nothing new was sent. A person must look.") from exc
        self.say(f"sent again, the same bytes: {txid}")
        return out

    def _check(self, raw: str, unsigned: funding.Unsigned, payload: bytes, to: str) -> int:
        """Read a signed transfer back the way the index will, before it goes
        anywhere. Returns its fee; raises if any of it is not what was meant."""
        from arcade import tx as txlib
        from arcade.script import OutputType
        decoded = self.rpc.call("decoderawtransaction", raw)
        mine = {(c["txid"], int(c["vout"])): c for c in unsigned.inputs}

        def lookup(txid: str, vout: int):
            coin = mine.get((txid, int(vout)))
            if coin is None or coin.get("address", self.address) != self.address:
                raise PublishError(f"input {txid}:{vout} is not one of {self.address}'s coins")
            return txlib.PrevOut(self.address, int(coin["value"]), OutputType.PUBKEYHASH)

        try:
            got = txlib.extract(decoded, 0, 0, self.params, lookup)
        except txlib.TxError as exc:
            raise PublishError(f"refusing to send: the transaction does not read back ({exc})") from exc
        if got is None:
            raise PublishError("refusing to send: the transaction carries no payload")
        problems = []
        if got.sender != self.address:
            problems.append(f"it reads as sent by {got.sender}")
        if got.reference != to:
            problems.append(f"it reads as paying {got.reference}, not {to}")
        if got.payload != payload:
            problems.append("its payload is not the one built")
        if not 0 < got.fee <= MAX_TRANSFER_FEE:
            problems.append(f"its fee is {got.fee / fees.COIN:.8f}")
        if len(decoded.get("vin", [])) != len(unsigned.inputs):
            problems.append("its inputs are not the coins chosen")
        if [v for a, v in got.outputs if a == to] != [sendermod.OUTPUT_VALUE]:
            problems.append(f"it does not pay {to} exactly one dust output")
        stray = sorted({a for a, _ in got.outputs if a not in (None, to, self.address, self.params.marker)})
        if stray:
            problems.append(f"it pays somebody else too: {', '.join(stray)}")
        if decoded.get("txid") != _txid_of(raw):
            problems.append("its txid is not its bytes'")
        if problems:
            raise PublishError("refusing to send: " + "; ".join(problems))
        return got.fee

    def split(self, count: int, value: int, intent: str, dry: bool = False) -> dict:
        """Turn confirmed coins into `count` outputs of `value` each, back to this
        address, so that many transfers can each take a confirmed coin of their
        own in one block. Journaled by intent like a transfer."""
        if not 1 <= count <= 500 or value < fees.dust_limit(self.params):
            raise PublishError("a split is 1 to 500 outputs of at least the dust limit each")
        key = intent_key(intent)
        rec = self.transfers.get(key)
        if rec:
            return self._resume(rec)
        self.coins.watch()
        unsigned = build(self.params, self.address, self.coins.confirmed(), [(value, p2pkh_script(self.address))] * count,
                         self.rate, f"split into {count} coins of {value / fees.COIN:.8f}")
        if unsigned.fee > MAX_TRANSFER_FEE * 10 or any(s != p2pkh_script(self.address) for _, s in unsigned.outputs):
            raise PublishError("refusing to send: the split pays somebody else or too much")
        raw = funding.assemble(unsigned, [self.key.sign(bytes.fromhex(h)).hex() for h in unsigned.sighashes],
                               self.key.pubkey)
        txid = _txid_of(raw)
        out = {"txid": txid, "fee": unsigned.fee, "what": unsigned.what, "resumed": False}
        if dry:
            return {**out, "dry": True}
        self._send_journaled(key, intent, unsigned, raw, txid, self.address, unsigned.what)
        return out


    def reserved(self) -> set[str]:
        """Splits an unfinished inscription is still waiting to spend: never swept."""
        held = set()
        for path in self.journal_home.glob("*.json"):
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if data.get("split") and not data.get("txids"):
                held.add(data["split"])
        return held

    def consolidate(self, below: int, intent: str, max_inputs: int = 200, min_inputs: int = 20,
                    dry: bool = False) -> dict | None:
        """Sweep this address's small confirmed coins (each under `below`) into
        one coin back to itself, so payouts are not funded from a handful of
        crumbs. Coins worth less than they cost to spend are left alone, and so
        is any coin of a split an unfinished inscription is waiting on. None when
        there are fewer than `min_inputs` to sweep. Journaled by intent."""
        key = intent_key(intent)
        rec = self.transfers.get(key)
        if rec:
            return self._resume(rec)
        self.coins.watch()
        worth = funding.price(1, [], self.rate, params=self.params) - funding.price(0, [], self.rate, params=self.params)   # what one more input costs
        skip = self.reserved()
        small = sorted((c for c in self.coins.confirmed()
                        if worth * 2 < c["value"] < below and c["txid"] not in skip),
                       key=lambda c: c["value"])[:max_inputs]
        if len(small) < min_inputs:
            return None
        total = sum(c["value"] for c in small)
        script = p2pkh_script(self.address)
        fee = funding.price(len(small), [(total, script)], self.rate, params=self.params)
        if fee > MAX_TRANSFER_FEE * 10 or total - fee < fees.dust_limit(self.params):
            raise PublishError(f"refusing to consolidate: {len(small)} coins would cost {fee / fees.COIN:.8f}")
        outs = [(total - fee, script)]
        ntime = funding.tx_time(self.params)
        raw_unsigned = build_raw_tx([(c["txid"], c["vout"]) for c in small], outs, ntime=ntime)
        hashes = [funding.sighash(small, outs, n, script, ntime=ntime).hex() for n in range(len(small))]
        unsigned = funding.Unsigned(raw=raw_unsigned, inputs=small, outputs=outs, sighashes=hashes,
                                    fee=fee, change=0, what=f"consolidate {len(small)} small coins", ntime=ntime)
        raw = funding.assemble(unsigned, [self.key.sign(bytes.fromhex(h)).hex() for h in hashes], self.key.pubkey)
        decoded = self.rpc.call("decoderawtransaction", raw)
        if len(decoded.get("vin", [])) != len(small) or len(decoded.get("vout", [])) != 1 \
                or decoded["vout"][0]["scriptPubKey"]["hex"] != script.hex():
            raise PublishError("refusing to send: the consolidation does not read back as one coin to this address")
        txid = _txid_of(raw)
        out = {"txid": txid, "fee": fee, "what": unsigned.what, "inputs": len(small), "value": total - fee,
               "resumed": False}
        if dry:
            return {**out, "dry": True}
        self._send_journaled(key, intent, unsigned, raw, txid, self.address, unsigned.what)
        return out


def _txid_of(raw: str) -> str:
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()


# ------------------------------------------------------------------------- the command
