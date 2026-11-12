"""Every chain Arcade V1.0 keeps, by V1.0's chain key, as the publisher's `Params`.

Address versions are Arcade V1.0's (crates/arcade-chain/src/params.rs) and are checked against the
original arcade's where it had the chain (tests/test_chains.py). The fee rate and dust limit are not
taken from here: `for_chain` asks the running V1.0 (`tx.fee`), so a transaction is priced exactly as
V1.0 prices its own.

Class B (bare-multisig data outputs) is on for every chain: V1.0 reads it on all of them. The original
arcade had it off on Litecoin and Kotia (a product choice there, not a network rule).
"""

from __future__ import annotations

import dataclasses

from arcade import config as C
from arcade.config import Params

_BASE: dict[str, Params] = {
    "peptest": C.TESTNET,
    "pep": C.MAINNET,
    "doge": C.DOGECOIN,
    "ltc": C.LITECOIN,
    "ltctest": C.LITECOIN_TESTNET,
    "dgb": C.DIGIBYTE,
    "dgbtest": C.DIGIBYTE_TESTNET,
    "kot": C.KOTIA,
    "flop": C.FLOPCOIN,
    "wjk": C.WOJAKCOIN,
    "bel": C.BELLSCOIN,
    "lky": C.LUCKYCOIN,
    # Chains Arcade V1.0 added after the original arcade: its versions, on the closest original shape.
    "btc": dataclasses.replace(C.LITECOIN, name="btc", coin="BTC", label="Bitcoin", pubkeyhash_version=0,
                               scripthash_version=5, other_pubkeyhash_version=None, bech32_hrp="bc", mweb=False,
                               genesis="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
    "shic": dataclasses.replace(C.DOGECOIN, name="shic", coin="SHIC", label="Shibacoin", pubkeyhash_version=63,
                                scripthash_version=22, other_pubkeyhash_version=None, auxpow_chain_id=74,
                                genesis="ff271edcc83f7d71e7a4e4b0a43b386a188e1470a28671cdbdc47e900118ac7f"),
    "jkc": dataclasses.replace(C.LITECOIN, name="jkc", coin="JKC", label="Junkcoin", pubkeyhash_version=16,
                               scripthash_version=5, other_pubkeyhash_version=None, bech32_hrp="jc"),
}

KEYS = tuple(_BASE)


def params(key: str) -> Params:
    """The chain `key` names, Class B on, fees not yet set (see `for_chain`)."""
    try:
        base = _BASE[key]
    except KeyError:
        raise ValueError(f"unknown chain {key!r}; Arcade V1.0's chains are: {', '.join(KEYS)}") from None
    return dataclasses.replace(base, class_b=True)


def for_chain(key: str, fee_per_kb: int, dust: int) -> Params:
    """The chain `key` names, priced as the running V1.0 prices it (its `tx.fee` answer)."""
    return dataclasses.replace(params(key), min_fee_per_kb=int(fee_per_kb), dust_limit=int(dust))
