# arcade-publish

Inscribe files, and send tokens and inscriptions, with **your own key**, through
[Arcade V1.0](https://github.com/martinseeger2002/arcade-v1) running on the same computer, on any chain it keeps.

The key never leaves this program: every transaction is built and signed here and handed to V1.0 to broadcast.
V1.0's own wallet is never used. A journal (keyed by each file's sha256) records what has gone out, so a run
that stops picks up where it stopped and nothing is paid for twice.

## Install

    pip install git+https://github.com/martinseeger2002/arcade-publish-v1

or from a clone: `pip install .` (Python 3.10+; needs `cryptography`, `requests`, `pynacl`).

## Use

Make a key (64 hex digits, readable by you only) and see its address:

    python3 -c "import secrets; print(secrets.token_hex(32))" > publish.key && chmod 600 publish.key
    arcade-publish --key publish.key --whoami

Send that address some coins on the chain you want, then:

    arcade-publish --key publish.key game.js                         # on V1.0's home chain
    arcade-publish --key publish.key --chain doge cover.png --json '{"name": "my game"}'
    arcade-publish --key publish.key --intent "job 41" --send-token 26 30 <address>
    arcade-publish --key publish.key --intent "job 42" --send-nft <inscription id> <address>
    arcade-publish --key publish.key --intent "split 1" --split 20 5000000   # 20 coins, for many transfers

Asked again with the same file, it finishes what is unfinished and sends nothing twice. A transfer is
named by `--intent` (unique to it): asked again, it is paid once. `--dry` builds and checks a transfer
without sending it.

## Finding Arcade V1.0

| Option | Default |
|---|---|
| `--arcade-url` | `$ARCADE_URL`, else `http://127.0.0.1:8420` (V1.0's web port) |
| `--arcade-home` | `$ARCADE_HOME`, else `/var/lib/arcade` (a system install), else `~/.local/share/arcade` (Linux) or `%LOCALAPPDATA%\arcade` (Windows) |
| `--cookie` | `<arcade home>/.cookie` (V1.0 writes a new one on every start) |
| `--chain` | V1.0's home chain |
| `--journal` | `~/.arcade-publish/<chain>` |

## Chains

Any chain V1.0 keeps or borrows: `peptest`, `pep`, `doge`, `ltc`, `ltctest`, `dgb`, `dgbtest`, `kot`, `flop`,
`wjk`, `bel`, `lky`, `btc`, `shic`, `jkc`. Borrowed chains (not installed on that arcade, or still syncing)
need an Arcade V1.0 with borrowed-chain RPC (arcade-v1 PR #94): coins then come from a lender's address
index, each checked against its block, and transactions go out through the lenders.

- Addresses are legacy P2PKH, with each chain's own version byte (the same key gives a different address per chain).
- The fee rate and dust limit come from V1.0 (`tx.fee`). From arcade-v1 PR #94 on they are V1.0's own wallet's for
  that chain; older V1.0 builds give one rate for every chain.
- Small bodies go in an OP_RETURN (Class C); bigger ones use the Class B marker and bare-multisig outputs, 0.01 coin
  each, as V1.0 builds them. On a chain whose coin is worth a lot (Bitcoin) that value adds up: check
  `--whoami` and start small.
- Kotia transactions carry the transaction time Kotia needs.

## How it talks to V1.0

V1.0 answers Core's JSON-RPC for each chain it keeps at `POST /chain/<key>` (cookie as Basic auth, this computer
only): `listunspent`, `sendrawtransaction`, `getrawtransaction`, `gettxout`, `decoderawtransaction`,
`listtransactions`, `validateaddress`. Fee rates come from V1.0's own `/rpc` (`tx.fee`).

## Tests

    python3 -m unittest discover -s tests

Offline: every chain's address versions against V1.0's, signed inscriptions on every chain, Class B, Kotia's
transaction time. Nothing is sent.

## Where the code comes from

`arcade/` is the transaction, encoding and inscription code of the original Dogecoin Arcade
([dogecoin-arcade](https://github.com/martinseeger2002/dogecoin-arcade)), copied unchanged except for comments.
`v1publish/` is its publisher, pointed at Arcade V1.0 and made chain-aware for every chain V1.0 keeps.
