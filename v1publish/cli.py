"""`arcade-publish`: inscribe files and make transfers with your own key, through Arcade V1.0.

    arcade-publish --key publish.key --whoami
    arcade-publish --key publish.key --chain doge game.js --json '{"name": "my game"}'
    arcade-publish --key publish.key --intent "job 41" --send-token 26 30 <address>
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

import requests

from arcade import fees, funding
from arcade import inscriptions as inscriptionlib
from arcade import tokens as tokenlib
from arcade.config import RpcCredentials
from arcade.rpc import RpcClient, RpcError

from . import chains
from .publisher import Key, Publisher, PublishError

DEFAULT_URL = "http://127.0.0.1:8420"


@dataclasses.dataclass(frozen=True)
class V1Credentials(RpcCredentials):
    """V1.0's Core RPC for one chain: POST <arcade>/chain/<key> with the cookie."""

    base: str = DEFAULT_URL
    chain: str = ""

    @property
    def url(self) -> str:
        return f"{self.base.rstrip('/')}/chain/{self.chain}"

    def __repr__(self) -> str:  # never show the cookie
        return f"V1Credentials(url={self.url!r}, password=***)"


def default_home() -> Path:
    """Where Arcade V1.0 keeps its data (and its .cookie), as V1.0 itself picks it."""
    if os.environ.get("ARCADE_HOME"):
        return Path(os.environ["ARCADE_HOME"])
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "arcade"
    system = Path("/var/lib/arcade")
    if (system / ".cookie").exists():
        return system
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "arcade"


def read_cookie(path: Path) -> tuple[str, str]:
    try:
        user, _, password = path.read_text().strip().partition(":")
    except OSError as exc:
        raise PublishError(f"cannot read Arcade V1.0's cookie at {path} ({exc.strerror}): is V1.0 running, "
                           f"and is this the right home (--arcade-home, ARCADE_HOME)?") from None
    return user, password


def v1_call(base: str, auth: tuple[str, str], method: str, params: dict) -> dict:
    """One call to V1.0's own JSON-RPC (/rpc)."""
    try:
        r = requests.post(f"{base.rstrip('/')}/rpc", auth=auth, timeout=30,
                          json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    except requests.RequestException as exc:
        raise PublishError(f"cannot reach Arcade V1.0 at {base} ({exc.__class__.__name__}); "
                           f"is it running, and on this port (--arcade-url, ARCADE_URL)?") from None
    if r.status_code == 401:
        raise PublishError(f"Arcade V1.0 at {base} refused the cookie: it changes on every start; is this "
                           f"V1.0's home (--arcade-home)?")
    body = r.json()
    if body.get("error"):
        raise PublishError(f"Arcade V1.0: {body['error'].get('message', body['error'])}")
    return body["result"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arcade-publish", description=__doc__.split("\n\n")[0])
    ap.add_argument("--key", required=True, help="file holding the secret as 64 hex digits (keep it 0600)")
    ap.add_argument("--chain", default="", help=f"V1.0 chain key (default: V1.0's home chain): {', '.join(chains.KEYS)}")
    ap.add_argument("--arcade-url", default=os.environ.get("ARCADE_URL", DEFAULT_URL),
                    help=f"V1.0's local web port (default $ARCADE_URL or {DEFAULT_URL})")
    ap.add_argument("--arcade-home", default="", help="V1.0's data folder, for its .cookie (default: as V1.0 picks it)")
    ap.add_argument("--cookie", default="", help="V1.0's .cookie file itself (instead of --arcade-home)")
    ap.add_argument("--journal", default=os.environ.get("ARCADE_PUBLISH_JOURNAL", str(Path.home() / ".arcade-publish")),
                    help="where what has gone out is written (default ~/.arcade-publish)")
    ap.add_argument("--json", default="", help="the JSON beside the file")
    ap.add_argument("--name", default="", help="the inscription's name (default: the file's)")
    ap.add_argument("--type", default="", help="content type (default: from the file name)")
    ap.add_argument("--whoami", action="store_true", help="say the address and its balance on the chain, send nothing")
    ap.add_argument("--send-token", nargs=3, metavar=("PROPERTY", "UNITS", "TO"),
                    help="send base units of a token this address holds")
    ap.add_argument("--grant-token", nargs=3, metavar=("PROPERTY", "UNITS", "TO"),
                    help="grant new base units of a managed token this address issued")
    ap.add_argument("--send-nft", nargs=2, metavar=("INSCRIPTION", "TO"), help="hand an inscription on")
    ap.add_argument("--split", nargs=2, type=int, metavar=("COUNT", "SATS"),
                    help="make COUNT coins of SATS each, so transfers each have a confirmed coin")
    ap.add_argument("--intent", default="",
                    help="what a transfer is for, unique to it (e.g. a job id): asked again, it is paid once")
    ap.add_argument("--dry", action="store_true", help="build and check a transfer, send nothing")
    ap.add_argument("file", nargs="?")
    args = ap.parse_args(argv)
    try:
        cookie = Path(args.cookie) if args.cookie else (Path(args.arcade_home) if args.arcade_home else default_home()) / ".cookie"
        user, password = read_cookie(cookie)
        fee = v1_call(args.arcade_url, (user, password), "tx.fee", {"chain": args.chain} if args.chain else {})
        key_name = args.chain or fee["chain"]
        params = chains.for_chain(key_name, fee["fee_per_kb"], fee["dust"])
        key = Key.from_file(args.key)
        creds = V1Credentials(host="127.0.0.1", port=0, user=user, password=password,
                              base=args.arcade_url, chain=key_name)
        journal = Path(args.journal) / key_name
        with RpcClient(creds) as rpc:
            pub = Publisher(rpc, params, key, journal, say=lambda s: print("   " + s, flush=True))
            if args.send_token or args.grant_token or args.send_nft or args.split:
                if args.send_token:
                    pid, units, to = args.send_token
                    out = pub.transfer_token(int(pid), int(units), to, args.intent, dry=args.dry)
                elif args.grant_token:
                    pid, units, to = args.grant_token
                    out = pub.grant_token(int(pid), int(units), to, args.intent, dry=args.dry)
                elif args.send_nft:
                    out = pub.transfer_nft(args.send_nft[0], args.send_nft[1], args.intent, dry=args.dry)
                else:
                    out = pub.split(args.split[0], args.split[1], args.intent, dry=args.dry)
                print(json.dumps(out, indent=1))
                return 0
            if args.whoami or not args.file:
                coins = pub.coins.unspent()
                print(json.dumps({"address": pub.address, "chain": key_name, "label": params.label,
                                  "balance": sum(c["value"] for c in coins) / fees.COIN, "coins": len(coins),
                                  "fee_per_kb": params.min_fee_per_kb, "dust": params.dust_limit}, indent=1))
                return 0
            data = Path(args.file).read_bytes()
            out = pub.inscribe(data, args.type, args.json, args.name or os.path.basename(args.file))
            print(json.dumps({**out, "chain": key_name}, indent=1))
            return 0
    except (PublishError, ValueError, funding.FundingError, inscriptionlib.InscriptionError,
            tokenlib.TokenError, RpcError) as exc:
        print(f"arcade-publish: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
