"""Every coin's value the ord walk has seen, kept on disk beside the index (2026-10-25: "Remember + parallel
asks").

The walk needs the value of each coin a transaction spends ahead of an inscribed one (the koinu an inscription sits on
is counted across the inputs). It kept the last 500,000 values in memory, only those of 1 coin or less, and lost them
all at every start, so it asked a Core again for transactions it had walked long before -- each a random read on the
lender's disk (2026-10-25: a test arcade, borrowing Dogecoin from a small test machine's hard disk, 40-250 ms a transaction, up to ~700 a
2023 block, 0.02 blocks a second; more than 99% of them coins made after the index's first block). Kept here, a coin
the walk has seen is never asked again: only coins older than the index's first block are.

A value is the transaction's own: the key is its id and output number, and nothing goes in that was not read from
bytes that hash to that id (rawchain.read_tx / read_block, ord_notes.decode). So the file is never wrong, only short --
a reorg, a crash, a value let go of early just mean asking a Core again. Spent coins are let go of; a coin spent before
the backfill brought it in stays (harmless: its value is still its value).

`from` is the first block the walk filed here; the blocks before it (walked before this file existed) are brought in
once by the lanes, a chunk at a time (DoginalIndex._values_wanted), and each chunk brought in is marked done.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

#: Bytes of the transaction id in a key (96 bits: no two of a chain's transactions share them).
KEY_TX = 12
#: Keys asked in one query.
QUERY_MAX = 500


def key(txid: str, vout: int) -> bytes:
    return bytes.fromhex(txid)[:KEY_TX] + int(vout).to_bytes(4, "little")


class Values:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS v (k BLOB PRIMARY KEY, val INTEGER NOT NULL) WITHOUT ROWID")
        self._db.execute("CREATE TABLE IF NOT EXISTS done (c INTEGER PRIMARY KEY)")
        self._db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER)")
        self._done: set[int] | None = None

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def get(self, k: bytes) -> int | None:
        with self._lock:
            row = self._db.execute("SELECT val FROM v WHERE k=?", (k,)).fetchone()
        return row[0] if row else None

    def get_many(self, keys: list[bytes]) -> dict[bytes, int]:
        out: dict[bytes, int] = {}
        with self._lock:
            for at in range(0, len(keys), QUERY_MAX):
                part = keys[at:at + QUERY_MAX]
                out.update(self._db.execute(f"SELECT k, val FROM v WHERE k IN ({','.join('?' * len(part))})",
                                            part).fetchall())
        return out

    def put(self, outs: list[tuple[bytes, int]], spent: list[bytes] = ()) -> None:
        """A block's (or a fetched transaction's) outputs in, the coins it spends out, at once."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                if outs:
                    self._db.executemany("INSERT OR REPLACE INTO v VALUES (?,?)", outs)
                if spent:
                    self._db.executemany("DELETE FROM v WHERE k=?", [(k,) for k in spent])
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def block(self, txs, h: int) -> None:
        """Every output of a block the walk filed, every coin it spends gone; the first such block is `from`."""
        outs, spent = [], []
        for tx in txs:
            outs += [(key(tx.txid, n), v) for n, (v, _s) in enumerate(tx.vout)]
            spent += [key(i["txid"], i["vout"]) for i in tx.vin if i["vout"] != -1]
        self.put(outs, spent)
        if self.start() is None:
            self.set_start(h)

    def start(self) -> int | None:
        with self._lock:
            row = self._db.execute("SELECT v FROM meta WHERE k='from'").fetchone()
        return row[0] if row else None

    def set_start(self, h: int) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO meta VALUES ('from', ?)", (int(h),))

    def done(self) -> set[int]:
        if self._done is None:
            with self._lock:
                self._done = {r[0] for r in self._db.execute("SELECT c FROM done")}
        return self._done

    def mark_done(self, c: int) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO done VALUES (?)", (int(c),))
        self.done().add(int(c))

    def size(self) -> int:
        total = 0
        for tail in ("", "-wal"):
            try:
                total += Path(str(self.path) + tail).stat().st_size
            except FileNotFoundError:
                pass
        return total
