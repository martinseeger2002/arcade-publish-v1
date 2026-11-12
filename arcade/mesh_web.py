"""The .mesh web (2026-10-26: "I want to use .mesh DNS protocol. For the Meshtastic ... a simple 'web' browser.
Whichever wallet holds the name should be able to inscribe a companion to the name that displays a webpage designed
specifically for the Meshtastic network and the T deck in mind. It should work just like original web like in 1990").

A .mesh NAME is an ordinary "p":"dns" name (ord_rules.NAME_RULES, the spec reading) on Pepecoin mainnet. Its PAGE is a
JSON inscription of its own:

    {"p": "mesh", "name": "me-seeks.mesh", "pages": {"/": "# Hello\\n...", "/about": "..."}}

A page counts when the address it was inscribed to (its reveal's first output) holds the name's inscription now; of
those, the newest wins (the operator chose "Latest by the holder"). Sell the name and the old holder's pages stop counting
until the new holder inscribes one.

Each page is MESHTEXT: plain UTF-8 lines in the spirit of 1990s hypertext (Gemini's text format):

    # Heading / ## Sub heading / ### Small heading
    * a list item
    > a quote
    => name.mesh/path A link       (one per line; "=> /path Label" is a page of the same site)
    ```  ... preformatted (ASCII art) ...  ```
    anything else: a paragraph line

    ![A picture](inscription id)   a picture: any image inscription (2026-10-26: "small size images on .mesh ...
                                   like the old school Internet ... load from the top to the bottom")

A whole site is at most SITE_MAX bytes: one 16-part LoRa message, so every page also loads by radio. A picture is its own
inscription, any size; a T-Deck gets it as a MESH PICTURE (arcade/mesh_picture.py): at most 300 x 200, 16 colours, rows
in bands that each fill about one LoRa part, so it draws from the top down as the parts come in.

SITES ON ANY NAME (2026-10-26: "When it's opened on the PWA or website it should be able to explore all p:dns
names. DNS names other than .mesh should not be limited like the .mesh pages"): the same record, on whichever chain the
name lives, for any p:dns name. Not .mesh, it is read in a browser only, so it is not capped to a LoRa message (the
indexer finds a record of up to RECORD_MAX bytes) and a page may be, besides MeshText:

    {"html": "<!doctype html>..."}     a page of HTML, run sandboxed like an inscription
    {"id": "<inscription id>"}         another inscription (an HTML page, a picture, a game): a site of any size
"""
from __future__ import annotations

import hashlib
import json
import re

from . import ord_rules

#: The chain .mesh names and pages are read on.
NET = "main"
ENDING = ".mesh"
#: A .mesh site's whole inscription: one 16-part LoRa message (PROTOCOL.md: parts of 195 bytes) less the answer's own
#: fields.
SITE_MAX = 3000
#: Any other name's record: as big as the indexer reads a JSON "p" from (ord_rules.PROTOCOL_MAX); its pages may be
#: inscriptions of their own, so the site itself has no size.
RECORD_MAX = ord_rules.PROTOCOL_MAX
#: An inscription id, as a page or a picture names one.
INSCRIPTION = re.compile(r"^[0-9a-f]{64}i\d{1,6}$")
#: A picture line of MeshText.
PICTURE_LINE = re.compile(r"^!\[([^\]]*)\]\(\s*([0-9a-fA-F]{64}[iI]\d{1,6})\s*\)\s*$")
#: Paths: "/" and "/word/word", short, lowercase letters, digits, - _ .
PATH = re.compile(r"^/(?:[a-z0-9._-]{1,32}(?:/[a-z0-9._-]{1,32}){0,3})?$")
PATHS_MAX = 24
#: Pages looked at, newest first, when a name is resolved or the directory drawn.
SCAN = 400


class MeshError(ValueError):
    pass


def name_of(raw: str) -> str | None:
    """A .mesh name as the spec reading makes it, or None when it is not one."""
    made = ord_rules.normalise("spec", "json", str(raw or "").strip())
    return made if made and made.endswith(ENDING) else None


def site_name(raw: str) -> str | None:
    """Any p:dns name a site may be made for: the spec reading's, else the JSON reading's (an operator's registrar sells
    names the spec leaves out); never a block map. None when it is no name."""
    raw = str(raw or "").strip()
    made = ord_rules.normalise("spec", "json", raw) or ord_rules.normalise("json", "json", raw)
    if not made or "/" in made or ord_rules.is_block_map(made.rpartition(".")[2]):
        return None
    return made


def is_mesh(name: str | None) -> bool:
    return bool(name) and str(name).endswith(ENDING)


def page_kind(value) -> tuple[str, str]:
    """("text", MeshText) | ("html", HTML) | ("id", inscription id) for a page's value; ("", "") when it is none."""
    if isinstance(value, str):
        return "text", value
    if isinstance(value, dict):
        if isinstance(value.get("html"), str):
            return "html", value["html"]
        iid = str(value.get("id") or "").strip().lower()
        if INSCRIPTION.match(iid):
            return "id", iid
    return "", ""


def split_address(address: str, any_name: bool = False) -> tuple[str | None, str]:
    """ "me-seeks.mesh/about" -> ("me-seeks.mesh", "/about"); a bare name is its "/". `any_name`: every p:dns name
    (site_name), not only .mesh."""
    s = str(address or "").strip()
    if s.lower().startswith("mesh://"):
        s = s[7:]
    name, slash, path = s.partition("/")
    path = "/" + path.strip("/") if slash else "/"
    return (site_name(name) if any_name else name_of(name)), path.lower()


def parse(body: bytes) -> dict | None:
    """A page inscription's {"name", "pages"}, or None when the body is not one that counts. A .mesh site: at most
    SITE_MAX bytes, MeshText pages only. Any other name's: at most RECORD_MAX, a page MeshText, {"html"} or {"id"}."""
    if not body or len(body) > RECORD_MAX:
        return None
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("p") != "mesh" or not isinstance(value.get("pages"), dict):
        return None
    name = site_name(value.get("name"))
    if not name or (is_mesh(name) and len(body) > SITE_MAX):
        return None
    pages = {}
    for path, page in list(value["pages"].items())[:PATHS_MAX]:
        kind, got = page_kind(page)
        if not isinstance(path, str) or not PATH.match(path.lower()) or not kind or (is_mesh(name) and kind != "text"):
            continue
        pages[path.lower()] = got if kind == "text" else {kind: got}
    if not pages:
        return None
    return {"name": name, "pages": pages}


def make(name: str, pages: dict) -> bytes:
    """The bytes of a page inscription (Creator -> Names -> Publish a site), compact, refused when it would not count.
    A page is MeshText, or (not .mesh) {"html": ...} or {"id": inscription id}."""
    made = site_name(name)
    if not made:
        raise MeshError("not a name: label.ending, like yours.mesh or yours.pepe")
    clean = {}
    for path, page in pages.items():
        p = "/" + str(path or "").strip().strip("/").lower() if str(path or "").strip("/") else "/"
        if not PATH.match(p):
            raise MeshError(f"{path!r} is not a path: / and short words of a-z 0-9 . _ - between slashes")
        kind, value = page_kind(page)
        if not kind:
            raise MeshError(f'{p}: a page is MeshText, {{"html": ...}} or {{"id": an inscription id}}')
        if is_mesh(made) and kind != "text":
            raise MeshError(f"{p}: a .mesh page is MeshText, so a T-Deck can show it (pictures go in it as ![...](id))")
        value = value.replace("\r\n", "\n")
        clean[p] = value if kind == "text" else {kind: value}
    if len(clean) > PATHS_MAX:
        raise MeshError(f"at most {PATHS_MAX} pages")
    if "/" not in clean:
        raise MeshError("a site needs its front page, /")
    body = json.dumps({"p": "mesh", "name": made, "pages": clean}, ensure_ascii=False, separators=(",", ":")).encode()
    if is_mesh(made) and len(body) > SITE_MAX:
        raise MeshError(f"{len(body):,} bytes: a .mesh site is at most {SITE_MAX:,}, so it loads over LoRa too "
                        f"(pictures are inscriptions of their own: they do not count)")
    if len(body) > RECORD_MAX:
        raise MeshError(f"{len(body):,} bytes: a site's record is at most {RECORD_MAX:,} -- put big pages in "
                        f"inscriptions of their own and name them here")
    if parse(body) is None:
        raise MeshError("that would not read back as a page")
    return body


def title_of(page) -> str:
    """A page's first heading, else its first line: what the directory and the browser's title show. An HTML page's
    <title>; an inscription's: none."""
    kind, text = page_kind(page)
    if kind == "html":
        found = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        return re.sub(r"\s+", " ", found.group(1)).strip()[:80] if found else ""
    if kind != "text":
        return ""
    first = ""
    for line in str(text).splitlines():
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip()[:80]
        if s and not first and not s.startswith(("=>", "```", "![")):
            first = s
    return first[:80]


def links_of(text: str) -> list[tuple[str, str]]:
    """(target, label) of each "=>" line, in order."""
    out, pre = [], False
    for line in str(text).splitlines():
        if line.startswith("```"):
            pre = not pre
            continue
        if not pre and line.startswith("=>"):
            parts = line[2:].strip().split(None, 1)
            if parts:
                out.append((parts[0], parts[1].strip() if len(parts) > 1 else parts[0]))
    return out


def pictures_of(text: str) -> list[tuple[str, str]]:
    """(inscription id, alt text) of each picture line, in order."""
    out, pre = [], False
    for line in str(text).splitlines():
        if line.startswith("```"):
            pre = not pre
            continue
        found = None if pre else PICTURE_LINE.match(line.strip())
        if found:
            out.append((found.group(2).lower(), found.group(1).strip()))
    return out


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
