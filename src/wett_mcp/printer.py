"""Printing over IPP: a minimal IPP/1.1 client (RFC 8010/8011) for one driverless printer, plus the
document preparation the print tool needs (format sniffing, page counting, text to PDF)."""

import asyncio
import base64
import binascii
import hashlib
import re
import struct
import urllib.parse
import zlib
from typing import Any

import httpx
from mcp.server.fastmcp.exceptions import ToolError

# Delimiter and value tags (RFC 8010 §3.5).
OPERATION, JOB, END, PRINTER = 0x01, 0x02, 0x03, 0x04
INTEGER, BOOLEAN, ENUM = 0x21, 0x22, 0x23
RESOLUTION, RANGE, BEGIN_COLLECTION, TEXT_LANG, NAME_LANG, END_COLLECTION = 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
TEXT, NAME, KEYWORD, URI, CHARSET, LANGUAGE, MIME, MEMBER_NAME = 0x41, 0x42, 0x44, 0x45, 0x47, 0x48, 0x49, 0x4A

PRINT_JOB, GET_JOBS, GET_PRINTER_ATTRIBUTES = 0x0002, 0x000A, 0x000B
BUSY = 0x0507  # server-error-busy

STATUS = {
    0x0400: "client-error-bad-request", 0x0401: "client-error-forbidden",
    0x0402: "client-error-not-authenticated", 0x0403: "client-error-not-authorized",
    0x0404: "client-error-not-possible", 0x0405: "client-error-timeout", 0x0406: "client-error-not-found",
    0x0408: "client-error-request-entity-too-large", 0x040A: "client-error-document-format-not-supported",
    0x040B: "client-error-attributes-or-values-not-supported", 0x040E: "client-error-conflicting-attributes",
    0x0411: "client-error-document-format-error", 0x0500: "server-error-internal-error",
    0x0501: "server-error-operation-not-supported", 0x0502: "server-error-service-unavailable",
    0x0503: "server-error-version-not-supported", 0x0504: "server-error-device-error",
    0x0505: "server-error-temporary-error", 0x0506: "server-error-not-accepting-jobs", 0x0507: "server-error-busy",
}
PRINTER_STATE = {3: "idle", 4: "processing", 5: "stopped"}
JOB_STATE = {3: "pending", 4: "pending-held", 5: "processing", 6: "processing-stopped", 7: "canceled",
             8: "aborted", 9: "completed"}

USER = "wett-mcp"
PAPER = {"letter": "na_letter_8.5x11in", "legal": "na_legal_8.5x14in", "a4": "iso_a4_210x297mm",
         "a5": "iso_a5_148x210mm", "a6": "iso_a6_105x148mm", "4x6": "na_index-4x6_4x6in",
         "5x7": "na_5x7_5x7in"}
_MEDIA_SIZE = re.compile(r"_(\d+(?:\.\d+)?)x(\d+(?:\.\d+)?)(mm|in)$")
_PWG_MEDIA = re.compile(r"^[a-z0-9]+_[a-z0-9.-]+_\d+(?:\.\d+)?x\d+(?:\.\d+)?(?:mm|in)$")


# --- IPP encoding -------------------------------------------------------------------------------------

def _value(tag: int, value: Any) -> bytes:
    if tag in (INTEGER, ENUM):
        return struct.pack(">i", value)
    if tag == BOOLEAN:
        return bytes([1 if value else 0])
    if tag == RANGE:
        return struct.pack(">ii", *value)
    return value.encode()


def encode(operation: int, request_id: int, groups: list[tuple[int, list[tuple[int, str, Any]]]]) -> bytes:
    """An IPP/1.1 request: groups of (value tag, name, value or list of values)."""
    out = bytearray(struct.pack(">BBHI", 1, 1, operation, request_id))
    for group, attrs in groups:
        out.append(group)
        for tag, name, values in attrs:
            for i, v in enumerate(values if isinstance(values, list) else [values]):
                n = name.encode() if i == 0 else b""
                data = _value(tag, v)
                out += struct.pack(">BH", tag, len(n)) + n + struct.pack(">H", len(data)) + data
    out.append(END)
    return bytes(out)


class Response:
    """A decoded IPP message. `status` is the operation id in a request; `data` follows the attributes."""

    def __init__(self, status: int, request_id: int, groups: list[tuple[int, dict[str, list]]], data: bytes = b""):
        self.status, self.request_id, self.groups, self.data = status, request_id, groups, data

    def group(self, tag: int) -> list[dict[str, list]]:
        return [attrs for t, attrs in self.groups if t == tag]

    def merged(self, tag: int) -> dict[str, list]:
        out: dict[str, list] = {}
        for attrs in self.group(tag):
            out.update(attrs)
        return out


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated IPP message")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def attribute(self) -> tuple[int, str, bytes]:
        tag = self.u8()
        name = self.take(self.u16()).decode()
        return tag, name, self.take(self.u16())

    def peek(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated IPP message")
        return self.data[self.pos]


def _decode_value(tag: int, raw: bytes) -> Any:
    if tag in (INTEGER, ENUM):
        return struct.unpack(">i", raw)[0]
    if tag == BOOLEAN:
        return raw != b"\0"
    if tag == RANGE:
        return list(struct.unpack(">ii", raw))
    if tag == RESOLUTION:
        x, y, units = struct.unpack(">iib", raw)
        return f"{x}x{y}{'dpi' if units == 3 else 'dpcm'}"
    if tag in (TEXT_LANG, NAME_LANG):
        lang_len = struct.unpack(">H", raw[:2])[0]
        return raw[4 + lang_len:].decode(errors="replace")
    if 0x10 <= tag <= 0x1F:  # out-of-band: unsupported, unknown, no-value
        return None
    if tag >= 0x40 or tag == 0x30:  # strings; octetString holds text in practice (printer-supply)
        return raw.decode(errors="replace")
    return raw.hex()  # dateTime


def _decode_collection(r: _Reader) -> dict[str, Any]:
    members: dict[str, list] = {}
    current = None
    while True:
        tag, _, raw = r.attribute()
        if tag == END_COLLECTION:
            return {k: v[0] if len(v) == 1 else v for k, v in members.items()}
        if tag == MEMBER_NAME:
            current = members.setdefault(raw.decode(), [])
        elif current is None:
            raise ValueError("collection value without a member name")
        else:
            current.append(_decode_collection(r) if tag == BEGIN_COLLECTION else _decode_value(tag, raw))


def decode(data: bytes) -> Response:
    r = _Reader(data)
    _, _, status, request_id = struct.unpack(">BBHI", r.take(8))
    groups: list[tuple[int, dict[str, list]]] = []
    attrs: dict[str, list] | None = None
    last: list | None = None
    while True:
        tag = r.peek()
        if tag <= 0x0F:  # delimiter
            r.pos += 1
            if tag == END:
                return Response(status, request_id, groups, data[r.pos:])
            attrs, last = {}, None
            groups.append((tag, attrs))
            continue
        if attrs is None:
            raise ValueError("IPP attribute outside a group")
        tag, name, raw = r.attribute()
        value = _decode_collection(r) if tag == BEGIN_COLLECTION else _decode_value(tag, raw)
        if name:
            last = attrs.setdefault(name, [])
        elif last is None:
            raise ValueError("additional IPP value without an attribute")
        last.append(value)


def _one(attrs: dict[str, list], name: str, default: Any = None) -> Any:
    values = attrs.get(name)
    return values[0] if values else default


# --- documents ----------------------------------------------------------------------------------------

def sniff(data: bytes) -> str | None:
    if b"%PDF-" in data[:1024]:
        return "application/pdf"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    return None


_PAGE = re.compile(rb"/Type\s*/Page(?![A-Za-z])")
_OBJ = re.compile(rb"(?<![0-9])(\d+)\s+\d+\s+obj\b")
_STREAM = re.compile(rb"\bstream\r?\n")


def count_pdf_pages(data: bytes, max_inflated: int = 64 << 20) -> int:
    """Distinct page objects in a PDF, including those in compressed object streams (PDF 1.5+). An
    object redefined by an incremental update counts once; pages an update deleted still count, so this
    errs high. 0 means it found none, e.g. because the PDF is encrypted."""
    pages: set[int] = set()
    view = memoryview(data)
    budget = max_inflated
    for m in _OBJ.finditer(data):
        end = data.find(b"endobj", m.end())
        end = len(data) if end < 0 else end
        stream = _STREAM.search(data, m.end(), end)
        head = data[m.end():stream.start() if stream else end]
        if _PAGE.search(head):
            pages.add(int(m.group(1)))
        if not stream or b"/ObjStm" not in head or b"/FlateDecode" not in head:
            continue
        n, first = re.search(rb"/N\s+(\d+)", head), re.search(rb"/First\s+(\d+)", head)
        if not n or not first:
            continue
        try:
            text = zlib.decompressobj().decompress(view[stream.end():], budget + 1)
        except zlib.error:
            continue
        budget -= len(text)
        if budget < 0:
            raise ToolError("the PDF's object streams inflate to more than 64 MiB")
        first_at = int(first.group(1))
        try:
            pairs = [int(x) for x in text[:first_at].split()][:2 * int(n.group(1))]
        except ValueError:
            continue
        pairs = pairs[:len(pairs) // 2 * 2]
        offsets = pairs[1::2] + [len(text) - first_at]
        for i, number in enumerate(pairs[0::2]):
            if _PAGE.search(text, first_at + offsets[i], first_at + offsets[i + 1]):
                pages.add(number)
    return len(pages)


def media_size_pt(media: str) -> tuple[float, float] | None:
    """Width and height in points from a self-describing PWG media name, e.g. iso_a4_210x297mm."""
    m = _MEDIA_SIZE.search(media)
    if not m:
        return None
    scale = 72 / 25.4 if m.group(3) == "mm" else 72.0
    return float(m.group(1)) * scale, float(m.group(2)) * scale


def _pdf_string(line: str) -> bytes:
    raw = line.encode("cp1252", errors="replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def text_to_pdf(text: str, width: float, height: float) -> tuple[bytes, int]:
    """Plain text as a PDF in 10 pt Courier with half-inch margins. Long lines wrap, tabs expand to 8
    columns and form feeds start a new page. Characters outside Windows-1252 print as '?'."""
    margin, size, leading, char_width = 36, 10, 12, 6.0
    cols = max(20, int((width - 2 * margin) // char_width))
    rows = max(5, int((height - 2 * margin) // leading))
    pages: list[list[str]] = []
    for chunk in text.replace("\r\n", "\n").replace("\r", "\n").split("\f"):
        pages.append([])
        for raw in chunk.split("\n"):
            line = raw.expandtabs(8)
            while True:
                if len(pages[-1]) == rows:
                    pages.append([])
                pages[-1].append(line[:cols])
                line = line[cols:]
                if not line:
                    break
    # Drop blank trailing lines and the pages they leave empty.
    while pages and pages[-1] and not pages[-1][-1].strip():
        pages[-1].pop()
        if not pages[-1] and len(pages) > 1:
            pages.pop()

    objects: list[bytes] = [b"", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                            b"/Encoding /WinAnsiEncoding >>"]
    kids = []
    for lines in pages:
        content = (f"BT /F1 {size} Tf {leading} TL {margin} {height - margin - size:.2f} Td\n".encode()
                   + b"".join(_pdf_string(line) + b" Tj T*\n" for line in lines) + b"ET")
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width:.2f} {height:.2f}] "
                       f"/Resources << /Font << /F1 3 0 R >> >> /Contents {len(objects)} 0 R >>".encode())
        kids.append(f"{len(objects)} 0 R")
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out), len(pages)


# --- the printer --------------------------------------------------------------------------------------

def _level(level: int, low: int | None = None) -> dict:
    # Negative levels (RFC 3805 prtMarkerSuppliesLevel): -1 not reported, -2 unknown, -3 some remaining.
    if level < 0:
        return {"level_pct": None, "level": "some remaining" if level == -3 else "unknown", "low": False}
    return {"level_pct": level, "low": low is not None and level <= low}


def _supplies(a: dict[str, list]) -> list[dict]:
    """Ink/toner from marker-* (CUPS, AirPrint) or else printer-supply (PWG 5100.13)."""
    names = a.get("marker-names", [])
    if names:
        levels, lows = a.get("marker-levels", []), a.get("marker-low-levels", [])
        colors, types = a.get("marker-colors", []), a.get("marker-types", [])
        return [{"name": name, "type": types[i] if i < len(types) else None,
                 "color": colors[i] if i < len(colors) else None,
                 **_level(levels[i] if i < len(levels) else -2, lows[i] if i < len(lows) else None)}
                for i, name in enumerate(names)]
    descriptions = a.get("printer-supply-description", [])
    out = []
    for i, raw in enumerate(a.get("printer-supply", [])):
        f = dict(kv.split("=", 1) for kv in (raw or "").split(";") if "=" in kv)
        try:
            level, capacity = int(f.get("level", -2)), int(f.get("maxcapacity", -2))
        except ValueError:
            level, capacity = -2, -2
        if level >= 0 and f.get("unit") != "percent":
            level = round(100 * level / capacity) if capacity > 0 else -2
        out.append({"name": descriptions[i] if i < len(descriptions) else f.get("type"), "type": f.get("type"),
                    "color": f.get("colorantname"), **_level(level)})
    return out


STATUS_ATTRS = ["printer-make-and-model", "printer-info", "printer-location", "printer-state",
                "printer-state-reasons", "printer-state-message", "printer-is-accepting-jobs", "queued-job-count",
                "marker-names", "marker-colors", "marker-types", "marker-levels", "marker-low-levels",
                "printer-supply", "printer-supply-description", "media-ready", "media-default",
                "sides-supported", "document-format-supported"]
JOB_TARGET_ATTRS = ["printer-state", "printer-state-reasons", "printer-is-accepting-jobs",
                    "document-format-supported", "sides-supported", "media-supported", "media-default",
                    "copies-supported"]
JOB_ATTRS = ["job-id", "job-name", "job-state", "job-state-reasons", "job-originating-user-name",
             "job-impressions-completed"]


def http_url(uri: str) -> str:
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme not in ("ipp", "ipps") or not parts.hostname:
        raise ValueError(f"printer URI must be ipp:// or ipps://, got {uri!r}")
    netloc = parts.netloc if parts.port else f"{parts.netloc}:631"
    return urllib.parse.urlunsplit(("http" if parts.scheme == "ipp" else "https", netloc, parts.path or "/",
                                    parts.query, ""))


class Printer:
    """One printer. `uri` is the device itself (status, supplies). Jobs go to `jobUri` when set, e.g. a
    local CUPS driverless queue that converts PDF, text and images for printers that only take raster."""

    def __init__(self, cfg: dict, transport: httpx.AsyncBaseTransport | None = None):
        self.uri = cfg["uri"]
        self.job_uri = cfg.get("jobUri") or self.uri
        for uri in (self.uri, self.job_uri):
            http_url(uri)  # fail at startup on a bad URI
        self.max_bytes = cfg.get("maxBytes", 10 << 20)
        self.max_pages = cfg.get("maxPages", 30)
        self.max_copies = cfg.get("maxCopies", 10)
        self.transport = transport
        self._request_id = 0
        self.busy_delay = 5.0

    async def request(self, uri: str, operation: int, op_attrs: list, job_attrs: list | None = None,
                      document: bytes = b"", timeout: float = 15, busy_retries: int = 0) -> Response:
        """One IPP operation. server-error-busy (a printer still on its previous job) is retried
        `busy_retries` times, `busy_delay` seconds apart."""
        groups = [(OPERATION, [(CHARSET, "attributes-charset", "utf-8"),
                               (LANGUAGE, "attributes-natural-language", "en"),
                               (URI, "printer-uri", uri), (NAME, "requesting-user-name", USER), *op_attrs])]
        if job_attrs:
            groups.append((JOB, job_attrs))
        for attempt in range(busy_retries + 1):
            self._request_id += 1
            body = encode(operation, self._request_id, groups) + document
            # Printers serve ipps:// with self-signed certificates; like CUPS, encrypt without verifying.
            async with httpx.AsyncClient(transport=self.transport, timeout=timeout, verify=False) as client:
                try:
                    resp = await client.post(http_url(uri), content=body,
                                             headers={"Content-Type": "application/ipp"})
                except httpx.HTTPError as e:
                    raise ToolError(f"printer unreachable at {uri}: {type(e).__name__}: {e}") from None
            if resp.status_code != 200:
                raise ToolError(f"printer at {uri} returned HTTP {resp.status_code}")
            try:
                reply = decode(resp.content)
            except (ValueError, struct.error, UnicodeDecodeError) as e:
                raise ToolError(f"printer at {uri} sent a malformed IPP response: {e}") from None
            if reply.status != BUSY or attempt == busy_retries:
                break
            await asyncio.sleep(self.busy_delay)
        if reply.status >= 0x0100:
            message = _one(reply.merged(OPERATION), "status-message", "")
            name = STATUS.get(reply.status, f"0x{reply.status:04x}")
            raise ToolError(f"printer at {uri} refused the request: {name}" + (f" ({message})" if message else ""))
        return reply

    async def attributes(self, uri: str, names: list[str]) -> dict[str, list]:
        reply = await self.request(uri, GET_PRINTER_ATTRIBUTES, [(KEYWORD, "requested-attributes", names)])
        return reply.merged(PRINTER)

    async def jobs(self, uri: str) -> list[dict]:
        reply = await self.request(uri, GET_JOBS, [(KEYWORD, "which-jobs", "not-completed"),
                                                   (INTEGER, "limit", 20),
                                                   (KEYWORD, "requested-attributes", JOB_ATTRS)])
        return [{"id": _one(j, "job-id"), "name": _one(j, "job-name"),
                 "state": JOB_STATE.get(_one(j, "job-state"), _one(j, "job-state")),
                 "reasons": [r for r in j.get("job-state-reasons", []) if r != "none"],
                 "user": _one(j, "job-originating-user-name"),
                 "pages_done": _one(j, "job-impressions-completed")} for j in reply.group(JOB)]

    async def status(self) -> dict:
        a = await self.attributes(self.uri, STATUS_ATTRS)
        supplies = _supplies(a)
        out = {
            "uri": self.uri,
            "model": _one(a, "printer-make-and-model"),
            "info": _one(a, "printer-info"),
            "location": _one(a, "printer-location") or None,
            "state": PRINTER_STATE.get(_one(a, "printer-state"), _one(a, "printer-state")),
            "state_reasons": [r for r in a.get("printer-state-reasons", []) if r != "none"],
            "state_message": _one(a, "printer-state-message") or None,
            "accepting_jobs": _one(a, "printer-is-accepting-jobs"),
            "queued_jobs": _one(a, "queued-job-count"),
            "supplies": supplies,
            "paper_loaded": [m for m in a.get("media-ready", []) if m],
            "paper_default": _one(a, "media-default"),
            "duplex": any(s.startswith("two-sided") for s in a.get("sides-supported", [])),
            "formats": a.get("document-format-supported", []),
        }
        try:
            out["jobs"] = await self.jobs(self.uri)
        except ToolError as e:
            out["jobs"] = {"error": str(e)}
        if self.job_uri != self.uri:
            try:
                q = await self.attributes(self.job_uri, ["printer-state", "printer-state-reasons",
                                                         "printer-is-accepting-jobs", "queued-job-count"])
                out["queue"] = {
                    "uri": self.job_uri,
                    "state": PRINTER_STATE.get(_one(q, "printer-state"), _one(q, "printer-state")),
                    "state_reasons": [r for r in q.get("printer-state-reasons", []) if r != "none"],
                    "accepting_jobs": _one(q, "printer-is-accepting-jobs"),
                    "jobs": await self.jobs(self.job_uri),
                }
            except ToolError as e:
                out["queue"] = {"uri": self.job_uri, "error": str(e)}
        return out

    def check_request(self, text: str | None, document_base64: str | None, copies: int) -> None:
        """Argument checks that need no printer round trip."""
        if (text is None) == (document_base64 is None):
            raise ToolError("give exactly one of text or document_base64")
        if not 1 <= copies <= self.max_copies:
            raise ToolError(f"copies must be 1-{self.max_copies}")
        size = len(text.encode()) if text is not None else len(document_base64) * 3 // 4
        if size > self.max_bytes:
            raise ToolError(f"document is larger than {self.max_bytes} bytes")

    async def print(self, text: str | None, document_base64: str | None, title: str | None, copies: int,
                    duplex: bool, paper: str | None) -> dict:
        self.check_request(text, document_base64, copies)
        media = None
        if paper:
            media = PAPER.get(paper.strip().lower(), paper.strip())
            if not _PWG_MEDIA.match(media):
                raise ToolError(f"unknown paper {paper!r}: use {', '.join(PAPER)} or a PWG media name "
                                "such as iso_a4_210x297mm")
        if text is not None:
            if not text.strip():
                raise ToolError("text is empty")
            document, fmt = None, "application/pdf"
        else:
            try:
                document = base64.b64decode(document_base64, validate=True)
            except (binascii.Error, ValueError):
                raise ToolError("document_base64 is not valid base64") from None
            if len(document) > self.max_bytes:
                raise ToolError(f"document is larger than {self.max_bytes} bytes")
            fmt = sniff(document)
            if fmt is None:
                raise ToolError("unsupported document: send a PDF, JPEG or PNG, or plain text as text")
            pages = count_pdf_pages(document) if fmt == "application/pdf" else 1
            if pages == 0:
                raise ToolError("could not count the PDF's pages (encrypted or malformed?)")
            self._check_pages(pages, copies)

        target = await self.attributes(self.job_uri, JOB_TARGET_ATTRS)
        formats = target.get("document-format-supported", [])
        if fmt not in formats:
            raise ToolError(f"the printer at {self.job_uri} does not accept {fmt} (it takes {', '.join(formats)}). "
                            "For printers that only take raster, set printer.cupsQueue so CUPS converts documents.")
        if not _one(target, "printer-is-accepting-jobs", True):
            raise ToolError(f"the printer at {self.job_uri} is not accepting jobs")
        sides = "two-sided-long-edge" if duplex else "one-sided"
        if duplex and sides not in target.get("sides-supported", []):
            raise ToolError("this printer cannot print two-sided")
        supported_media = target.get("media-supported", [])
        if media and supported_media and media not in supported_media:
            raise ToolError(f"paper {media} is not supported; the printer lists: {', '.join(supported_media)}")
        copies_range = _one(target, "copies-supported")
        if copies > 1 and isinstance(copies_range, list) and copies > copies_range[1]:
            raise ToolError(f"this printer prints at most {copies_range[1]} copies per job")

        if document is None:
            size = media_size_pt(media or _one(target, "media-default") or "") or media_size_pt(PAPER["letter"])
            document, pages = text_to_pdf(text, *size)
            self._check_pages(pages, copies)

        name = (title or "").strip()[:100] or "wett-mcp"
        job_attrs = [(INTEGER, "copies", copies)] if copies > 1 else []
        if duplex:
            job_attrs.append((KEYWORD, "sides", sides))
        if media:
            job_attrs.append((KEYWORD, "media", media))
        reply = await self.request(self.job_uri, PRINT_JOB, [(NAME, "job-name", name), (MIME, "document-format", fmt)],
                                   job_attrs, document, timeout=120, busy_retries=6)
        job = reply.merged(JOB)
        return {"job_id": _one(job, "job-id"), "state": JOB_STATE.get(_one(job, "job-state"), _one(job, "job-state")),
                "printer": self.job_uri, "title": name, "format": fmt, "pages": pages, "copies": copies,
                "sides": sides, "media": media, "bytes": len(document),
                # 16 hex digits: enough to identify the document, short of the audit log's hex redaction.
                "sha256_prefix": hashlib.sha256(document).hexdigest()[:16],
                **({"ipp_status": f"0x{reply.status:04x}"} if reply.status else {})}

    def _check_pages(self, pages: int, copies: int) -> None:
        if pages * copies > self.max_pages:
            raise ToolError(f"{pages} page(s) x {copies} copies is over the {self.max_pages}-page limit per job")
