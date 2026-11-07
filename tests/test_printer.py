"""The IPP client against wire-format fixtures and a fake printer, PDF page counting, text to PDF."""

import base64
import re
import struct
import zlib

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from conftest import DEVICE
from wett_mcp import printer as ipp


def wire_attr(tag: int, name: str, value: bytes) -> bytes:
    return struct.pack(">BH", tag, len(name)) + name.encode() + struct.pack(">H", len(value)) + value


def make_pdf(pages: int) -> bytes:
    body = b"".join(b"%d 0 obj << /Type /Page /Parent 2 0 R >> endobj\n" % (3 + i) for i in range(pages))
    return b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages >> endobj\n" + body


def test_decode_wire_format():
    """A Get-Printer-Attributes response as RFC 8010 lays it out: 1setOf values, an out-of-band value,
    textWithLanguage, rangeOfInteger and a nested collection, then document data."""
    media_col = (wire_attr(ipp.BEGIN_COLLECTION, "media-col-ready", b"")
                 + wire_attr(ipp.MEMBER_NAME, "", b"media-size")
                 + wire_attr(ipp.BEGIN_COLLECTION, "", b"")
                 + wire_attr(ipp.MEMBER_NAME, "", b"x-dimension") + wire_attr(ipp.INTEGER, "", struct.pack(">i", 21000))
                 + wire_attr(ipp.MEMBER_NAME, "", b"y-dimension") + wire_attr(ipp.INTEGER, "", struct.pack(">i", 29700))
                 + wire_attr(ipp.END_COLLECTION, "", b"")
                 + wire_attr(ipp.MEMBER_NAME, "", b"media-source") + wire_attr(ipp.KEYWORD, "", b"main")
                 + wire_attr(ipp.END_COLLECTION, "", b""))
    data = (struct.pack(">BBHI", 2, 0, 0x0001, 7)
            + bytes([ipp.OPERATION]) + wire_attr(ipp.CHARSET, "attributes-charset", b"utf-8")
            + bytes([ipp.PRINTER])
            + wire_attr(ipp.ENUM, "printer-state", struct.pack(">i", 3))
            + wire_attr(ipp.MIME, "document-format-supported", b"application/pdf")
            + wire_attr(ipp.MIME, "", b"image/jpeg")
            + wire_attr(ipp.RANGE, "copies-supported", struct.pack(">ii", 1, 99))
            + wire_attr(ipp.TEXT_LANG, "printer-info", struct.pack(">H", 2) + b"en" + struct.pack(">H", 5) + b"Canon")
            + wire_attr(0x13, "printer-location", b"")
            + media_col
            + wire_attr(ipp.BOOLEAN, "printer-is-accepting-jobs", b"\x01")
            + bytes([ipp.END]) + b"%PDF-")
    reply = ipp.decode(data)
    assert (reply.status, reply.request_id, reply.data) == (1, 7, b"%PDF-")
    attrs = reply.merged(ipp.PRINTER)
    assert attrs == {
        "printer-state": [3],
        "document-format-supported": ["application/pdf", "image/jpeg"],
        "copies-supported": [[1, 99]],
        "printer-info": ["Canon"],
        "printer-location": [None],
        "media-col-ready": [{"media-size": {"x-dimension": 21000, "y-dimension": 29700}, "media-source": "main"}],
        "printer-is-accepting-jobs": [True],
    }
    with pytest.raises(ValueError):
        ipp.decode(data[:40])


def test_encode_wire_format():
    """Additional values of a 1setOf attribute carry an empty name."""
    body = ipp.encode(ipp.GET_PRINTER_ATTRIBUTES, 9, [(ipp.OPERATION, [
        (ipp.KEYWORD, "requested-attributes", ["a", "bc"]), (ipp.INTEGER, "limit", 5)])])
    assert body == (b"\x01\x01\x00\x0b\x00\x00\x00\x09\x01"
                    b"\x44\x00\x14requested-attributes\x00\x01a"
                    b"\x44\x00\x00\x00\x02bc"
                    b"\x21\x00\x05limit\x00\x04\x00\x00\x00\x05"
                    b"\x03")


def test_pdf_pages_in_object_streams_and_incremental_updates():
    objs = [b"<< /Type /Page /Parent 2 0 R >>", b"<< /Type /Page /Parent 2 0 R /Rotate 90 >>",
            b"<< /Type /Font /Subtype /Type1 >>"]
    offsets, pos = [], 0
    for o in objs:
        offsets.append(pos)
        pos += len(o) + 1
    header = b"4 %d 5 %d 7 %d " % tuple(offsets)
    stream = zlib.compress(header + b" ".join(objs) + b" ")
    objstm = b"6 0 obj << /Type /ObjStm /N 3 /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (
        len(header), len(stream))
    pdf = (b"%PDF-1.5\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
           b"2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >> endobj\n"
           b"3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
           + objstm + stream + b"\nendstream\nendobj\n%%EOF\n"
           # An incremental update redefines page 3: still three pages.
           b"3 0 obj << /Type /Page /Parent 2 0 R /Rotate 180 >> endobj\n%%EOF\n")
    assert ipp.count_pdf_pages(pdf) == 3
    assert ipp.count_pdf_pages(b"%PDF-1.7\n1 0 obj << /Encrypt 2 0 R >> endobj\n") == 0


def test_text_to_pdf_pagination():
    # Letter, half-inch margins, 10 pt Courier: 90 columns, 60 lines.
    text = "\n".join(f"line {i}" for i in range(121)) + "\n\n\n"
    pdf, pages = ipp.text_to_pdf(text, 612, 792)
    assert pages == 3 and ipp.count_pdf_pages(pdf) == 3
    pdf, pages = ipp.text_to_pdf("x" * 200 + "\fsecond (page) \\", 612, 792)
    assert pages == 2
    assert b"(" + b"x" * 90 + b") Tj" in pdf and b"(" + b"x" * 20 + b") Tj" in pdf
    assert b"(second \\(page\\) \\\\) Tj" in pdf
    assert b"/MediaBox [0 0 612.00 792.00]" in pdf


def test_text_to_pdf_large_font_wraps_at_words():
    # 24 pt on letter: 37 columns, 25 lines; leading spaces of a line are kept.
    words = "Hello Herb, this is a note in large type that wraps at word boundaries."
    pdf, pages = ipp.text_to_pdf("  " + words + "\n" * 30 + "end", 612, 792, size=24)
    assert pages == 2
    assert b"/F1 24 Tf 28.80 TL" in pdf
    lines = [m.decode() for m in re.findall(rb"\((.*?)\) Tj", pdf)]
    assert lines[:3] == ["  Hello Herb, this is a note in large", "type that wraps at word boundaries.", ""]
    assert all(len(line) <= 37 for line in lines)


def printer(fake, **cfg):
    p = ipp.Printer({"uri": DEVICE, "maxPages": 10, "maxCopies": 3, "maxBytes": 4096, **cfg},
                    transport=fake.transport)
    p.busy_delay = 0
    return p


async def test_print_job_request(fake_printer):
    pdf = make_pdf(2)
    job = await printer(fake_printer).print(None, base64.b64encode(pdf).decode(), "Report", 3, True, "A4")
    assert job["job_id"] == 1 and job["state"] == "processing" and job["pages"] == 2
    [(url, op, attrs, data)] = fake_printer.print_jobs()
    assert url == "http://printer.test:631/ipp/print" and data == pdf
    assert op["printer-uri"] == [DEVICE] and op["document-format"] == ["application/pdf"]
    assert op["job-name"] == ["Report"] and op["requesting-user-name"] == ["wett-mcp"]
    assert attrs == {"copies": [3], "sides": ["two-sided-long-edge"], "media": ["iso_a4_210x297mm"]}


async def test_text_follows_printer_default_paper(fake_printer):
    fake_printer.attrs["media-default"] = (ipp.KEYWORD, "iso_a4_210x297mm")
    job = await printer(fake_printer).print("hello", None, None, 1, False, None)
    [(_, op, attrs, data)] = fake_printer.print_jobs()
    assert op["document-format"] == ["application/pdf"] and op["job-name"] == ["wett-mcp"] and attrs == {}
    assert b"/MediaBox [0 0 595.28 841.89]" in data and b"(hello) Tj" in data
    assert job["pages"] == 1 and job["media"] is None


async def test_jobs_go_to_the_queue_when_configured(fake_printer):
    queue = "ipp://localhost:631/printers/canon"
    p = printer(fake_printer, jobUri=queue)
    await p.print("hi", None, None, 1, False, None)
    assert [url for url, *_ in fake_printer.requests] == ["http://localhost:631/printers/canon"] * 2
    status = await p.status()
    assert status["uri"] == DEVICE and status["queue"]["uri"] == queue
    assert status["queue"]["jobs"][0]["name"] == "wett-mcp"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.mark.parametrize("args, attrs, error", [
    ({"text": "a", "document_base64": b64(b"x")}, {}, "exactly one"),
    ({}, {}, "exactly one"),
    ({"text": " \n"}, {}, "empty"),
    ({"text": "a", "copies": 0}, {}, "copies must be 1-3"),
    ({"text": "a", "copies": 4}, {}, "copies must be 1-3"),
    ({"text": "a", "font_size": 7}, {}, "font_size must be 8-36"),
    ({"text": "a", "font_size": 37}, {}, "font_size must be 8-36"),
    ({"text": "a\n" * 200, "font_size": 36}, {}, "13 page(s) x 1 copies is over the 10-page limit"),
    ({"text": "a" * 5000}, {}, "larger than 4096"),
    ({"document_base64": b64(make_pdf(1) + b" " * 5000)}, {}, "larger than 4096"),
    ({"document_base64": "not base64!"}, {}, "not valid base64"),
    ({"document_base64": b64(b"PK\x03\x04 zip")}, {}, "unsupported document"),
    ({"document_base64": b64(make_pdf(4)), "copies": 3}, {}, "4 page(s) x 3 copies is over the 10-page limit"),
    ({"document_base64": b64(b"%PDF-1.7 encrypted")}, {}, "count the PDF's pages"),
    ({"text": "\f".join("p" * 11)}, {}, "11 page(s) x 1 copies"),
    ({"text": "a", "paper": "tabloid"}, {}, "unknown paper"),
    ({"text": "a", "paper": "a5"}, {}, "iso_a5_148x210mm is not supported"),
    ({"document_base64": b64(b"\x89PNG\r\n\x1a\nrest")}, {}, "does not accept image/png"),
    ({"text": "a", "duplex": True}, {"sides-supported": (ipp.KEYWORD, ["one-sided"])}, "two-sided"),
    ({"text": "a", "copies": 2}, {"copies-supported": (ipp.RANGE, (1, 1))}, "at most 1 copies"),
    ({"text": "a"}, {"printer-is-accepting-jobs": (ipp.BOOLEAN, False)}, "not accepting jobs"),
])
async def test_print_refused_before_any_job(fake_printer, args, attrs, error):
    fake_printer.attrs.update(attrs)
    call = {"text": None, "document_base64": None, "title": None, "copies": 1, "duplex": False, "paper": None,
            **args}
    with pytest.raises(ToolError, match=re.escape(error)):
        await printer(fake_printer).print(**call)
    assert fake_printer.print_jobs() == []


async def test_busy_printer_is_retried_then_given_up(fake_printer):
    fake_printer.replies = [ipp.BUSY, ipp.BUSY]
    job = await printer(fake_printer).print("a", None, None, 1, False, None)
    assert job["job_id"] == 1 and len(fake_printer.print_jobs()) == 3

    fake_printer.replies = [ipp.BUSY] * 7
    with pytest.raises(ToolError, match=r"server-error-busy \(Currently printing another job.\)"):
        await printer(fake_printer).print("a", None, None, 1, False, None)
    assert len(fake_printer.print_jobs()) == 3 + 7


async def test_status_markers_jobs_and_negative_levels(fake_printer):
    fake_printer.jobs = [(4, "Report", 5)]
    s = await printer(fake_printer).status()
    assert s["model"] == "Canon TEST series" and s["state"] == "idle" and s["state_reasons"] == []
    assert s["accepting_jobs"] is True and s["duplex"] is True and s["paper_loaded"] == ["na_letter_8.5x11in"]
    assert s["supplies"] == [
        {"name": "Black Ink", "type": "ink-cartridge", "color": "#000000", "level_pct": 12, "low": True},
        {"name": "Color Ink", "type": "ink-cartridge", "color": "#00FFFF#FF00FF#FFFF00", "level_pct": None,
         "level": "some remaining", "low": False},
    ]
    assert s["jobs"] == [{"id": 4, "name": "Report", "state": "processing", "reasons": ["job-printing"],
                          "user": None, "pages_done": None}]
    assert "queue" not in s


async def test_status_from_printer_supply(fake_printer):
    """Printers without marker-* report PWG 5100.13 printer-supply strings instead."""
    for name in ("marker-names", "marker-levels", "marker-colors", "marker-types", "marker-low-levels"):
        del fake_printer.attrs[name]
    fake_printer.attrs["printer-supply"] = (0x30, [
        "index=1;class=supplyThatIsConsumed;type=toner;unit=percent;maxcapacity=100;level=75;colorantname=black;",
        "index=2;class=supplyThatIsConsumed;type=toner;unit=impressions;maxcapacity=2000;level=500;",
        "index=3;type=wasteToner;level=-2;"])
    fake_printer.attrs["printer-supply-description"] = (ipp.TEXT, ["Black Toner", "Drum"])
    fake_printer.attrs["printer-state"] = (ipp.ENUM, 5)
    fake_printer.attrs["printer-state-reasons"] = (ipp.KEYWORD, ["media-empty-error", "toner-low-warning"])
    s = await printer(fake_printer).status()
    assert s["state"] == "stopped" and s["state_reasons"] == ["media-empty-error", "toner-low-warning"]
    assert [(x["name"], x["level_pct"]) for x in s["supplies"]] == [("Black Toner", 75), ("Drum", 25),
                                                                    ("wasteToner", None)]


async def test_ipp_errors_and_unreachable(fake_printer):
    with pytest.raises(ToolError, match="printer unreachable at ipp://printer.invalid"):
        await ipp.Printer({"uri": "ipp://printer.invalid/ipp/print"}).status()
    with pytest.raises(ValueError, match="ipp:// or ipps://"):
        ipp.Printer({"uri": "http://printer.test/"})
    assert ipp.http_url("ipps://printer.test/ipp/print") == "https://printer.test:631/ipp/print"
    assert ipp.http_url("ipp://[fd00::5]:8631/ipp/print") == "http://[fd00::5]:8631/ipp/print"
