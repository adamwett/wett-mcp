"""A fake IPP printer on an httpx MockTransport, shared by the printer and MCP tests."""

import httpx
import pytest

from wett_mcp import printer as ipp

DEVICE = "ipp://printer.test/ipp/print"


class FakePrinter:
    """Answers Get-Printer-Attributes, Get-Jobs and Print-Job; records every request. `attrs` maps
    attribute name to (value tag, value or list) and can be edited per test. `replies` queues status
    codes for the next Print-Job requests (e.g. server-error-busy)."""

    def __init__(self):
        self.attrs = {
            "printer-make-and-model": (ipp.TEXT, "Canon TEST series"),
            "printer-state": (ipp.ENUM, 3),
            "printer-state-reasons": (ipp.KEYWORD, ["none"]),
            "printer-is-accepting-jobs": (ipp.BOOLEAN, True),
            "queued-job-count": (ipp.INTEGER, 0),
            "document-format-supported": (ipp.MIME, ["application/octet-stream", "application/pdf", "image/jpeg",
                                                     "image/pwg-raster"]),
            "sides-supported": (ipp.KEYWORD, ["one-sided", "two-sided-long-edge", "two-sided-short-edge"]),
            "media-supported": (ipp.KEYWORD, ["na_letter_8.5x11in", "iso_a4_210x297mm", "na_index-4x6_4x6in"]),
            "media-default": (ipp.KEYWORD, "na_letter_8.5x11in"),
            "media-ready": (ipp.KEYWORD, ["na_letter_8.5x11in"]),
            "copies-supported": (ipp.RANGE, (1, 99)),  # a tuple is one value; lists are 1setOf
            "marker-names": (ipp.NAME, ["Black Ink", "Color Ink"]),
            "marker-types": (ipp.KEYWORD, ["ink-cartridge", "ink-cartridge"]),
            "marker-colors": (ipp.NAME, ["#000000", "#00FFFF#FF00FF#FFFF00"]),
            "marker-levels": (ipp.INTEGER, [12, -3]),
            "marker-low-levels": (ipp.INTEGER, [15, 15]),
        }
        self.jobs: list[tuple[int, str, int]] = []  # job id, name, state
        self.replies: list[int] = []
        self.requests: list[tuple[str, int, dict, dict, bytes]] = []
        self.transport = httpx.MockTransport(self.handle)

    def print_jobs(self) -> list[tuple[str, dict, dict, bytes]]:
        return [(url, op, job, data) for url, code, op, job, data in self.requests if code == ipp.PRINT_JOB]

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/ipp"
        req = ipp.decode(request.content)
        op, job = req.merged(ipp.OPERATION), req.merged(ipp.JOB)
        self.requests.append((str(request.url), req.status, op, job, req.data))
        head = [(ipp.CHARSET, "attributes-charset", "utf-8"), (ipp.LANGUAGE, "attributes-natural-language", "en")]
        groups = [(ipp.OPERATION, head)]
        status = 0
        if req.status == ipp.GET_PRINTER_ATTRIBUTES:
            wanted = op["requested-attributes"]
            groups.append((ipp.PRINTER, [(tag, name, value) for name, (tag, value) in self.attrs.items()
                                         if name in wanted]))
        elif req.status == ipp.GET_JOBS:
            for job_id, name, state in self.jobs:
                groups.append((ipp.JOB, [(ipp.INTEGER, "job-id", job_id), (ipp.NAME, "job-name", name),
                                         (ipp.ENUM, "job-state", state),
                                         (ipp.KEYWORD, "job-state-reasons", "job-printing")]))
        elif req.status == ipp.PRINT_JOB:
            status = self.replies.pop(0) if self.replies else 0
            if status == 0:
                self.jobs.append((len(self.jobs) + 1, op["job-name"][0], 5))
                groups.append((ipp.JOB, [(ipp.INTEGER, "job-id", len(self.jobs)), (ipp.ENUM, "job-state", 5)]))
            else:
                head.append((ipp.TEXT, "status-message", "Currently printing another job."))
        body = ipp.encode(status, req.request_id, groups)
        return httpx.Response(200, content=body, headers={"Content-Type": "application/ipp"})


@pytest.fixture
def fake_printer():
    return FakePrinter()
