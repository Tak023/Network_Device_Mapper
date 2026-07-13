"""mDNS packet encode/decode (pure functions; no sockets touched)."""

import struct

from backend.mdns import (
    CLASS_IN,
    TYPE_PTR,
    _build_query,
    _encode_name,
    _parse_ptr_answers,
    _ptr_name,
)


def test_ptr_name():
    assert _ptr_name("192.168.1.50") == "50.1.168.192.in-addr.arpa"


def test_build_query_roundtrip():
    pkt = _build_query("192.168.1.50")
    _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", pkt[:12])
    assert (flags, qd, an) == (0, 1, 0)
    assert b"in-addr" in pkt
    assert pkt.endswith(struct.pack(">HH", TYPE_PTR, CLASS_IN | 0x8000))


def _response(qname: str, target: str, compressed: bool) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", TYPE_PTR, CLASS_IN)
    # Answer name: either a compression pointer back to the question (offset 12)
    # or the full name again — real responders send both styles.
    answer_name = struct.pack(">H", 0xC000 | 12) if compressed else _encode_name(qname)
    rdata = _encode_name(target)
    answer = answer_name + struct.pack(">HHIH", TYPE_PTR, CLASS_IN, 120, len(rdata)) + rdata
    return header + question + answer


def test_parse_ptr_answer_plain():
    q = _ptr_name("192.168.1.50")
    out = _parse_ptr_answers(_response(q, "Living-Room-TV.local", compressed=False))
    assert out == {q.lower(): "Living-Room-TV.local"}


def test_parse_ptr_answer_compressed():
    q = _ptr_name("10.0.0.7")
    out = _parse_ptr_answers(_response(q, "printer.local", compressed=True))
    assert out == {q.lower(): "printer.local"}


def test_parse_ignores_queries_and_garbage():
    assert _parse_ptr_answers(_build_query("192.168.1.50")) == {}  # a query, not a response
    assert _parse_ptr_answers(b"\x00\x01") == {}
    assert _parse_ptr_answers(b"") == {}
    # Truncated mid-answer must not raise.
    resp = _response(_ptr_name("10.0.0.7"), "printer.local", compressed=True)
    assert _parse_ptr_answers(resp[: len(resp) - 5]) == {}
