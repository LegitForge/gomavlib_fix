#!/usr/bin/env python3
"""Compare what pymavlink and gomavlib make of the same bytes.

    tcpdump -i any -w arm.pcap udp port 14550
    ./mavstream.py extract arm.pcap --port 14550 -o arm
    ./mavstream.py parse arm -o arm.python.json
    go run ./cmd/streamparse -stream arm -o arm.go.json
    ./mavstream.py compare arm.python.json arm.go.json

extract writes two files: <name>.bin, the UDP payloads concatenated in capture
order, and <name>.idx, the offset and source of every datagram inside it. Both
parsers read the same .bin, so any difference in the reports is a difference
between the parsers and not between two captures.
"""

import argparse
import json
import struct
import sys

PCAP_MAGIC = {
    0xA1B2C3D4: ("<", 1),          # little endian, microseconds
    0xD4C3B2A1: (">", 1),
    0xA1B23C4D: ("<", 1000),       # nanoseconds
    0x4D3CB2A1: (">", 1000),
}

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def _strip_link_layer(linktype, data):
    """Return the IP packet, or None when the link layer does not carry one."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8):        # VLAN tags
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        return data[offset:] if ethertype in (0x0800, 0x86DD) else None

    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return data[16:] if struct.unpack("!H", data[14:16])[0] in (0x0800, 0x86DD) else None

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        return data[20:] if struct.unpack("!H", data[0:2])[0] in (0x0800, 0x86DD) else None

    if linktype == LINKTYPE_RAW:
        return data

    if linktype == LINKTYPE_NULL:
        return data[4:] if len(data) >= 4 else None

    raise SystemExit(f"unsupported pcap linktype {linktype}")


def _udp_payload(ip):
    """Return (src, dst, payload) for a UDP packet, or None."""
    if not ip:
        return None
    version = ip[0] >> 4

    if version == 4:
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 8 or ip[9] != 17:
            return None
        # a non-zero fragment offset means this is not the head of the datagram
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:
            return None
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        udp = ip[ihl:]
    elif version == 6:
        if len(ip) < 48 or ip[6] != 17:
            return None
        src = ip[8:24].hex()
        dst = ip[24:40].hex()
        udp = ip[40:]
    else:
        return None

    if len(udp) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", udp[0:6])
    payload = udp[8:length] if 8 <= length <= len(udp) else udp[8:]
    return (f"{src}:{sport}", f"{dst}:{dport}", payload)


def cmd_extract(args):
    with open(args.pcap, "rb") as f:
        raw = f.read()

    if len(raw) < 24:
        raise SystemExit("file is too short to be a pcap")
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        raise SystemExit("this is a pcapng file; convert it with "
                         "'editcap -F pcap in.pcapng out.pcap'")

    magic = struct.unpack("<I", raw[:4])[0]
    if magic not in PCAP_MAGIC:
        magic = struct.unpack(">I", raw[:4])[0]
    if magic not in PCAP_MAGIC:
        raise SystemExit("not a pcap file")

    endian, _ = PCAP_MAGIC[magic]
    linktype = struct.unpack(endian + "I", raw[20:24])[0]

    stream = bytearray()
    index = []
    pos = 24
    while pos + 16 <= len(raw):
        ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + "IIII", raw[pos:pos + 16])
        pos += 16
        data = raw[pos:pos + caplen]
        pos += caplen

        if caplen < origlen:
            print(f"warning: packet truncated by the capture "
                  f"({caplen} of {origlen} bytes); re-run tcpdump with -s0",
                  file=sys.stderr)

        parsed = _udp_payload(_strip_link_layer(linktype, data))
        if parsed is None:
            continue
        src, dst, payload = parsed

        if args.port is not None:
            if not (src.endswith(f":{args.port}") or dst.endswith(f":{args.port}")):
                continue
        if args.src is not None and not src.startswith(args.src):
            continue

        index.append({
            "offset": len(stream),
            "length": len(payload),
            "time": ts_sec + ts_usec / 1_000_000.0,
            "src": src,
            "dst": dst,
        })
        stream += payload

    if not index:
        raise SystemExit("no UDP datagrams matched; check --port and --src")

    with open(args.out + ".bin", "wb") as f:
        f.write(stream)
    with open(args.out + ".idx", "w", encoding="utf-8") as f:
        json.dump(index, f, indent=1)

    sources = sorted({d["src"] for d in index})
    print(f"{len(index)} datagrams, {len(stream)} bytes -> {args.out}.bin")
    print(f"sources: {', '.join(sources)}")
    if len(sources) > 1:
        print("warning: more than one source is interleaved in the stream, "
              "which desynchronises any parser. Narrow it with --src.",
              file=sys.stderr)


def _load_stream(name):
    with open(name + ".bin", "rb") as f:
        stream = f.read()
    try:
        with open(name + ".idx", encoding="utf-8") as f:
            index = json.load(f)
    except FileNotFoundError:
        index = []
    return stream, index


def _datagram_of(index, offset):
    """Which datagram an offset falls in, and how far into it."""
    lo, hi = 0, len(index) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        d = index[mid]
        if offset < d["offset"]:
            hi = mid - 1
        elif offset >= d["offset"] + d["length"]:
            lo = mid + 1
        else:
            return mid, offset - d["offset"], d["length"]
    return None, None, None


def cmd_parse(args):
    from pymavlink import mavutil
    from pymavlink.dialects.v20 import ardupilotmega

    stream, index = _load_stream(args.stream)

    mav = ardupilotmega.MAVLink(None)
    mav.robust_parsing = True

    frames = []
    errors = []
    consumed = 0

    # feed the whole stream at once: pymavlink keeps one parse buffer and does
    # not care where the datagram boundaries were, which is the behaviour we
    # are comparing against
    mav.buf.extend(stream)
    while True:
        before = mav.buf_index
        try:
            msg = mav.parse_char(b"")
        except Exception as exc:                    # noqa: BLE001
            errors.append({"offset": before, "reason": str(exc)})
            break
        if msg is None:
            break
        consumed = mav.buf_index

        if msg.get_type() == "BAD_DATA":
            dg, into, dglen = _datagram_of(index, before)
            errors.append({
                "offset": before,
                "length": consumed - before,
                "reason": str(getattr(msg, "reason", "bad data")),
                "hex": bytes(msg.data)[:64].hex(),
                "datagram": dg,
                "offset_in_datagram": into,
                "datagram_length": dglen,
                "at_datagram_tail": (dg is not None and into + (consumed - before) >= dglen),
            })
            continue

        frames.append({
            "offset": before,
            "msgid": msg.get_msgId(),
            "type": msg.get_type(),
            "sysid": msg.get_srcSystem(),
            "compid": msg.get_srcComponent(),
            "seq": msg.get_seq(),
            "payload_len": len(msg.get_payload() or b""),
        })

    report = _build_report("pymavlink", stream, index, frames, errors)
    _write_report(report, args.out)


def _build_report(parser, stream, index, frames, errors):
    # seq gaps per source: MAVLink increments seq on every frame a component
    # emits, so a gap is a frame that never arrived. Keep the breakdown: a
    # source that appears out of nowhere with a huge gap is a false frame that
    # got through the parser, not a lost one.
    gaps = []
    missing_by_source = {}
    frames_by_source = {}
    last = {}
    for fr in frames:
        key = f"{fr['sysid']}:{fr['compid']}"
        frames_by_source[key] = frames_by_source.get(key, 0) + 1
        prev = last.get(key)
        if prev is not None:
            missing = (fr["seq"] - prev - 1) % 256
            if missing:
                gaps.append({"source": key, "offset": fr["offset"], "missing": missing})
                missing_by_source[key] = missing_by_source.get(key, 0) + missing
        last[key] = fr["seq"]

    by_type = {}
    by_msgid = {}
    for fr in frames:
        by_type[fr["type"]] = by_type.get(fr["type"], 0) + 1
        by_msgid[str(fr["msgid"])] = by_msgid.get(str(fr["msgid"]), 0) + 1

    return {
        "parser": parser,
        "stream_bytes": len(stream),
        "datagrams": len(index),
        "frames": len(frames),
        "errors": len(errors),
        "skipped_bytes": sum(e.get("length", 0) for e in errors),
        "seq_gaps": len(gaps),
        "frames_missing_by_seq": sum(g["missing"] for g in gaps),
        "frames_by_source": frames_by_source,
        "missing_by_source": missing_by_source,
        "frames_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "frames_by_msgid": by_msgid,
        "gap_detail": gaps[:50],
        "error_detail": errors[:50],
        "frame_offsets": [fr["offset"] for fr in frames],
        "frame_detail": frames,
    }


def _write_report(report, out):
    text = json.dumps(report, indent=1)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
    summary = {k: v for k, v in report.items()
               if k not in ("gap_detail", "error_detail", "frame_offsets",
                            "frames_by_type", "frames_by_source",
                            "frames_by_msgid", "frame_detail")}
    print(json.dumps(summary, indent=1))
    for err in report["error_detail"][:10]:
        print(f"  error at {err['offset']}: {err['reason']}", file=sys.stderr)


def cmd_compare(args):
    with open(args.a, encoding="utf-8") as f:
        a = json.load(f)
    with open(args.b, encoding="utf-8") as f:
        b = json.load(f)

    print(f"{'':24} {a['parser']:>14} {b['parser']:>14}")
    for key in ("stream_bytes", "datagrams", "frames", "errors",
                "skipped_bytes", "seq_gaps", "frames_missing_by_seq"):
        mark = "  <-- differs" if a.get(key) != b.get(key) else ""
        print(f"{key:24} {a.get(key, '-'):>14} {b.get(key, '-'):>14}{mark}")

    only_a = sorted(set(a["frame_offsets"]) - set(b["frame_offsets"]))
    only_b = sorted(set(b["frame_offsets"]) - set(a["frame_offsets"]))

    print()
    if not only_a and not only_b:
        print("both parsers found the same frames at the same offsets.")
        print("any loss is upstream of the parser: on the vehicle or on the link.")
        return

    if only_a:
        print(f"{len(only_a)} frames only {a['parser']} found, first offsets: {only_a[:10]}")
        print("these are frames our parser is losing.")

        lost = {}
        index = {fr["offset"]: fr for fr in a.get("frame_detail", [])}
        for off in only_a:
            fr = index.get(off)
            if fr:
                lost[fr["type"]] = lost.get(fr["type"], 0) + 1
        if lost:
            print("by message type:", dict(sorted(lost.items(), key=lambda kv: -kv[1])))
    if only_b:
        print(f"{len(only_b)} frames only {b['parser']} found, first offsets: {only_b[:10]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="pcap -> byte stream + datagram index")
    p.add_argument("pcap")
    p.add_argument("-o", "--out", required=True, help="output name, without extension")
    p.add_argument("--port", type=int, help="keep only datagrams on this UDP port")
    p.add_argument("--src", help="keep only datagrams from this source, e.g. 10.0.0.5")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("parse", help="parse a stream with pymavlink")
    p.add_argument("stream", help="name given to extract, without extension")
    p.add_argument("-o", "--out", help="write the full report here")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("compare", help="diff two reports")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
