"""
mscad_flowmeter -- a patched CICFlowMeter flow/feature engine for MSCAD.

WHY THIS FILE EXISTS
--------------------
The pip package `cicflowmeter` 0.5.0 defines the 76 CICFlowMeter features we
need, but it cannot be used as shipped.  Its feature classes
(features/packet_length.py, features/flag_count.py, ...) take live scapy
Packet objects and keep every one of them in `Flow.packets`, so the required
fixes -- include non-TCP/UDP traffic, stop storing whole packets, read real
TCP flags -- cannot be applied by monkey-patching: they change the data model.

So this module reimplements the same feature set, keeping the package's own
field names (`tot_fwd_pkts`, `flow_byts_s`, `cwr_flag_count`, ...) so the
mapping to MSCAD column names stays one-to-one and auditable.  The feature
definitions follow the *Java* CICFlowMeter, which is the tool that produced
the Kaggle MSCAD.csv we compare against.

PATCHES APPLIED (numbered as in the task brief)
-----------------------------------------------
1. No CLI.  The engine is a library; nothing calls `cicflowmeter -f`, so the
   `'bool' object has no attribute 'split'` crash cannot occur.
2. All IPv4 packets are processed, not just TCP/UDP.  ICMP and any other
   IP protocol form flows keyed on (src, dst, 0, 0, proto); ICMP flows get
   Src/Dst Port = 0 and Protocol = 1.  IP fragments with a non-zero fragment
   offset carry no transport header, so they also get ports 0 and are kept in
   the (src, dst, 0, 0, proto) flow -- which is what makes the App-02 ICMP
   flood survive.
3. No BPF capture filter, so no dependency on tcpdump/libpcap on Windows.
4. FIN is read from the real TCP flags byte, not from the IP flags field.
5. The first packet of a flow is added exactly once.
6. No packet objects are retained.  Every feature is maintained as an
   incremental accumulator (Welford mean/variance plus min/max/sum), so
   memory is O(open flows) and independent of flow length.  This is stronger
   than keeping a slim per-packet record and is what makes the 650k-packet
   brute-force capture run in constant memory.
7. Timeouts are checked on the flow the packet belongs to, plus a periodic
   sweep every SWEEP_EVERY_PACKETS packets.  Nothing rescans all open flows
   on every FIN, so the cost is O(packets) instead of O(packets x flows).
8. Flow timeout 120 s (Java CICFlowMeter default, the one used for MSCAD),
   idle timeout 240 s, activity timeout 5 s, clump timeout 1 s.

Two further bugs found while reading cicflowmeter 0.5.0 and also fixed here:
9. Its `Flow.update_subflow` compares `packet.time` against
   `self.latest_timestamp` *after* that field has already been advanced to
   `packet.time`, so the difference is always 0, `update_active_idle` is
   never reached and every Active/Idle feature is identically 0.  Also
   `last_active` starts at 0 (the epoch), so the first idle value would have
   been ~1.7e9 seconds.  Active/Idle are computed properly here.
10. Its `get_statistics` returns zeros unless `len(list) > 1`, so a flow with
    exactly two packets (one IAT) reports Flow IAT Mean/Max/Min = 0.  Here
    statistics are produced from one value onwards.

UNITS
-----
Packet times are carried as integer microseconds end to end (pcap gives
seconds + microseconds, so this is exact and free of float drift).  Every
time-derived feature -- Flow Duration, all IAT, all Active/Idle -- is
therefore emitted in MICROSECONDS, matching MSCAD.
"""

import math
import os
import socket
import struct

import mscad_config as CFG

# TCP flag bits
F_FIN, F_SYN, F_RST, F_PSH, F_ACK, F_URG, F_ECE, F_CWR = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

FORWARD, REVERSE = 0, 1

US = 1_000_000  # microseconds per second


# ==========================================================================
# Incremental statistics
# ==========================================================================
class RunningStats:
    """Welford accumulator with min/max/sum. No sample list is retained."""

    __slots__ = ("n", "_mean", "_m2", "mn", "mx", "total")

    def __init__(self):
        self.n = 0
        self._mean = 0.0
        self._m2 = 0.0
        self.mn = None
        self.mx = None
        self.total = 0

    def add(self, x):
        self.n += 1
        self.total += x
        d = x - self._mean
        self._mean += d / self.n
        self._m2 += d * (x - self._mean)
        if self.mn is None or x < self.mn:
            self.mn = x
        if self.mx is None or x > self.mx:
            self.mx = x

    @property
    def mean(self):
        return self._mean if self.n else 0.0

    @property
    def var(self):
        """Variance. ddof from config: 1 = Java/commons-math, 0 = numpy."""
        if self.n == 0:
            return 0.0
        if CFG.STD_DDOF == 1:
            if self.n < 2:
                return 0.0
            return self._m2 / (self.n - 1)
        return self._m2 / self.n

    @property
    def std(self):
        v = self.var
        return math.sqrt(v) if v > 0 else 0.0

    @property
    def minimum(self):
        return self.mn if self.n else 0

    @property
    def maximum(self):
        return self.mx if self.n else 0


def _div(a, b):
    """Java-style division for the long/long features."""
    if b == 0:
        return 0
    if CFG.JAVA_INTEGER_DIVISION:
        return int(a) // int(b)
    return a / b


# ==========================================================================
# Packet reading
# ==========================================================================
class PcapFormatError(Exception):
    pass


# datalink type -> (fixed header length, ethertype offset or None)
_LINKTYPES = {
    1:   ("ether", 14),
    0:   ("null", 4),
    101: ("raw", 0),
    228: ("raw", 0),
    12:  ("raw", 0),
    113: ("sll", 16),
    276: ("sll2", 20),
}


def _l2_ipv4_offset(linkname, data, hdr_len):
    """Return the offset of the IPv4 header, or -1 if this is not IPv4."""
    if linkname == "raw":
        if len(data) >= 1 and (data[0] >> 4) == 4:
            return 0
        return -1
    if linkname == "ether":
        if len(data) < 14:
            return -1
        off = 12
        et = (data[12] << 8) | data[13]
        base = 14
        # Up to two stacked VLAN / QinQ tags.
        for _ in range(2):
            if et in (0x8100, 0x88A8, 0x9100):
                if len(data) < base + 4:
                    return -1
                et = (data[base + 2] << 8) | data[base + 3]
                base += 4
            else:
                break
        if et == 0x0800:
            return base
        return -1
    if linkname == "null":
        if len(data) < 4:
            return -1
        # BSD loopback: 32-bit address family, host byte order either way.
        fam_le = struct.unpack("<I", data[0:4])[0]
        fam_be = struct.unpack(">I", data[0:4])[0]
        if 2 in (fam_le, fam_be):
            return 4
        return -1
    if linkname == "sll":
        if len(data) < 16:
            return -1
        et = (data[14] << 8) | data[15]
        return 16 if et == 0x0800 else -1
    if linkname == "sll2":
        if len(data) < 20:
            return -1
        et = (data[0] << 8) | data[1]
        return 20 if et == 0x0800 else -1
    return -1


def iter_pcap_records(path, block=4 << 20):
    """Stream (t_us, caplen, origlen, data) out of a classic libpcap file.

    Hand-rolled on purpose: it is fast, it needs no scapy dissection, and it
    hands us the captured bytes directly (so packet lengths come from the
    capture, never from a rebuilt packet).  Yields the datalink name first.
    """
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise PcapFormatError("%s: file shorter than a pcap header" % path)
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, tsdiv = "<", 1          # usec, little endian
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, tsdiv = ">", 1
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, tsdiv = "<", 1000       # nsec resolution
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, tsdiv = ">", 1000
        elif magic[:4] == b"\x0a\x0d\x0d\x0a":
            raise PcapFormatError(
                "%s is a pcapng file; use the scapy fallback reader" % path)
        else:
            raise PcapFormatError(
                "%s: unrecognised pcap magic %r" % (path, magic))

        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype not in _LINKTYPES:
            raise PcapFormatError(
                "%s: unsupported datalink type %d" % (path, linktype))
        linkname, _hdrlen = _LINKTYPES[linktype]
        yield linkname  # first item is the datalink name

        rec = struct.Struct(endian + "IIII")
        unpack = rec.unpack_from
        buf = bytearray()
        view_start = 0
        eof = False
        while True:
            # Top up the buffer.
            if not eof and len(buf) - view_start < (1 << 18):
                if view_start:
                    del buf[:view_start]
                    view_start = 0
                chunk = fh.read(block)
                if not chunk:
                    eof = True
                else:
                    buf += chunk
            avail = len(buf) - view_start
            if avail < 16:
                if eof:
                    break
                continue
            ts_sec, ts_frac, caplen, origlen = unpack(buf, view_start)
            if avail < 16 + caplen:
                if eof:
                    break  # truncated final record
                continue
            start = view_start + 16
            data = bytes(buf[start:start + caplen])
            view_start = start + caplen
            yield (ts_sec * US + ts_frac // tsdiv, caplen, origlen, data)


def iter_pcapng_records(path):
    """Fallback for .pcapng via scapy, same output shape as the above."""
    from scapy.utils import RawPcapNgReader

    rdr = RawPcapNgReader(path)
    linkname_sent = False
    for data, meta in rdr:
        lt = getattr(meta, "linktype", 1)
        if not linkname_sent:
            if lt not in _LINKTYPES:
                raise PcapFormatError(
                    "%s: unsupported datalink type %d" % (path, lt))
            yield _LINKTYPES[lt][0]
            linkname_sent = True
        tsresol = getattr(meta, "tsresol", 1_000_000) or 1_000_000
        raw_ts = (getattr(meta, "tshigh", 0) << 32) | getattr(meta, "tslow", 0)
        t_us = raw_ts * US // tsresol if tsresol != US else raw_ts
        wl = getattr(meta, "wirelen", len(data)) or len(data)
        yield (t_us, len(data), wl, bytes(data))
    if not linkname_sent:
        yield "ether"


def open_capture(path):
    gen = (iter_pcapng_records(path)
           if path.lower().endswith((".pcapng", ".ntar"))
           else iter_pcap_records(path))
    linkname = next(gen)
    return linkname, gen


class PacketCounters:
    __slots__ = ("total", "ipv4", "non_ipv4", "ipv4_truncated", "fragments",
                 "by_proto")

    def __init__(self):
        self.total = 0
        self.ipv4 = 0
        self.non_ipv4 = 0
        self.ipv4_truncated = 0
        self.fragments = 0
        self.by_proto = {}

    def as_dict(self):
        return {
            "packets_read": self.total,
            "ipv4_packets": self.ipv4,
            "non_ipv4_packets": self.non_ipv4,
            "ipv4_truncated_len": self.ipv4_truncated,
            "ipv4_non_first_fragments": self.fragments,
            "ipv4_by_protocol": dict(sorted(self.by_proto.items())),
        }


_inet_ntoa = socket.inet_ntoa


def parse_ipv4(data, off, caplen, counters):
    """Return a slim packet tuple, or None when this is not usable IPv4.

    (src, dst, sport, dport, proto, l4_hdr_len, payload_len, frame_len,
     tcp_flags, tcp_window, is_tcp)
    """
    avail = caplen - off
    if avail < 20:
        return None
    b0 = data[off]
    if (b0 >> 4) != 4:
        return None
    ihl = (b0 & 0x0F) * 4
    if ihl < 20 or avail < ihl:
        return None
    total_len = (data[off + 2] << 8) | data[off + 3]
    frag_word = (data[off + 6] << 8) | data[off + 7]
    frag_off = (frag_word & 0x1FFF) * 8
    proto = data[off + 9]
    src = _inet_ntoa(data[off + 12:off + 16])
    dst = _inet_ntoa(data[off + 16:off + 20])

    # Trust the IP total length when it is sane; fall back to the captured
    # bytes when the capture was snapped short or the NIC did TSO (len 0).
    if total_len == 0 or total_len > avail:
        counters.ipv4_truncated += 1
        ip_len = avail
    else:
        ip_len = total_len
    ip_payload_len = max(0, ip_len - ihl)

    counters.by_proto[proto] = counters.by_proto.get(proto, 0) + 1

    if frag_off > 0:
        # Non-first fragment: no transport header in this packet.
        counters.fragments += 1
        return (src, dst, 0, 0, proto, 0, ip_payload_len, caplen, 0, 0, False)

    l4 = off + ihl
    if proto == 6 and (caplen - l4) >= 20:
        sport = (data[l4] << 8) | data[l4 + 1]
        dport = (data[l4 + 2] << 8) | data[l4 + 3]
        dataofs = (data[l4 + 12] >> 4) * 4
        if dataofs < 20:
            dataofs = 20
        flags = data[l4 + 13]
        window = (data[l4 + 14] << 8) | data[l4 + 15]
        payload = max(0, ip_payload_len - dataofs)
        return (src, dst, sport, dport, 6, dataofs, payload, caplen,
                flags, window, True)
    if proto == 17 and (caplen - l4) >= 8:
        sport = (data[l4] << 8) | data[l4 + 1]
        dport = (data[l4 + 2] << 8) | data[l4 + 3]
        udp_len = (data[l4 + 4] << 8) | data[l4 + 5]
        payload = (max(0, udp_len - 8) if 8 <= udp_len <= ip_payload_len
                   else max(0, ip_payload_len - 8))
        return (src, dst, sport, dport, 17, 8, payload, caplen, 0, 0, False)
    if proto == 1 and (caplen - l4) >= 8:
        # ICMP: 8-byte header, no ports.  Patch 2 keeps these.
        return (src, dst, 0, 0, 1, 8, max(0, ip_payload_len - 8), caplen,
                0, 0, False)
    # Any other IP protocol, or a transport header too short to read.
    return (src, dst, 0, 0, proto, 0, ip_payload_len, caplen, 0, 0, False)


# ==========================================================================
# Flow
# ==========================================================================
class Flow:
    """One CICFlowMeter flow, maintained incrementally (patch 6)."""

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_t", "last_t", "last_fwd_t", "last_bwd_t",
        "fwd_len", "bwd_len", "all_len",
        "flow_iat", "fwd_iat", "bwd_iat",
        "fwd_hdr_bytes", "bwd_hdr_bytes", "min_seg_fwd",
        "fwd_act_data_pkts",
        "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr",
        "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg",
        "init_fwd_win", "init_bwd_win",
        "start_active", "end_active", "active", "idle",
        "sf_last_t", "sf_count",
        "fb_last_t", "fb_start_tmp", "fb_count", "fb_count_tmp",
        "fb_duration", "fb_pkt_count", "fb_size", "fb_size_tmp",
        "bb_last_t", "bb_start_tmp", "bb_count", "bb_count_tmp",
        "bb_duration", "bb_pkt_count", "bb_size", "bb_size_tmp",
    )

    def __init__(self, pkt, t_us, direction):
        src, dst, sport, dport, proto = pkt[0], pkt[1], pkt[2], pkt[3], pkt[4]
        if direction == FORWARD:
            self.src_ip, self.dst_ip = src, dst
            self.src_port, self.dst_port = sport, dport
        else:
            self.src_ip, self.dst_ip = dst, src
            self.src_port, self.dst_port = dport, sport
        self.protocol = proto

        self.start_t = t_us
        self.last_t = t_us
        self.last_fwd_t = 0
        self.last_bwd_t = 0

        self.fwd_len = RunningStats()
        self.bwd_len = RunningStats()
        self.all_len = RunningStats()
        self.flow_iat = RunningStats()
        self.fwd_iat = RunningStats()
        self.bwd_iat = RunningStats()

        self.fwd_hdr_bytes = 0
        self.bwd_hdr_bytes = 0
        self.min_seg_fwd = None
        self.fwd_act_data_pkts = 0

        self.fin = self.syn = self.rst = self.psh = 0
        self.ack = self.urg = self.ece = self.cwr = 0
        self.fwd_psh = self.bwd_psh = self.fwd_urg = self.bwd_urg = 0

        self.init_fwd_win = CFG.INIT_WIN_DEFAULT
        self.init_bwd_win = CFG.INIT_WIN_DEFAULT

        # Java seeds both active markers with the flow's first packet time,
        # which is what makes the first idle value sane (patch 9).
        self.start_active = t_us
        self.end_active = t_us
        self.active = RunningStats()
        self.idle = RunningStats()

        self.sf_last_t = t_us
        self.sf_count = 0

        self.fb_last_t = self.fb_start_tmp = 0
        self.fb_count = self.fb_count_tmp = 0
        self.fb_duration = self.fb_pkt_count = 0
        self.fb_size = self.fb_size_tmp = 0
        self.bb_last_t = self.bb_start_tmp = 0
        self.bb_count = self.bb_count_tmp = 0
        self.bb_duration = self.bb_pkt_count = 0
        self.bb_size = self.bb_size_tmp = 0

    # -- packet ingestion -------------------------------------------------
    def add_packet(self, pkt, t_us, direction):
        (_src, _dst, _sp, _dp, _proto, l4_hdr, payload, frame,
         flags, window, is_tcp) = pkt

        length = payload if CFG.PKT_LEN_MODE == "payload" else frame
        hdr = l4_hdr if CFG.HEADER_LEN_MODE == "l4" else 0

        npkts = self.fwd_len.n + self.bwd_len.n
        if npkts:  # not the first packet of the flow (patch 5)
            self._update_active_idle(t_us)
            self._update_subflow(t_us)
            self.flow_iat.add(t_us - self.last_t)

        self._update_bulk(t_us, payload, direction)

        if is_tcp:
            if flags & F_FIN:
                self.fin += 1
            if flags & F_SYN:
                self.syn += 1
            if flags & F_RST:
                self.rst += 1
            if flags & F_PSH:
                self.psh += 1
            if flags & F_ACK:
                self.ack += 1
            if flags & F_URG:
                self.urg += 1
            if flags & F_ECE:
                self.ece += 1
            if flags & F_CWR:
                self.cwr += 1

        if direction == FORWARD:
            if self.fwd_len.n:
                self.fwd_iat.add(t_us - self.last_fwd_t)
            elif is_tcp:
                self.init_fwd_win = window
            self.fwd_len.add(length)
            self.fwd_hdr_bytes += hdr
            if self.min_seg_fwd is None or l4_hdr < self.min_seg_fwd:
                self.min_seg_fwd = l4_hdr
            if payload >= 1:
                self.fwd_act_data_pkts += 1
            if is_tcp:
                if flags & F_PSH:
                    self.fwd_psh += 1
                if flags & F_URG:
                    self.fwd_urg += 1
            self.last_fwd_t = t_us
        else:
            if self.bwd_len.n:
                self.bwd_iat.add(t_us - self.last_bwd_t)
            elif is_tcp:
                self.init_bwd_win = window
            self.bwd_len.add(length)
            self.bwd_hdr_bytes += hdr
            if payload >= 1:
                pass  # Java tracks act_data_pkt for the forward side only
            if is_tcp:
                if flags & F_PSH:
                    self.bwd_psh += 1
                if flags & F_URG:
                    self.bwd_urg += 1
            self.last_bwd_t = t_us

        self.all_len.add(length)
        self.last_t = t_us

    def _update_active_idle(self, t_us):
        """Java BasicFlow.updateActiveIdleTime, called once per packet.

        The Java tool reaches this from two places and passes a duration in
        one of them; we call it once with the real timestamp (patch 9).
        """
        thr = int(CFG.ACTIVITY_TIMEOUT * US)
        if (t_us - self.end_active) > thr:
            dur = self.end_active - self.start_active
            if dur > 0:
                self.active.add(dur)
            self.idle.add(t_us - self.end_active)
            self.start_active = t_us
            self.end_active = t_us
        else:
            self.end_active = t_us

    def _update_subflow(self, t_us):
        if (t_us - self.sf_last_t) > int(CFG.CLUMP_TIMEOUT * US):
            self.sf_count += 1
        self.sf_last_t = t_us

    def _update_bulk(self, t_us, payload, direction):
        if payload <= 0:
            return
        clump = int(CFG.CLUMP_TIMEOUT * US)
        if direction == FORWARD:
            if self.bb_last_t > self.fb_start_tmp:
                self.fb_start_tmp = 0
            if self.fb_start_tmp == 0:
                self.fb_start_tmp = t_us
                self.fb_last_t = t_us
                self.fb_count_tmp = 1
                self.fb_size_tmp = payload
            elif (t_us - self.fb_last_t) > clump:
                self.fb_start_tmp = t_us
                self.fb_last_t = t_us
                self.fb_count_tmp = 1
                self.fb_size_tmp = payload
            else:
                self.fb_count_tmp += 1
                self.fb_size_tmp += payload
                if self.fb_count_tmp == CFG.BULK_BOUND:
                    self.fb_count += 1
                    self.fb_pkt_count += self.fb_count_tmp
                    self.fb_size += self.fb_size_tmp
                    self.fb_duration += t_us - self.fb_start_tmp
                elif self.fb_count_tmp > CFG.BULK_BOUND:
                    self.fb_pkt_count += 1
                    self.fb_size += payload
                    self.fb_duration += t_us - self.fb_last_t
                self.fb_last_t = t_us
        else:
            if self.fb_last_t > self.bb_start_tmp:
                self.bb_start_tmp = 0
            if self.bb_start_tmp == 0:
                self.bb_start_tmp = t_us
                self.bb_last_t = t_us
                self.bb_count_tmp = 1
                self.bb_size_tmp = payload
            elif (t_us - self.bb_last_t) > clump:
                self.bb_start_tmp = t_us
                self.bb_last_t = t_us
                self.bb_count_tmp = 1
                self.bb_size_tmp = payload
            else:
                self.bb_count_tmp += 1
                self.bb_size_tmp += payload
                if self.bb_count_tmp == CFG.BULK_BOUND:
                    self.bb_count += 1
                    self.bb_pkt_count += self.bb_count_tmp
                    self.bb_size += self.bb_size_tmp
                    self.bb_duration += t_us - self.bb_start_tmp
                elif self.bb_count_tmp > CFG.BULK_BOUND:
                    self.bb_pkt_count += 1
                    self.bb_size += payload
                    self.bb_duration += t_us - self.bb_last_t
                self.bb_last_t = t_us

    # -- output -----------------------------------------------------------
    @property
    def packet_count(self):
        return self.fwd_len.n + self.bwd_len.n

    @property
    def duration_us(self):
        return self.last_t - self.start_t

    def get_data(self):
        """All 76 CICFlowMeter features under the pip-cicflowmeter key names."""
        if CFG.ADD_FINAL_ACTIVE_SEGMENT:
            tail = self.end_active - self.start_active
            if tail > 0:
                self.active.add(tail)

        dur = self.duration_us
        dur_s = dur / float(US)
        n_fwd, n_bwd = self.fwd_len.n, self.bwd_len.n
        n_tot = n_fwd + n_bwd
        byts = self.fwd_len.total + self.bwd_len.total

        if dur > 0:
            flow_byts_s = byts / dur_s
            flow_pkts_s = n_tot / dur_s
            fwd_pkts_s = n_fwd / dur_s
            bwd_pkts_s = n_bwd / dur_s
        else:
            # Zero-duration flow.  The Java tool divides by 0.0 and so writes
            # Infinity (or NaN when the numerator is 0 too).  We always emit
            # Infinity, so that any NaN in the output is a genuine bug and the
            # Part 2 NaN check stays meaningful.  02_verify.py reports the
            # zero-duration flow count separately.
            inf = float("inf")
            flow_byts_s = flow_pkts_s = fwd_pkts_s = bwd_pkts_s = inf

        sf = self.sf_count if CFG.SUBFLOW_MODE == "divide" else 0
        if CFG.SUBFLOW_MODE == "divide":
            sf_div = sf + 1  # 1 subflow plus one per >1 s gap
            sub_fwd_pkts = _div(n_fwd, sf_div)
            sub_bwd_pkts = _div(n_bwd, sf_div)
            sub_fwd_byts = _div(self.fwd_len.total, sf_div)
            sub_bwd_byts = _div(self.bwd_len.total, sf_div)
        else:
            sub_fwd_pkts, sub_bwd_pkts = n_fwd, n_bwd
            sub_fwd_byts, sub_bwd_byts = self.fwd_len.total, self.bwd_len.total

        fb_rate = (self.fb_size / (self.fb_duration / float(US))
                   if self.fb_duration > 0 else 0)
        bb_rate = (self.bb_size / (self.bb_duration / float(US))
                   if self.bb_duration > 0 else 0)

        fwd_mean = self.fwd_len.mean
        bwd_mean = self.bwd_len.mean

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.start_t,          # integer microseconds
            "flow_duration": dur,
            "tot_fwd_pkts": n_fwd,
            "tot_bwd_pkts": n_bwd,
            "totlen_fwd_pkts": self.fwd_len.total,
            "totlen_bwd_pkts": self.bwd_len.total,
            "fwd_pkt_len_max": self.fwd_len.maximum,
            "fwd_pkt_len_min": self.fwd_len.minimum,
            "fwd_pkt_len_mean": fwd_mean,
            "fwd_pkt_len_std": self.fwd_len.std,
            "bwd_pkt_len_max": self.bwd_len.maximum,
            "bwd_pkt_len_min": self.bwd_len.minimum,
            "bwd_pkt_len_mean": bwd_mean,
            "bwd_pkt_len_std": self.bwd_len.std,
            "flow_byts_s": flow_byts_s,
            "flow_pkts_s": flow_pkts_s,
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.maximum,
            "flow_iat_min": self.flow_iat.minimum,
            "fwd_iat_tot": self.fwd_iat.total,
            "fwd_iat_mean": self.fwd_iat.mean,
            "fwd_iat_std": self.fwd_iat.std,
            "fwd_iat_max": self.fwd_iat.maximum,
            "fwd_iat_min": self.fwd_iat.minimum,
            "bwd_iat_tot": self.bwd_iat.total,
            "bwd_iat_mean": self.bwd_iat.mean,
            "bwd_iat_std": self.bwd_iat.std,
            "bwd_iat_max": self.bwd_iat.maximum,
            "bwd_iat_min": self.bwd_iat.minimum,
            "fwd_psh_flags": self.fwd_psh,
            "bwd_psh_flags": self.bwd_psh,
            "fwd_urg_flags": self.fwd_urg,
            "bwd_urg_flags": self.bwd_urg,
            "fwd_header_len": self.fwd_hdr_bytes,
            "bwd_header_len": self.bwd_hdr_bytes,
            "fwd_pkts_s": fwd_pkts_s,
            "bwd_pkts_s": bwd_pkts_s,
            "pkt_len_min": self.all_len.minimum,
            "pkt_len_max": self.all_len.maximum,
            "pkt_len_mean": self.all_len.mean,
            "pkt_len_std": self.all_len.std,
            "pkt_len_var": self.all_len.var,
            "fin_flag_cnt": self.fin,
            "syn_flag_cnt": self.syn,
            "rst_flag_cnt": self.rst,
            "psh_flag_cnt": self.psh,
            "ack_flag_cnt": self.ack,
            "urg_flag_cnt": self.urg,
            "cwr_flag_count": self.cwr,     # real CWR bit, not Fwd URG
            "ece_flag_cnt": self.ece,
            "down_up_ratio": _div(n_bwd, n_fwd) if n_fwd else 0,
            "pkt_size_avg": (byts / n_tot) if n_tot else 0,
            "fwd_seg_size_avg": fwd_mean,
            "bwd_seg_size_avg": bwd_mean,
            "fwd_byts_b_avg": _div(self.fb_size, self.fb_count),
            "fwd_pkts_b_avg": _div(self.fb_pkt_count, self.fb_count),
            "fwd_blk_rate_avg": fb_rate,
            "bwd_byts_b_avg": _div(self.bb_size, self.bb_count),
            "bwd_pkts_b_avg": _div(self.bb_pkt_count, self.bb_count),
            "bwd_blk_rate_avg": bb_rate,
            "subflow_fwd_pkts": sub_fwd_pkts,
            "subflow_fwd_byts": sub_fwd_byts,
            "subflow_bwd_pkts": sub_bwd_pkts,
            "subflow_bwd_byts": sub_bwd_byts,
            "init_fwd_win_byts": self.init_fwd_win,
            "init_bwd_win_byts": self.init_bwd_win,
            "fwd_act_data_pkts": self.fwd_act_data_pkts,
            "fwd_seg_size_min": (self.min_seg_fwd
                                 if self.min_seg_fwd is not None else 0),
            "active_mean": self.active.mean,
            "active_std": self.active.std,
            "active_max": self.active.maximum,
            "active_min": self.active.minimum,
            "idle_mean": self.idle.mean,
            "idle_std": self.idle.std,
            "idle_max": self.idle.maximum,
            "idle_min": self.idle.minimum,
        }


# ==========================================================================
# Engine
# ==========================================================================
class FlowEngine:
    """Builds flows from a capture and hands each finished flow to a sink."""

    def __init__(self, sink, progress=None):
        self.flows = {}
        self.sink = sink
        self.progress = progress
        self.counters = PacketCounters()
        self.flows_written = 0
        self.single_packet_flows = 0
        self.zero_duration_flows = 0
        self.flows_dropped_single = 0
        self.last_packet_time_us = 0

    def _emit(self, flow):
        if (CFG.DROP_SINGLE_PACKET_FLOWS and flow.packet_count <= 1):
            self.flows_dropped_single += 1
            return
        if flow.packet_count <= 1:
            self.single_packet_flows += 1
        if flow.duration_us == 0:
            self.zero_duration_flows += 1
        self.sink(flow.get_data())
        self.flows_written += 1

    def run(self, path):
        linkname, records = open_capture(path)
        c = self.counters
        flows = self.flows
        flow_to = int(CFG.FLOW_TIMEOUT * US)
        idle_to = int(CFG.IDLE_TIMEOUT * US)
        sweep_every = CFG.SWEEP_EVERY_PACKETS
        prog_every = CFG.PROGRESS_EVERY_PACKETS
        last_t_us = 0

        for t_us, caplen, origlen, data in records:
            c.total += 1
            if prog_every and self.progress and c.total % prog_every == 0:
                self.progress(c.total, len(flows), self.flows_written)

            off = _l2_ipv4_offset(linkname, data, caplen)
            if off < 0:
                c.non_ipv4 += 1
                continue
            pkt = parse_ipv4(data, off, caplen, c)
            if pkt is None:
                c.non_ipv4 += 1
                continue
            c.ipv4 += 1
            last_t_us = t_us

            src, dst, sp, dp, proto = pkt[0], pkt[1], pkt[2], pkt[3], pkt[4]
            fkey = (src, dst, sp, dp, proto)
            flow = flows.get(fkey)
            direction = FORWARD
            if flow is None:
                rkey = (dst, src, dp, sp, proto)
                flow = flows.get(rkey)
                if flow is not None:
                    fkey = rkey
                    direction = REVERSE

            if flow is None:
                flows[fkey] = Flow(pkt, t_us, FORWARD)
                flows[fkey].add_packet(pkt, t_us, FORWARD)
                continue

            # Patch 7: timeouts are checked on this flow only.
            if ((t_us - flow.start_t) > flow_to
                    or (t_us - flow.last_t) > idle_to):
                del flows[fkey]
                self._emit(flow)
                nkey = (src, dst, sp, dp, proto)
                flows[nkey] = Flow(pkt, t_us, FORWARD)
                flows[nkey].add_packet(pkt, t_us, FORWARD)
                continue

            flow.add_packet(pkt, t_us, direction)

            # Patch 4: real TCP flags.  Patch 7: no full rescan here.
            tcp_flags = pkt[8]
            if pkt[10] and ((CFG.CLOSE_FLOW_ON_FIN and (tcp_flags & F_FIN))
                            or (CFG.CLOSE_FLOW_ON_RST and (tcp_flags & F_RST))):
                del flows[fkey]
                self._emit(flow)
                continue

            if sweep_every and c.total % sweep_every == 0:
                self._sweep(t_us, flow_to, idle_to)

        # Flush everything still open.
        for flow in list(flows.values()):
            self._emit(flow)
        flows.clear()
        self.last_packet_time_us = last_t_us
        return self.counters

    def _sweep(self, now_us, flow_to, idle_to):
        dead = [k for k, f in self.flows.items()
                if (now_us - f.start_t) > flow_to
                or (now_us - f.last_t) > idle_to]
        for k in dead:
            f = self.flows.pop(k)
            self._emit(f)
