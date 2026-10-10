"""
Build a small synthetic fixture so the whole pipeline can be run end to end
without the real MSCAD data.

It writes, under the directory given as the first argument:
    pcaps/pcapngtopcap/{N-0,Scan-1,App-01,App-02,W-B-01,W-B-02}.pcap
    csv_original/MSCAD.csv        a stand-in "Kaggle" file with 66 of the 76
                                  CICFlowMeter columns, built from a sample of
                                  the flows the engine finds in those pcaps,
                                  so the Part 3 comparison has real matches

The captures deliberately exercise: TCP handshake/FIN teardown, UDP, ICMP,
IP-fragmented ICMP, a one-sided port scan (single-packet flows), several
attacker IPs, benign traffic inside an attack capture, flows longer than the
120 s flow timeout, gaps longer than the 240 s idle timeout, and ARP + IPv6
packets that must be excluded.

    python make_test_fixture.py /path/to/testdir
"""

import os
import random
import sys

from scapy.all import (ARP, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, fragment,
                       wrpcap)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE = 1_700_000_000.0
random.seed(7)


def eth(payload, t):
    p = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / payload
    p.time = t
    return p


def tcp_session(src, dst, sport, dport, t0, n_data=3, gap=0.01, fin=True,
                payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"):
    """A full handshake, some data each way, optional FIN teardown."""
    pkts, t = [], t0
    seq, ack = 1000, 5000
    pkts.append(eth(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                               flags="S", seq=seq,
                                               window=8192), t))
    t += gap
    pkts.append(eth(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                                               flags="SA", seq=ack, ack=seq + 1,
                                               window=29200), t))
    t += gap
    pkts.append(eth(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                               flags="A", seq=seq + 1,
                                               ack=ack + 1, window=8192), t))
    for i in range(n_data):
        t += gap
        pkts.append(eth(IP(src=src, dst=dst)
                        / TCP(sport=sport, dport=dport, flags="PA",
                              seq=seq + 1 + i * len(payload),
                              ack=ack + 1, window=8192) / Raw(payload), t))
        t += gap
        body = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * (120 + i * 40)
        pkts.append(eth(IP(src=dst, dst=src)
                        / TCP(sport=dport, dport=sport, flags="PA",
                              seq=ack + 1 + i * len(body), ack=seq + 1,
                              window=29200) / Raw(body), t))
    if fin:
        t += gap
        pkts.append(eth(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                                   flags="FA", window=8192), t))
        t += gap
        pkts.append(eth(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                                                   flags="FA",
                                                   window=29200), t))
    return pkts, t


def noise(t):
    """Packets that must be excluded: ARP and IPv6."""
    return [eth(ARP(pdst="192.168.159.1"), t),
            eth(IPv6(src="fe80::1", dst="fe80::2") / Raw(b"\x00" * 20),
                t + 0.001)]


def cap_normal():
    pkts, t = [], BASE
    for i in range(12):
        s, _ = tcp_session("192.168.159.50", "192.168.159.200",
                           40000 + i, 80, t, n_data=2 + i % 3)
        pkts += s
        t += 1.3
    # UDP DNS pairs
    for i in range(6):
        pkts.append(eth(IP(src="192.168.159.50", dst="192.168.159.2")
                        / UDP(sport=50000 + i, dport=53) / Raw(b"q" * 30), t))
        pkts.append(eth(IP(src="192.168.159.2", dst="192.168.159.50")
                        / UDP(sport=53, dport=50000 + i) / Raw(b"r" * 90),
                        t + 0.004))
        t += 0.7
    # a flow that outlives the 120 s flow timeout -> must be cut in two
    long_pkts, _ = tcp_session("192.168.159.51", "192.168.159.200", 41000,
                               8080, t, n_data=2, gap=35.0, fin=False)
    pkts += long_pkts
    t += 200
    # a gap longer than the 240 s idle timeout on the same 5-tuple
    pkts += noise(t)
    t += 300
    more, t = tcp_session("192.168.159.51", "192.168.159.200", 41000, 8080, t,
                          n_data=1)
    pkts += more
    # a lone ICMP echo pair in normal traffic
    pkts.append(eth(IP(src="192.168.159.50", dst="192.168.159.200")
                    / ICMP() / Raw(b"p" * 56), t + 1))
    pkts.append(eth(IP(src="192.168.159.200", dst="192.168.159.50")
                    / ICMP(type=0) / Raw(b"p" * 56), t + 1.01))
    return pkts


def cap_scan():
    """One attacker, many single-packet flows: SYN, FIN and UDP scans."""
    pkts, t = [], BASE + 10
    atk, tgt = "192.168.159.1", "192.168.159.200"
    for i, port in enumerate(range(1, 141)):
        pkts.append(eth(IP(src=atk, dst=tgt) / TCP(sport=55000 + i,
                                                   dport=port, flags="S",
                                                   window=1024), t))
        t += 0.002
        if port % 7 == 0:   # a few get a RST back
            pkts.append(eth(IP(src=tgt, dst=atk) / TCP(sport=port,
                                                       dport=55000 + i,
                                                       flags="RA",
                                                       window=0), t))
            t += 0.001
    for i, port in enumerate(range(200, 260)):
        pkts.append(eth(IP(src=atk, dst=tgt) / TCP(sport=56000 + i,
                                                   dport=port, flags="F",
                                                   window=1024), t))
        t += 0.002
    for i, port in enumerate(range(300, 350)):
        pkts.append(eth(IP(src=atk, dst=tgt) / UDP(sport=57000 + i,
                                                   dport=port)
                        / Raw(b"\x00" * 8), t))
        t += 0.002
    # benign traffic in the same capture -> must come out as Benign
    s, _ = tcp_session("192.168.159.60", "192.168.159.201", 42000, 443, t,
                       n_data=4)
    pkts += s
    pkts += noise(t + 5)
    return pkts


def cap_slowloris():
    """Three attacker IPs holding many half-open HTTP requests."""
    pkts, t = [], BASE + 20
    tgt = "192.168.159.200"
    for a, atk in enumerate(("192.168.159.10", "192.168.159.11",
                             "192.168.159.12")):
        for i in range(14):
            sp = 43000 + a * 100 + i
            pkts.append(eth(IP(src=atk, dst=tgt) / TCP(sport=sp, dport=80,
                                                       flags="S",
                                                       window=512), t))
            t += 0.003
            pkts.append(eth(IP(src=tgt, dst=atk) / TCP(sport=80, dport=sp,
                                                       flags="SA",
                                                       window=29200), t))
            t += 0.003
            pkts.append(eth(IP(src=atk, dst=tgt) / TCP(sport=sp, dport=80,
                                                       flags="A",
                                                       window=512), t))
            # dribble partial headers, with >1 s gaps so Active/Idle and the
            # subflow counter both get exercised
            for k in range(4):
                t += 1.4
                pkts.append(eth(IP(src=atk, dst=tgt)
                                / TCP(sport=sp, dport=80, flags="PA",
                                      window=512)
                                / Raw(b"X-a%d: b\r\n" % k), t))
            t += 0.05
    s, _ = tcp_session("192.168.159.61", tgt, 44000, 80, t, n_data=2)
    pkts += s
    pkts += noise(t + 2)
    return pkts


def cap_icmp_flood():
    """ICMP flood from three IPs, including IP-fragmented big pings."""
    pkts, t = [], BASE + 30
    tgt = "192.168.159.200"
    for atk, count in (("192.168.159.14", 260), ("192.168.159.10", 200),
                       ("192.168.159.12", 180)):
        for i in range(count):
            pkts.append(eth(IP(src=atk, dst=tgt, id=i + 1) / ICMP(id=i)
                            / Raw(b"f" * 56), t))
            t += 0.0008
        # big pings that the IP layer must fragment
        for i in range(6):
            big = IP(src=atk, dst=tgt, id=5000 + i) / ICMP(id=900 + i) \
                / Raw(b"B" * 3000)
            for frag in fragment(big, fragsize=1400):
                pkts.append(eth(frag, t))
                t += 0.0005
    s, _ = tcp_session("192.168.159.62", tgt, 45000, 80, t, n_data=1)
    pkts += s
    pkts += noise(t + 1)
    return pkts


def cap_crawl():
    pkts, t = [], BASE + 40
    atk, tgt = "192.168.159.1", "192.168.159.200"
    for i in range(30):
        s, t = tcp_session(atk, tgt, 46000 + i, 80, t, n_data=1 + i % 2,
                           payload=b"GET /page%d HTTP/1.1\r\n\r\n" % i)
        pkts += s
        t += 0.3
    s, _ = tcp_session("192.168.159.63", tgt, 47000, 80, t, n_data=2)
    pkts += s
    pkts += noise(t + 1)
    return pkts


def cap_brute():
    """Many short SSH sessions, each closed with a FIN."""
    pkts, t = [], BASE + 50
    atk, tgt = "192.168.159.13", "192.168.159.200"
    for i in range(90):
        s, t = tcp_session(atk, tgt, 48000 + i, 22, t, n_data=2,
                           payload=b"user%d:pass%d\n" % (i, i))
        pkts += s
        t += 0.05
    s, _ = tcp_session("192.168.159.64", tgt, 49000, 22, t, n_data=1)
    pkts += s
    pkts += noise(t + 1)
    return pkts


BUILDERS = {
    "N-0": cap_normal,
    "Scan-1": cap_scan,
    "App-01": cap_slowloris,
    "App-02": cap_icmp_flood,
    "W-B-01": cap_crawl,
    "W-B-02": cap_brute,
}


def build_fake_original(pcap_dir, csv_dir):
    """Run the engine over the fixture and write a stand-in Kaggle file with
    66 of the 76 columns, so schema resolution and Part 3 have real work."""
    import mscad_config as CFG
    import mscad_names as N
    from mscad_flowmeter import FlowEngine

    # Drop 10 features so the stand-in has 66, as the real MSCAD does.
    drop = {"fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_byts_b_avg",
            "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
            "subflow_fwd_byts", "subflow_bwd_byts", "ece_flag_cnt",
            "bwd_psh_flags"}
    keep = [(d, k) for d, k in N.CANONICAL_FEATURES if k not in drop]
    assert len(keep) == 66, len(keep)

    rows = []
    for key, label, _desc in CFG.CAPTURES:
        path = os.path.join(pcap_dir, key + ".pcap")
        got = []
        eng = FlowEngine(got.append)
        eng.run(path)
        # Attackers, by the same rule the pipeline uses.
        counts = {}
        for d in got:
            counts[d["src_ip"]] = counts.get(d["src_ip"], 0) + d["tot_fwd_pkts"]
        top = max(counts.values()) if counts else 0
        atk = {ip for ip, c in counts.items() if c >= 0.5 * top}
        for d in got:
            if key == "N-0":
                lab = label
            else:
                lab = label if (d["src_ip"] in atk or d["dst_ip"] in atk) \
                    else "Benign"
            # Keep ~55% of the flows, so row counts differ as they really do.
            if random.random() > 0.55:
                continue
            rows.append((d, lab))

    os.makedirs(csv_dir, exist_ok=True)
    out = os.path.join(csv_dir, "MSCAD.csv")
    import csv as _csv
    with open(out, "w", newline="") as fh:
        w = _csv.writer(fh, lineterminator="\n")
        # Quoted, space-padded headers, so the cleaning step gets exercised.
        w.writerow([" %s " % d for d, _k in keep] + ["Label"])
        for d, lab in rows:
            vals = []
            for _disp, k in keep:
                v = d[k]
                if isinstance(v, float):
                    if v != v or v in (float("inf"), float("-inf")):
                        vals.append("Infinity")
                        continue
                    vals.append("%.10g" % v)
                else:
                    vals.append(v)
            w.writerow(vals + [lab])
    print("wrote %s  (%d rows x %d cols)" % (out, len(rows), len(keep) + 1))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = os.path.abspath(sys.argv[1])
    pcap_dir = os.path.join(root, "pcaps", "pcapngtopcap")
    csv_dir = os.path.join(root, "csv_original")
    os.makedirs(pcap_dir, exist_ok=True)

    for key, fn in BUILDERS.items():
        pkts = fn()
        pkts.sort(key=lambda p: p.time)
        path = os.path.join(pcap_dir, key + ".pcap")
        wrpcap(path, pkts)
        print("wrote %-24s %6d packets" % (os.path.basename(path), len(pkts)))

    build_fake_original(pcap_dir, csv_dir)
    print("\nfixture root: %s" % root)
    print("  pcap dir : %s" % pcap_dir)
    print("  csv dir  : %s" % csv_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
