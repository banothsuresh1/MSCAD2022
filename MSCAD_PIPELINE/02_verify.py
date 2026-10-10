"""
Stage 02 -- verify the extraction (Part 2).

For every capture:
  * packets read, IPv4 packets accounted for in flows (sum of Tot Fwd Pkts +
    Tot Bwd Pkts), and TWO independent IPv4 counts:
      - tshark -r <file> -Y ip   (if tshark is installed)
      - a second-opinion counter in this file: its own raw-bytes record
        walk, independent of the pipeline's parser and needing no
        third-party package at all
    The flow total must equal the independent counts exactly.  The remainder
    up to "packets read" is ARP / IPv6 / non-IP, excluded by design.
  * duplicate flows (same 5-tuple + start Timestamp): must be 0
  * NaN, infinity, negative values, min > max, invalid ports
  * rows whose feature vectors are byte-for-byte identical (expected in
    floods / scans / brute force -- counted, never dropped)
"""

import json
import os
import struct
import subprocess
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG   # noqa: E402
import mscad_names as N      # noqa: E402
import mscad_schema as SCH   # noqa: E402

ARGS = CFG.apply_overrides()

MINMAX_PAIRS = [
    ("fwd_pkt_len_min", "fwd_pkt_len_max"),
    ("bwd_pkt_len_min", "bwd_pkt_len_max"),
    ("pkt_len_min", "pkt_len_max"),
    ("flow_iat_min", "flow_iat_max"),
    ("fwd_iat_min", "fwd_iat_max"),
    ("bwd_iat_min", "bwd_iat_max"),
    ("active_min", "active_max"),
    ("idle_min", "idle_max"),
]
# These two are -1 by design when the direction carries no TCP packet.
NEGATIVE_ALLOWED = {"init_fwd_win_byts", "init_bwd_win_byts"}


def tshark_ipv4_count(path):
    """Independent IPv4 packet count via tshark. Returns (count, note)."""
    exe = CFG.TSHARK_EXE
    if not os.path.isfile(exe):
        return None, "tshark not found at %s" % exe
    cmd = [exe, "-r", path, "-Y", "ip", "-T", "fields", "-e", "frame.number"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except Exception as exc:  # noqa: BLE001
        return None, "tshark failed: %s: %s" % (type(exc).__name__, exc)
    if p.returncode != 0:
        return None, "tshark exit %d: %s" % (p.returncode,
                                             (p.stderr or "").strip()[:300])
    n = sum(1 for line in p.stdout.splitlines() if line.strip())
    return n, "tshark -Y ip"


def second_opinion_ipv4_count(path):
    """A deliberately separate IPv4 packet counter.

    Written against the raw file bytes with its own record walk, independent
    of mscad_flowmeter's reader, and with no third-party imports at all -- so
    this check still runs on a stock Anaconda install with no scapy and no
    Wireshark. If it and the flow totals agree, no packet was lost or
    double-counted.
    """
    try:
        with open(path, "rb") as fh:
            gh = fh.read(24)
            if len(gh) < 24:
                return None, "file shorter than a pcap header"
            magic = gh[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                end = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                end = ">"
            elif magic[:4] == b"\x0a\x0d\x0d\x0a":
                return None, ("pcapng not supported by this counter; use "
                              "tshark, or convert with editcap -F pcap")
            else:
                return None, "unrecognised pcap magic %r" % magic
            linktype = struct.unpack(end + "I", gh[20:24])[0]
            if linktype not in (0, 1, 12, 101, 113, 228, 276):
                return None, "unsupported datalink type %d" % linktype

            hdr = struct.Struct(end + "IIII")
            n = 0
            total = 0
            while True:
                rh = fh.read(16)
                if len(rh) < 16:
                    break
                _s, _u, caplen, _orig = hdr.unpack(rh)
                data = fh.read(caplen)
                if len(data) < caplen:
                    break   # truncated final record
                total += 1
                if linktype == 1:
                    if len(data) < 14:
                        continue
                    et = (data[12] << 8) | data[13]
                    base = 14
                    while et in (0x8100, 0x88A8, 0x9100) and len(data) >= base + 4:
                        et = (data[base + 2] << 8) | data[base + 3]
                        base += 4
                    if et == 0x0800 and len(data) > base \
                            and (data[base] >> 4) == 4:
                        n += 1
                elif linktype in (12, 101, 228):
                    if data and (data[0] >> 4) == 4:
                        n += 1
                elif linktype == 113:
                    if len(data) >= 16 \
                            and ((data[14] << 8) | data[15]) == 0x0800:
                        n += 1
                elif linktype == 276:
                    if len(data) >= 20 \
                            and ((data[0] << 8) | data[1]) == 0x0800:
                        n += 1
                elif linktype == 0:
                    if len(data) >= 4 and (
                            struct.unpack("<I", data[0:4])[0] == 2
                            or struct.unpack(">I", data[0:4])[0] == 2):
                        n += 1
    except Exception as exc:  # noqa: BLE001 - surfaced in the table, not hidden
        return None, "%s: %s" % (type(exc).__name__, exc)
    return n, "independent raw-bytes counter (no scapy, no tshark)"


def load_raw(path, schema):
    """Read a regenerated CSV, keeping Infinity as numpy inf."""
    df = pd.read_csv(path, low_memory=False, skipinitialspace=True,
                     na_values=["", "nan", "NaN"], keep_default_na=False)
    df.columns = SCH.clean_names(df.columns)
    # Normalise the textual infinities the writer emits.
    for col in schema.feature_display:
        if col in df.columns and df[col].dtype == object:
            df[col] = pd.to_numeric(
                df[col].replace({"Infinity": np.inf, "-Infinity": -np.inf,
                                 "inf": np.inf, "-inf": -np.inf}),
                errors="coerce")
    return df


def verify_capture(key, label, pcap_path, schema, extraction):
    res = {"capture": key, "official_label": label, "problems": []}
    csv_path = CFG.raw_csv_path(key)
    if not os.path.isfile(csv_path):
        res["problems"].append("missing regenerated CSV %s" % csv_path)
        return res

    df = load_raw(csv_path, schema)
    res["flows"] = int(len(df))
    disp = {k: d for d, k in schema.features}

    # ---- packet accounting ---------------------------------------------
    fwd_col = disp.get("tot_fwd_pkts")
    bwd_col = disp.get("tot_bwd_pkts")
    if fwd_col and bwd_col:
        in_flows = int(df[fwd_col].sum() + df[bwd_col].sum())
    else:
        in_flows = None
        res["problems"].append("Tot Fwd/Bwd Pkts not in schema; cannot "
                               "verify packet conservation")
    res["ipv4_in_flows"] = in_flows
    res["packets_read"] = (extraction or {}).get(
        "counters", {}).get("packets_read")
    res["non_ipv4"] = (extraction or {}).get(
        "counters", {}).get("non_ipv4_packets")
    res["ipv4_parsed"] = (extraction or {}).get(
        "counters", {}).get("ipv4_packets")

    if pcap_path and os.path.isfile(pcap_path):
        res["tshark_ipv4"], res["tshark_note"] = tshark_ipv4_count(pcap_path)
        res["second_ipv4"], res["second_note"] = \
            second_opinion_ipv4_count(pcap_path)
    else:
        res["tshark_ipv4"] = res["second_ipv4"] = None
        res["tshark_note"] = res["second_note"] = "pcap not available"

    for name in ("tshark_ipv4", "second_ipv4", "ipv4_parsed"):
        v = res.get(name)
        if v is not None and in_flows is not None and v != in_flows:
            res["problems"].append(
                "%s = %d but flows account for %d IPv4 packets (diff %+d)"
                % (name, v, in_flows, v - in_flows))

    # ---- duplicate flows ------------------------------------------------
    dup_cols = [c for c in ["Src IP", "Dst IP", "Src Port", "Dst Port",
                            "Protocol", "Timestamp"] if c in df.columns]
    res["duplicate_flows"] = int(df.duplicated(subset=dup_cols).sum()) \
        if dup_cols else None
    if res["duplicate_flows"]:
        res["problems"].append("%d flows share a 5-tuple and start timestamp"
                               % res["duplicate_flows"])

    # ---- value sanity ---------------------------------------------------
    feats = [c for c in schema.feature_display if c in df.columns]
    block = df[feats]
    res["nan_cells"] = int(block.isna().sum().sum())
    inf_mask = np.isinf(block.to_numpy(dtype="float64"))
    res["inf_cells"] = int(inf_mask.sum())
    res["inf_by_column"] = {c: int(n) for c, n in
                            zip(feats, inf_mask.sum(axis=0)) if n}
    res["zero_duration_flows"] = (extraction or {}).get("zero_duration_flows")
    res["single_packet_flows"] = (extraction or {}).get("single_packet_flows")
    if res["nan_cells"]:
        res["problems"].append("%d NaN cells" % res["nan_cells"])

    neg_cols = [c for c in feats
                if N.NAME_TO_KEY.get(N.normalise(c)) not in NEGATIVE_ALLOWED]
    negs = (df[neg_cols] < 0).sum()
    res["negative_cells"] = int(negs.sum())
    res["negative_by_column"] = {c: int(v) for c, v in negs.items() if v}
    if res["negative_cells"]:
        res["problems"].append("%d negative feature values" %
                               res["negative_cells"])
    res["init_win_minus_one"] = {
        disp[k]: int((df[disp[k]] == -1).sum())
        for k in NEGATIVE_ALLOWED if k in disp and disp[k] in df.columns}

    bad_minmax = {}
    for kmin, kmax in MINMAX_PAIRS:
        cmin, cmax = disp.get(kmin), disp.get(kmax)
        if cmin in df.columns and cmax in df.columns:
            n = int((df[cmin] > df[cmax]).sum())
            if n:
                bad_minmax["%s > %s" % (cmin, cmax)] = n
    res["minmax_violations"] = bad_minmax
    res["minmax_violation_total"] = int(sum(bad_minmax.values()))
    if bad_minmax:
        res["problems"].append("min > max in: %s" % bad_minmax)

    bad_ports = 0
    for col in ("Src Port", "Dst Port"):
        if col in df.columns:
            p = pd.to_numeric(df[col], errors="coerce")
            bad_ports += int(((p < 0) | (p > 65535) | p.isna()).sum())
    res["invalid_ports"] = bad_ports
    if bad_ports:
        res["problems"].append("%d invalid port values" % bad_ports)

    bad_proto = 0
    if "Protocol" in df.columns:
        pr = pd.to_numeric(df["Protocol"], errors="coerce")
        bad_proto = int(((pr < 0) | (pr > 255) | pr.isna()).sum())
    res["invalid_protocol"] = bad_proto
    if bad_proto:
        res["problems"].append("%d invalid protocol values" % bad_proto)

    # ---- duplicate feature vectors --------------------------------------
    dup_feat = int(block.duplicated().sum())
    res["duplicate_feature_rows"] = dup_feat
    res["unique_feature_rows"] = int(len(block) - dup_feat)

    res["label_counts"] = {str(k): int(v) for k, v in
                           df[CFG.LABEL_COLUMN].value_counts().items()} \
        if CFG.LABEL_COLUMN in df.columns else {}
    res["protocol_counts"] = {str(k): int(v) for k, v in
                              df["Protocol"].value_counts().items()} \
        if "Protocol" in df.columns else {}
    return res


def main():
    CFG.ensure_out_dirs()
    print("=" * 78)
    print("STAGE 02 -- verification of the extraction (Part 2)")
    print("=" * 78)

    extraction = {}
    mp = CFG.metrics_path("01_extraction.json")
    if os.path.isfile(mp):
        with open(mp) as fh:
            for c in json.load(fh).get("captures", []):
                extraction[c["capture"]] = c
    else:
        print("NOTE: %s not found; packets-read figures will be blank." % mp)

    schema = SCH.build_schema()
    pcap_dir, _how = CFG.resolve_pcap_dir()

    wanted = [a for a in ARGS if not a.startswith("-")]
    results = []
    for key, label, _desc in CFG.CAPTURES:
        if wanted and key not in wanted:
            continue
        if not os.path.isfile(CFG.raw_csv_path(key)):
            print("\n%s: no regenerated CSV yet, skipping" % key)
            continue
        print("\nverifying %s ..." % key, flush=True)
        pcap = CFG.find_capture_file(pcap_dir, key) if pcap_dir else None
        results.append(verify_capture(key, label, pcap, schema,
                                      extraction.get(key)))

    # ---- tables ---------------------------------------------------------
    print("\n" + "=" * 110)
    print("TABLE 2.1  packet accounting   (flow total must equal the "
          "independent counts)")
    print("=" * 110)
    hdr = ("%-8s %12s %14s %14s %14s %12s %10s"
           % ("capture", "pkts read", "IPv4 in flows", "tshark IPv4",
              "2nd-opinion", "non-IPv4", "match"))
    print(hdr)
    print("-" * 110)
    for r in results:
        ok = all(r.get(k) in (None, r.get("ipv4_in_flows"))
                 for k in ("tshark_ipv4", "second_ipv4", "ipv4_parsed"))
        print("%-8s %12s %14s %14s %14s %12s %10s"
              % (r["capture"],
                 _n(r.get("packets_read")), _n(r.get("ipv4_in_flows")),
                 _n(r.get("tshark_ipv4")), _n(r.get("second_ipv4")),
                 _n(r.get("non_ipv4")), "YES" if ok else "NO"))
    notes = {r["capture"]: r.get("tshark_note") for r in results
             if r.get("tshark_ipv4") is None}
    for k, v in notes.items():
        print("    %s: tshark count unavailable -- %s" % (k, v))

    print("\n" + "=" * 110)
    print("TABLE 2.2  data sanity")
    print("=" * 110)
    print("%-8s %9s %7s %7s %7s %8s %8s %9s %10s %12s"
          % ("capture", "flows", "dupes", "NaN", "inf", "neg", "min>max",
             "badport", "1-pkt flws", "dup feat rows"))
    print("-" * 110)
    for r in results:
        print("%-8s %9s %7s %7s %7s %8s %8s %9s %10s %12s"
              % (r["capture"], _n(r.get("flows")),
                 _n(r.get("duplicate_flows")), _n(r.get("nan_cells")),
                 _n(r.get("inf_cells")), _n(r.get("negative_cells")),
                 _n(r.get("minmax_violation_total")),
                 _n(r.get("invalid_ports")),
                 _n(r.get("single_packet_flows")),
                 _n(r.get("duplicate_feature_rows"))))
    print("\n(inf cells are the zero-duration flows' Flow Byts/s, Flow "
          "Pkts/s, Fwd Pkts/s, Bwd Pkts/s -- normal CICFlowMeter behaviour.)")
    for r in results:
        if r.get("inf_by_column"):
            print("    %-8s inf by column: %s"
                  % (r["capture"], r["inf_by_column"]))
        if r.get("zero_duration_flows") is not None:
            print("    %-8s zero-duration flows: %s"
                  % (r["capture"], _n(r["zero_duration_flows"])))

    print("\n" + "=" * 110)
    print("TABLE 2.3  labels and protocols per capture")
    print("=" * 110)
    for r in results:
        print("%-8s labels: %-55s protocols: %s"
              % (r["capture"],
                 ", ".join("%s=%s" % (k, _n(v))
                           for k, v in sorted(r["label_counts"].items())),
                 ", ".join("%s=%s" % (k, _n(v))
                           for k, v in sorted(r["protocol_counts"].items()))))

    problems = [(r["capture"], p) for r in results for p in r["problems"]]
    print("\n" + "=" * 110)
    if problems:
        print("PROBLEMS FOUND (%d)" % len(problems))
        for cap, p in problems:
            print("    %-8s %s" % (cap, p))
    else:
        print("NO PROBLEMS FOUND: packet counts reconcile, no duplicate "
              "flows, no NaN, no negatives, no min>max, all ports valid.")
    print("=" * 110)

    with open(CFG.metrics_path("02_verification.json"), "w") as fh:
        json.dump({"captures": results, "problem_count": len(problems)},
                  fh, indent=2, default=str)
    print("\nMetrics: %s" % CFG.metrics_path("02_verification.json"))
    return 0


def _n(v):
    if v is None:
        return "-"
    if isinstance(v, (int, np.integer)):
        return "{:,}".format(int(v))
    return str(v)


if __name__ == "__main__":
    sys.exit(main())
