"""
Stage 01 -- PCAP -> flow CSV.

Usage (cmd):
    python 01_pcap_to_csv.py                  all six captures
    python 01_pcap_to_csv.py N-0              one capture (the quick test)
    python 01_pcap_to_csv.py N-0 Scan-1       a subset

Each capture is processed in two passes over the file:
  pass 1  build flows and total forward packets per Src IP  -> attackers
  pass 2  build flows again and write them out with the label

Two passes instead of one keeps memory flat: no flow rows and no packets are
ever held in RAM, which is what lets W-B-02 (~650k packets) and App-02
(~315k, ICMP-fragmented) run without the kernel dying.  Reading is the cheap
part of the job.

Output: OUT_DIR\\raw\\<capture>_flows.csv, with the column order
    Src IP, Dst IP, Src Port, Dst Port, Protocol, Timestamp,
    <the MSCAD features, names and order taken from the original CSV header>,
    Label
"""

import csv
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG      # noqa: E402
import mscad_names as N         # noqa: E402
import mscad_schema as SCH      # noqa: E402
from mscad_flowmeter import FlowEngine, US  # noqa: E402

ARGS = CFG.apply_overrides()


def fmt_timestamp(t_us):
    secs, micros = divmod(int(t_us), US)
    if CFG.TIMESTAMP_UTC:
        dt = datetime.datetime.fromtimestamp(secs, datetime.timezone.utc)
    else:
        dt = datetime.datetime.fromtimestamp(secs)
    return dt.replace(microsecond=micros).strftime(CFG.TIMESTAMP_FORMAT)


def fmt_value(key, v):
    """CSV text for one feature value."""
    if isinstance(v, str):
        return v
    if v != v:                              # NaN
        return "NaN"
    if v == float("inf"):
        return "Infinity"
    if v == float("-inf"):
        return "-Infinity"
    if key in N.INTEGER_KEYS:
        return str(int(round(v)))
    if isinstance(v, int):
        return str(v)
    if v == int(v) and abs(v) < 1e15:
        return str(int(v))
    return "%.10g" % v


def progress_printer(capture, t0):
    def _p(packets, open_flows, written):
        el = time.time() - t0
        rate = packets / el if el > 0 else 0
        print("    [%s] %10s packets  %7d open flows  %8d flows written"
              "  %6.0fs  %7.0f pkt/s"
              % (capture, "{:,}".format(packets), open_flows, written,
                 el, rate), flush=True)
    return _p


def detect_attackers(counts):
    """Attackers = every Src IP whose total forward packets reaches
    ATTACKER_SHARE of the top sender's."""
    if not counts:
        return set(), []
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    top = ranked[0][1]
    cutoff = CFG.ATTACKER_SHARE * top
    attackers = {ip for ip, c in ranked if c >= cutoff}
    return attackers, ranked


def process_capture(key, label, desc, path, schema, writer_factory):
    print("\n" + "-" * 78)
    print("CAPTURE %s  (%s)  -- %s" % (key, label, desc))
    print("  file: %s" % path)
    print("  size: %s bytes" % "{:,}".format(os.path.getsize(path)))
    is_normal = (key == "N-0")

    # ---------------- pass 1: attacker detection ------------------------
    attackers, ranked = set(), []
    pass1 = None
    if not is_normal:
        print("  pass 1/2: building flows to find attacker IPs ...")
        t0 = time.time()
        counts = {}

        def count_sink(d):
            ip = d["src_ip"]
            counts[ip] = counts.get(ip, 0) + d["tot_fwd_pkts"]

        eng = FlowEngine(count_sink, progress_printer(key + " p1", t0))
        eng.run(path)
        pass1 = {"flows": eng.flows_written,
                 "packets": eng.counters.total,
                 "seconds": round(time.time() - t0, 1)}
        attackers, ranked = detect_attackers(counts)
        top = ranked[0][1] if ranked else 0
        print("  top %d senders by total forward packets:"
              % CFG.ATTACKER_TOP_N_PRINT)
        for ip, c in ranked[:CFG.ATTACKER_TOP_N_PRINT]:
            share = (100.0 * c / top) if top else 0
            print("        %-16s %12s fwd pkts  (%6.2f%% of top)%s"
                  % (ip, "{:,}".format(c), share,
                     "   <-- ATTACKER" if ip in attackers else ""))
        print("  attackers (>= %.0f%% of top sender): %s"
              % (100 * CFG.ATTACKER_SHARE,
                 ", ".join(sorted(attackers)) or "(none)"))
    else:
        print("  normal capture: every flow is labelled %r, "
              "no attacker detection" % label)

    # ---------------- pass 2: write flows -------------------------------
    print("  pass %s: writing flows ..." % ("2/2" if not is_normal else "1/1"))
    t0 = time.time()
    out_path = CFG.raw_csv_path(key)
    feature_keys = schema.feature_keys
    rows = [0]
    label_counts = {}

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(schema.out_columns)

        def sink(d):
            if is_normal:
                lab = label
            elif d["src_ip"] in attackers or d["dst_ip"] in attackers:
                lab = label
            else:
                lab = CFG.BENIGN_LABEL
            row = [d["src_ip"], d["dst_ip"], d["src_port"], d["dst_port"],
                   d["protocol"], fmt_timestamp(d["timestamp"])]
            row.extend(fmt_value(k, d[k]) for k in feature_keys)
            row.append(lab)
            w.writerow(row)
            rows[0] += 1
            label_counts[lab] = label_counts.get(lab, 0) + 1

        eng = FlowEngine(sink, progress_printer(key + " p2", t0))
        counters = eng.run(path)

    elapsed = time.time() - t0
    print("  wrote %s flows to %s in %.1fs"
          % ("{:,}".format(rows[0]), out_path, elapsed))
    print("  packets read            : %s" % "{:,}".format(counters.total))
    print("  IPv4 packets in flows   : %s" % "{:,}".format(counters.ipv4))
    print("  non-IPv4 (ARP/IPv6/...) : %s" % "{:,}".format(counters.non_ipv4))
    print("  non-first IP fragments  : %s" % "{:,}".format(counters.fragments))
    print("  IPv4 by protocol        : %s"
          % ", ".join("%d:%s" % (p, "{:,}".format(c))
                      for p, c in sorted(counters.by_proto.items())))
    print("  single-packet flows     : %s"
          % "{:,}".format(eng.single_packet_flows))
    print("  zero-duration flows     : %s"
          % "{:,}".format(eng.zero_duration_flows))
    print("  labels                  : %s"
          % ", ".join("%s=%s" % (k, "{:,}".format(v))
                      for k, v in sorted(label_counts.items())))

    return {
        "capture": key,
        "official_label": label,
        "description": desc,
        "file": path,
        "file_bytes": os.path.getsize(path),
        "flows": rows[0],
        "label_counts": label_counts,
        "attackers": sorted(attackers),
        "top_senders": [{"src_ip": ip, "fwd_pkts": c} for ip, c in ranked[:10]],
        "pass1": pass1,
        "seconds": round(elapsed, 1),
        "single_packet_flows": eng.single_packet_flows,
        "zero_duration_flows": eng.zero_duration_flows,
        "counters": counters.as_dict(),
        "out_csv": out_path,
    }


def main():
    CFG.ensure_out_dirs()
    print("=" * 78)
    print("STAGE 01 -- PCAP -> flow CSV")
    print("=" * 78)
    print("flow timeout %.0fs | idle timeout %.0fs | activity %.0fs | "
          "clump %.0fs" % (CFG.FLOW_TIMEOUT, CFG.IDLE_TIMEOUT,
                           CFG.ACTIVITY_TIMEOUT, CFG.CLUMP_TIMEOUT))
    print("pkt-len mode %r | header-len mode %r | std ddof %d | subflow %r"
          % (CFG.PKT_LEN_MODE, CFG.HEADER_LEN_MODE, CFG.STD_DDOF,
             CFG.SUBFLOW_MODE))
    print("time features in MICROSECONDS")

    pcap_dir, how = CFG.resolve_pcap_dir()
    if pcap_dir is None:
        print("\nFATAL: PCAP folder not found. Candidates tried:")
        for c in CFG.PCAP_DIR_CANDIDATES:
            print("    %s" % c)
        print("Also searched recursively under %s" % CFG.PCAP_SEARCH_ROOT)
        return 2
    print("\nPCAP folder: %s  (%s)" % (pcap_dir, how))

    schema = SCH.build_schema()
    print(schema.describe())
    if schema.unknown:
        print("NOTE: the unmapped columns above are NOT written to the output.")

    wanted = [a for a in ARGS if not a.startswith("-")]
    captures = [c for c in CFG.CAPTURES if not wanted or c[0] in wanted]
    if wanted:
        unknown = set(wanted) - {c[0] for c in CFG.CAPTURES}
        if unknown:
            print("FATAL: unknown capture key(s): %s" % ", ".join(unknown))
            return 2

    results, failures = [], []
    t_all = time.time()
    for key, label, desc in captures:
        path = CFG.find_capture_file(pcap_dir, key)
        if path is None:
            msg = ("capture %s: no file named %s%s in %s"
                   % (key, key, "/".join(CFG.PCAP_EXTENSIONS), pcap_dir))
            print("\nERROR: " + msg)
            failures.append({"capture": key, "error": msg})
            continue
        try:
            results.append(process_capture(key, label, desc, path, schema,
                                           None))
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            import traceback
            print("\nERROR while processing %s:" % key)
            traceback.print_exc()
            failures.append({"capture": key,
                             "error": "%s: %s" % (type(exc).__name__, exc)})

    out = {
        "pcap_dir": pcap_dir,
        "pcap_dir_how": how,
        "schema_source": schema.source,
        "schema_features": schema.feature_display,
        "schema_unmapped": schema.unknown,
        "config": {
            "flow_timeout_s": CFG.FLOW_TIMEOUT,
            "idle_timeout_s": CFG.IDLE_TIMEOUT,
            "activity_timeout_s": CFG.ACTIVITY_TIMEOUT,
            "clump_timeout_s": CFG.CLUMP_TIMEOUT,
            "pkt_len_mode": CFG.PKT_LEN_MODE,
            "header_len_mode": CFG.HEADER_LEN_MODE,
            "std_ddof": CFG.STD_DDOF,
            "subflow_mode": CFG.SUBFLOW_MODE,
            "init_win_default": CFG.INIT_WIN_DEFAULT,
            "java_integer_division": CFG.JAVA_INTEGER_DIVISION,
            "drop_single_packet_flows": CFG.DROP_SINGLE_PACKET_FLOWS,
            "add_final_active_segment": CFG.ADD_FINAL_ACTIVE_SEGMENT,
            "attacker_share": CFG.ATTACKER_SHARE,
            "close_flow_on_fin": CFG.CLOSE_FLOW_ON_FIN,
            "close_flow_on_rst": CFG.CLOSE_FLOW_ON_RST,
        },
        "captures": results,
        "failures": failures,
        "total_seconds": round(time.time() - t_all, 1),
    }
    name = ("01_extraction.json" if not wanted
            else "01_extraction_%s.json" % "_".join(wanted))
    with open(CFG.metrics_path(name), "w") as fh:
        json.dump(out, fh, indent=2, default=str)

    print("\n" + "=" * 78)
    print("STAGE 01 SUMMARY  (%.1fs total)" % out["total_seconds"])
    print("=" * 78)
    print("%-8s %10s %12s %12s  %s"
          % ("capture", "flows", "pkts read", "IPv4 flows", "labels"))
    for r in results:
        print("%-8s %10s %12s %12s  %s"
              % (r["capture"], "{:,}".format(r["flows"]),
                 "{:,}".format(r["counters"]["packets_read"]),
                 "{:,}".format(r["counters"]["ipv4_packets"]),
                 ", ".join("%s=%d" % kv
                           for kv in sorted(r["label_counts"].items()))))
    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("    %s: %s" % (f["capture"], f["error"]))
    print("\nMetrics: %s" % CFG.metrics_path(name))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
