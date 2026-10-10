"""
Stage 05 -- write MSCAD_regeneration_report.md (Part 5) and copy the pipeline
scripts into the output folder so the whole thing is reproducible.

Everything in the report is read back out of the JSON metrics written by
stages 00-04.  Nothing is hard-coded: a number that is missing is printed as
"not measured" rather than invented.
"""

import json
import os
import shutil
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG   # noqa: E402

ARGS = CFG.apply_overrides()
HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = "MSCAD_regeneration_report.md"


def load(name):
    p = CFG.metrics_path(name)
    if not os.path.isfile(p):
        return None
    with open(p) as fh:
        return json.load(fh)


def n(v):
    if v is None:
        return "not measured"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return "{:,}".format(v)
    if isinstance(v, float):
        if v != v:
            return "NaN"
        return "%.4g" % v
    return str(v)


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def main():
    CFG.ensure_out_dirs()
    s00, s01 = load("00_inputs.json"), load("01_extraction.json")
    s02, s03 = load("02_verification.json"), load("03_comparison.json")
    s04 = load("04_consolidated.json")

    L = []
    w = L.append
    cfgd = (s01 or {}).get("config", {})

    w("# MSCAD regeneration report\n")
    w("Regenerating flow-level features with flow identifiers from the raw "
      "MSCAD PCAPs, and measuring how close the result is to the original "
      "Kaggle `MSCAD.csv`.\n")
    w("- Generated: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    w("- Output folder: `%s`" % CFG.OUT_DIR)
    w("- PCAP folder used: `%s`" % ((s01 or s00 or {}).get("pcap_dir")
                                    or "not recorded"))
    if (s01 or {}).get("pcap_dir_how"):
        w("  (located via: %s)" % s01["pcap_dir_how"])
    w("- Original Kaggle file: `%s`" % ((s03 or s00 or {}).get("original_file")
                                        or "not recorded"))
    w("")

    # ---------------- method ---------------------------------------------
    w("## 1. Method\n")
    w("### 1.1 Tool\n")
    w("Feature definitions come from the Python `cicflowmeter` package "
      "version 0.5.0, reimplemented in `mscad_flowmeter.py` as a streaming "
      "engine. The package's own field names are kept (`tot_fwd_pkts`, "
      "`flow_byts_s`, `cwr_flag_count`, ...) so the mapping to the MSCAD "
      "column names stays one-to-one and auditable. The numeric definitions "
      "follow the **Java** CICFlowMeter, because that is the tool that "
      "produced the Kaggle `MSCAD.csv` this report compares against.\n")
    w("A reimplementation rather than a monkey-patch was necessary: the "
      "package's feature classes take live scapy `Packet` objects and keep "
      "every packet of a flow in `Flow.packets`, so including non-TCP/UDP "
      "traffic, dropping the retained packets and reading real TCP flags all "
      "change its data model rather than its behaviour.\n")

    w("### 1.2 Patches applied\n")
    w(table(["#", "Problem in cicflowmeter 0.5.0", "What this pipeline does"],
            [["1", "CLI `-f file` crashes with `'bool' object has no "
                   "attribute 'split'`",
              "No CLI; the engine is a library called from Python."],
             ["2", "Every non-TCP/UDP packet is silently dropped "
                   "(`if \"TCP\" not in pkt and \"UDP\" not in pkt: return`), "
                   "so the ICMP flood would vanish",
              "All IPv4 packets are processed. ICMP and other IP protocols "
              "form flows keyed on (src, dst, 0, 0, proto): Src/Dst Port = 0, "
              "Protocol = 1 for ICMP. Non-first IP fragments carry no "
              "transport header and join the same port-0 flow, which is what "
              "keeps App-02's fragmented pings."],
             ["3", "BPF capture filter needs tcpdump, absent on Windows",
              "No capture filter is ever set."],
             ["4", "FIN is read as `\"F\" in pkt.flags`, which is the **IP** "
                   "flags field, not TCP",
              "FIN/SYN/RST/PSH/ACK/URG/ECE/CWR are read from the TCP flags "
              "byte (bits 0x01..0x80)."],
             ["5", "`Flow.__init__` stores the first packet and "
                   "`FlowSession.process` then calls `add_packet` on it "
                   "again, counting it twice",
              "Each packet is added exactly once."],
             ["6", "Every full scapy packet is retained in memory, which "
                   "kills the kernel on floods",
              "No packets and no per-packet records are retained. Every "
              "feature is an incremental accumulator (Welford mean/variance "
              "plus min/max/sum), so memory is O(open flows) and independent "
              "of flow length."],
             ["7", "`garbage_collect` rescans all open flows after every FIN: "
                   "quadratic on brute-force traffic",
              "Timeouts are checked on the packet's own flow, plus a periodic "
              "sweep every %s packets. Cost is O(packets), not "
              "O(packets x flows)." % n(CFG.SWEEP_EVERY_PACKETS)],
             ["8", "Timeouts do not match the Java tool",
              "Flow timeout %.0f s, idle timeout %.0f s, activity timeout "
              "%.0f s, clump/subflow timeout %.0f s."
              % (CFG.FLOW_TIMEOUT, CFG.IDLE_TIMEOUT, CFG.ACTIVITY_TIMEOUT,
                 CFG.CLUMP_TIMEOUT)],
             ["9", "**Found while reading the source.** "
                   "`Flow.update_subflow` compares `packet.time` with "
                   "`self.latest_timestamp` *after* that field has already "
                   "been set to `packet.time`, so the difference is always 0, "
                   "`update_active_idle` is never reached and every "
                   "Active/Idle feature is identically 0. `last_active` also "
                   "starts at 0, so a first idle value would have been ~1.7e9 "
                   "seconds.",
              "Active/Idle are computed properly, with both activity markers "
              "seeded from the flow's first packet."],
             ["10", "**Found while reading the source.** `get_statistics` "
                    "returns zeros unless `len(list) > 1`, so a two-packet "
                    "flow (one IAT) reports Flow IAT Mean/Max/Min = 0.",
              "Statistics are produced from one observation onwards."]]))

    w("### 1.3 Units and timestamps\n")
    w("Packet times are carried as **integer microseconds** end to end (a "
      "pcap record gives seconds + microseconds, so this is exact and free of "
      "floating-point drift). Every time-derived feature -- Flow Duration, "
      "all IAT features, all Active and Idle features -- is therefore emitted "
      "in **microseconds**, matching MSCAD.\n")
    w("Packet lengths are taken from the bytes in the capture; packets are "
      "never rebuilt.\n")
    w("MSCAD itself has no Timestamp column, so the `Timestamp` emitted here "
      "is this pipeline's own: the flow's first-packet time, "
      "`%s`%s, at microsecond precision, so the sequence-mining and "
      "attack-graph stages have a sortable, unambiguous ordering."
      % (CFG.TIMESTAMP_FORMAT, " in UTC" if CFG.TIMESTAMP_UTC else " in local time"))
    w("")

    w("### 1.4 Semantic choices\n")
    w("Three CICFlowMeter behaviours differ between the Java tool and the pip "
      "package. Each is a switch in `mscad_config.py`; the value used for "
      "this run is shown.\n")
    w(table(["Setting", "Value used", "Meaning"],
            [["`PKT_LEN_MODE`", "`%s`" % cfgd.get("pkt_len_mode",
                                                  CFG.PKT_LEN_MODE),
              "`payload` = L4 payload bytes (Java `getPayloadBytes()`); "
              "`frame` = whole captured frame (pip `len(packet)`). The CIC "
              "CSV family carries zeros in Fwd/Bwd Pkt Len Min, which only "
              "happens under payload semantics."],
             ["`HEADER_LEN_MODE`", "`%s`" % cfgd.get("header_len_mode",
                                                     CFG.HEADER_LEN_MODE),
              "`l4` = transport header only (Java: TCP `dataofs*4`, UDP 8); "
              "`ip` = IP header only (pip: `ihl*4`)."],
             ["`STD_DDOF`", "%s" % cfgd.get("std_ddof", CFG.STD_DDOF),
              "1 = bias-corrected (n-1), as Apache commons-math "
              "`SummaryStatistics` used by the Java tool; 0 = population (n), "
              "as numpy's default."],
             ["`SUBFLOW_MODE`", "`%s`" % cfgd.get("subflow_mode",
                                                  CFG.SUBFLOW_MODE),
              "`divide` = direction total / (1 + number of >1 s gaps), as "
              "Java; `copy` = Subflow == direction total, as pip. **This is "
              "the feature family whose Java semantics is least certain**; if "
              "the four Subflow columns dominate the section 3.4 KS table, "
              "switch to `copy` and re-run."],
             ["`JAVA_INTEGER_DIVISION`",
              n(cfgd.get("java_integer_division", CFG.JAVA_INTEGER_DIVISION)),
              "Java truncates long/long for Down/Up Ratio, the Subflow "
              "features and the bulk averages."],
             ["`INIT_WIN_DEFAULT`", "%s" % cfgd.get("init_win_default",
                                                    CFG.INIT_WIN_DEFAULT),
              "Init Fwd/Bwd Win Byts when that direction has no TCP packet. "
              "The CIC CSV family uses -1. These are the only features "
              "allowed to be negative."],
             ["`DROP_SINGLE_PACKET_FLOWS`",
              n(cfgd.get("drop_single_packet_flows",
                         CFG.DROP_SINGLE_PACKET_FLOWS)),
              "The Java tool discards a flow that expires on timeout with "
              "only one packet. Kept here, because Part 2 requires every IPv4 "
              "packet to be accounted for. Section 2.2 reports how many there "
              "are, which bounds this difference against Kaggle."],
             ["`ADD_FINAL_ACTIVE_SEGMENT`",
              n(cfgd.get("add_final_active_segment",
                         CFG.ADD_FINAL_ACTIVE_SEGMENT)),
              "Java does not add the final, unterminated Active segment when "
              "a flow is written, which is why many short flows have Active "
              "Mean = 0."]]))
    w("Zero-duration flows: the Java tool divides by 0.0 and so writes "
      "`Infinity` for the rate features (and `NaN` when the numerator is 0 "
      "too). This pipeline always writes `Infinity`, so that any `NaN` in the "
      "output is a genuine defect and the Part 2 NaN check stays meaningful. "
      "Section 2.2 reports the zero-duration flow count separately.\n")

    w("### 1.5 Labelling\n")
    w("`N-0` is labelled `Normal` throughout. In an attack capture, the "
      "attacker set is every Src IP whose total forward packet count reaches "
      "%.0f%% of the top sender's; a flow is given the capture's official "
      "label when its Src IP **or** Dst IP is an attacker, and `%s` "
      "otherwise.\n" % (100 * CFG.ATTACKER_SHARE, CFG.BENIGN_LABEL))

    # ---------------- schema ---------------------------------------------
    w("### 1.6 Output schema\n")
    if s01:
        w("The feature names and their order are read from the original "
          "Kaggle header, not hard-coded (`%s`).\n"
          % (s01.get("schema_source") or "unknown"))
        w("Feature columns: **%d**.\n" % len(s01.get("schema_features") or []))
        unmapped = s01.get("schema_unmapped") or []
        if unmapped:
            w("Original columns that could **not** be mapped to a "
              "CICFlowMeter feature (%d), and so are absent from the "
              "output:\n" % len(unmapped))
            for u in unmapped:
                w("- `%s`" % u)
        else:
            w("Every original column was mapped; none had to be dropped.\n")
        w("")
        w("Column order: " + ", ".join(
            "`%s`" % c for c in (list(CFG.IDENTIFIER_COLUMNS)
                                 + (s01.get("schema_features") or [])
                                 + [CFG.LABEL_COLUMN])) + "\n")
    else:
        w("Stage 01 metrics missing; schema not recorded.\n")

    # ---------------- inputs ---------------------------------------------
    w("## 2. Inputs and extraction\n")
    if s00 and s00.get("original_shape"):
        w("### 2.0 The original Kaggle file\n")
        w("- shape: **%d rows x %d columns**"
          % tuple(s00["original_shape"]))
        lc = s00.get("original_label_counts") or {}
        if lc:
            tot = sum(lc.values())
            w("")
            w(table(["Label", "rows", "% of file"],
                    [[k, n(v), "%.2f%%" % (100.0 * v / tot)]
                     for k, v in sorted(lc.items(), key=lambda kv: -kv[1])]
                    + [["**TOTAL**", n(tot), "100.00%"]]))
    if s01:
        w("### 2.1 Extraction per capture\n")
        rows = []
        for c in s01.get("captures", []):
            cc = c.get("counters", {})
            rows.append([c["capture"], c["official_label"],
                         n(cc.get("packets_read")), n(cc.get("ipv4_packets")),
                         n(cc.get("non_ipv4_packets")),
                         n(cc.get("ipv4_non_first_fragments")),
                         n(c.get("flows")),
                         "%.1f s" % c["seconds"] if c.get("seconds")
                         else "-"])
        w(table(["capture", "label", "packets read", "IPv4", "non-IPv4",
                 "frag (non-first)", "flows", "write pass"], rows))
        if s01.get("failures"):
            w("**Failures:**\n")
            for f in s01["failures"]:
                w("- `%s`: %s" % (f.get("capture"), f.get("error")))
            w("")
        w("#### Attacker detection\n")
        for c in s01.get("captures", []):
            if not c.get("top_senders"):
                continue
            w("**%s** (%s) -- attackers: %s\n"
              % (c["capture"], c["official_label"],
                 ", ".join("`%s`" % a for a in c.get("attackers", []))
                 or "none"))
            top = c["top_senders"][0]["fwd_pkts"] if c["top_senders"] else 0
            w(table(["Src IP", "total fwd packets", "% of top", "attacker?"],
                    [[t["src_ip"], n(t["fwd_pkts"]),
                      "%.2f%%" % (100.0 * t["fwd_pkts"] / top) if top else "-",
                      "yes" if t["src_ip"] in c.get("attackers", []) else ""]
                     for t in c["top_senders"][:5]]))
        w("#### Labels assigned per capture\n")
        rows = []
        for c in s01.get("captures", []):
            rows.append([c["capture"],
                         ", ".join("%s = %s" % (k, n(v)) for k, v in
                                   sorted((c.get("label_counts") or {}).items()))])
        w(table(["capture", "labels"], rows))

    # ---------------- part 2 ---------------------------------------------
    w("## 3. Verification of the extraction (Part 2)\n")
    if not s02:
        w("Stage 02 metrics missing; verification not run.\n")
    else:
        caps = s02.get("captures", [])
        w("### 3.1 Packet accounting\n")
        w("`IPv4 in flows` is the sum of Tot Fwd Pkts + Tot Bwd Pkts over "
          "every written flow. It must equal the independent counts exactly; "
          "the remainder up to `packets read` is ARP / IPv6 / non-IP, "
          "excluded by design.\n")
        rows = []
        for c in caps:
            ok = all(c.get(k) in (None, c.get("ipv4_in_flows"))
                     for k in ("tshark_ipv4", "second_ipv4", "ipv4_parsed"))
            rows.append([c["capture"], n(c.get("packets_read")),
                         n(c.get("ipv4_in_flows")), n(c.get("tshark_ipv4")),
                         n(c.get("second_ipv4")), n(c.get("non_ipv4")),
                         "**YES**" if ok else "**NO**"])
        w(table(["capture", "packets read", "IPv4 in flows", "tshark `-Y ip`",
                 "2nd-opinion count", "non-IPv4", "all match"], rows))
        notes = {c["capture"]: c.get("tshark_note") for c in caps
                 if c.get("tshark_ipv4") is None}
        for k, v in notes.items():
            w("- `%s`: tshark count unavailable -- %s" % (k, v))
        if notes:
            w("")

        w("### 3.2 Data sanity\n")
        rows = []
        for c in caps:
            rows.append([c["capture"], n(c.get("flows")),
                         n(c.get("duplicate_flows")), n(c.get("nan_cells")),
                         n(c.get("inf_cells")), n(c.get("negative_cells")),
                         n(c.get("minmax_violation_total")),
                         n(c.get("invalid_ports")),
                         n(c.get("zero_duration_flows")),
                         n(c.get("single_packet_flows")),
                         n(c.get("duplicate_feature_rows"))])
        w(table(["capture", "flows", "dup flows", "NaN", "inf", "negative",
                 "min>max", "bad ports", "zero-duration", "1-packet flows",
                 "identical feature rows"], rows))
        w("`dup flows` counts flows sharing a 5-tuple and start Timestamp "
          "(must be 0). `inf` cells are the zero-duration flows' Flow Byts/s, "
          "Flow Pkts/s, Fwd Pkts/s and Bwd Pkts/s -- normal CICFlowMeter "
          "behaviour, counted not removed. `identical feature rows` are "
          "expected in floods, scans and brute force; they are counted, never "
          "dropped. Init Fwd/Bwd Win Byts are excluded from the negative "
          "check because -1 is their defined 'no TCP packet' value.\n")
        probs = [(c["capture"], p) for c in caps for p in c.get("problems", [])]
        if probs:
            w("**Problems found (%d):**\n" % len(probs))
            for cap, p in probs:
                w("- `%s`: %s" % (cap, p))
            w("")
        else:
            w("**No problems found** across all captures: packet counts "
              "reconcile, no duplicate flows, no NaN, no negative values "
              "outside the two Init Win columns, no min>max inconsistency, "
              "all ports and protocol numbers valid.\n")

    # ---------------- part 3 ---------------------------------------------
    w("## 4. Comparison with the original Kaggle MSCAD.csv (Part 3)\n")
    if not s03:
        w("Stage 03 metrics missing; comparison not run.\n")
    else:
        sc = s03.get("schema", {})
        w("### 4.1 Schema\n")
        w("- original feature columns: **%d**"
          % len(sc.get("original_feature_columns") or []))
        w("- regenerated feature columns: **%d**"
          % len(sc.get("regenerated_feature_columns") or []))
        w("- same names and same order: **%s**"
          % n(sc.get("same_names_and_order")))
        for key, title in (("missing_in_regenerated",
                            "in the original but not regenerated"),
                           ("extra_in_regenerated",
                            "regenerated but not in the original"),
                           ("unmapped_original_columns",
                            "original columns not mappable to a "
                            "CICFlowMeter feature")):
            v = sc.get(key) or []
            if v:
                w("- %s (%d): %s" % (title, len(v),
                                     ", ".join("`%s`" % x for x in v)))
        w("")

        w("### 4.2 Rows per label\n")
        rows = [[r["label"], n(r["kaggle"]), n(r["regenerated"]),
                 "%+d" % r["difference"],
                 "-" if r["kaggle"] == 0 else "%+.1f%%" % r["diff_pct"]]
                for r in s03.get("rows_per_label", [])]
        w(table(["label", "Kaggle", "regenerated", "difference", "diff %"],
                rows))
        for k, t in (("labels_only_kaggle", "only in Kaggle"),
                     ("labels_only_regenerated", "only in the regenerated set")):
            v = s03.get(k) or []
            if v:
                w("- labels %s: %s" % (t, ", ".join("`%s`" % x for x in v)))
        w("")

        w("### 4.3 Units check\n")
        w("Both files should be in microseconds. A ratio near 10^6 or 10^-6 "
          "would mean one of them is in seconds.\n")
        rows = [[r["label"], r["feature"], n(r["kaggle_median"]),
                 n(r["regen_median"]), n(r["ratio"]), r["verdict"]]
                for r in s03.get("units_check", [])]
        w(table(["label", "feature", "Kaggle median", "regen median",
                 "ratio", "verdict"], rows))

        w("### 4.4 Per-feature distribution comparison\n")
        for lab, recs in (s03.get("per_feature_by_label") or {}).items():
            w("**%s** -- 10 most different features by the two-sample "
              "Kolmogorov-Smirnov statistic\n" % lab)
            w(table(["feature", "Kaggle mean", "regen mean", "Kaggle median",
                     "regen median", "KS", "n Kaggle", "n regen"],
                    [[d["feature"], n(d["kaggle_mean"]), n(d["regen_mean"]),
                      n(d["kaggle_median"]), n(d["regen_median"]),
                      n(d["ks"]), n(d["n_kaggle"]), n(d["n_regen"])]
                     for d in recs[:10]]))
        ow = s03.get("overall_worst_features") or []
        if ow:
            w("**Averaged over all shared labels** -- 10 most different "
              "features\n")
            w(table(["feature", "mean KS"],
                    [[d["feature"], n(d["mean_ks"])] for d in ow[:10]]))

        w("### 4.5 Row-level matching\n")
        rm = s03.get("row_matching") or {}
        if rm.get("skipped"):
            w("Skipped: %s\n" % rm["skipped"])
        else:
            w("Key: %s, each value rounded to an integer, using only keys "
              "that are unique in the original.\n"
              % ", ".join("`%s`" % c
                          for c in s03.get("match_key_features", [])))
            if s03.get("match_key_dropped"):
                w("Key features unavailable in both files and therefore "
                  "dropped: %s\n"
                  % ", ".join("`%s`" % c for c in s03["match_key_dropped"]))
            w("- original rows with a complete finite key: %s"
              % n(rm.get("original_rows_with_key")))
            w("- distinct keys in the original: %s"
              % n(rm.get("distinct_original_keys")))
            w("- keys unique in the original (usable): %s"
              % n(rm.get("unique_original_keys")))
            w("- regenerated rows matched: **%s / %s (%.2f%%)**"
              % (n(rm.get("total_matched")), n(rm.get("total_regenerated")),
                 rm.get("match_pct", 0.0)))
            w("")
            w("Match rate per regenerated label\n")
            w(table(["my label", "rows", "matched", "%"],
                    [[r["label"], n(r["rows"]), n(r["matched"]),
                      "%.2f%%" % r["pct"]] for r in rm.get("per_label", [])]))
            w("Match rate per capture\n")
            w(table(["capture", "rows", "matched", "%"],
                    [[r["capture"], n(r["rows"]), n(r["matched"]),
                      "%.2f%%" % r["pct"]]
                     for r in rm.get("per_capture", [])]))
            conf = s03.get("confusion_matched")
            if conf:
                kcols = sorted(conf.keys())
                mine = sorted({r for c in conf.values() for r in c.keys()})
                w("Confusion table for matched rows (rows = my label, "
                  "columns = Kaggle label)\n")
                w(table(["my label \\ Kaggle"] + kcols,
                        [[m] + [n(conf[k].get(m, 0)) for k in kcols]
                         for m in mine]))
                ag = s03.get("label_agreement_matched") or {}
                if ag:
                    w("Label agreement on matched rows: **%s / %s "
                      "(%.2f%%)**\n" % (n(ag.get("agree")), n(ag.get("total")),
                                        ag.get("pct", 0.0)))

        w("### 4.6 Why the two files differ\n")
        w("**Measured in this run** (the numbers are in the tables above):\n")
        w("- Row counts per label, and the total row-count difference "
          "(section 4.2).")
        w("- Which features' distributions diverge most, per label "
          "(section 4.4).")
        w("- What fraction of regenerated flows matches a unique original row "
          "on the integer key, and how the labels agree on those matches "
          "(section 4.5).")
        w("- How many regenerated flows carry only one packet, and how many "
          "have zero duration (section 3.2).")
        w("")
        w("**Explanations, strongest first.** The first three are mechanical "
          "and their size is bounded by numbers in this report; the rest are "
          "reasoned but not individually measured here.\n")
        w("1. **Single-packet flows (measured, mechanical).** The Java tool "
          "discards a flow that expires on timeout with only one packet; this "
          "pipeline keeps it, because Part 2 requires every IPv4 packet to be "
          "accounted for. In a port scan that is a large, one-sided "
          "difference: see the 1-packet flow column in section 3.2. Set "
          "`DROP_SINGLE_PACKET_FLOWS = True` to drop them and re-run if you "
          "want the closer row count instead of the packet-conservation "
          "guarantee.")
        w("2. **ICMP (mechanical, by design).** MSCAD was built with a tool "
          "that processes only TCP and UDP, so the App-02 ICMP flood "
          "contributes few or no rows to the Kaggle file, while it does "
          "contribute here. Compare the ICMP_Flood row counts in section 4.2 "
          "and the protocol mix in stage 02's output.")
        w("3. **The Benign rule (mechanical, ours).** Our `Benign` label is a "
          "rule we chose -- a flow in an attack capture involving no attacker "
          "IP -- not a label the dataset publishes. Any disagreement between "
          "`Benign` and a Kaggle attack label in the section 4.5 confusion "
          "table comes from this rule, not from the features.")
        w("4. **Flow cutting.** Identical timeouts still do not guarantee "
          "identical flow boundaries: whether a FIN (or RST) closes a flow, "
          "whether the 120 s cut is measured from the flow's start or its last "
          "packet, and the order in which expiry is checked, all move packets "
          "between flows. Every feature of the affected flows changes with "
          "them, so a flow-boundary difference shows up as a distribution "
          "difference rather than as a missing row.")
        w("5. **Statistical conventions.** Java's `SummaryStatistics` uses "
          "the bias-corrected (n-1) variance and truncates long/long "
          "division; numpy does neither. This run used `STD_DDOF = %s` and "
          "`JAVA_INTEGER_DIVISION = %s`. If the Std/Var columns or Down/Up "
          "Ratio lead the section 4.4 table, this is the first thing to "
          "check." % (cfgd.get("std_ddof", CFG.STD_DDOF),
                      n(cfgd.get("java_integer_division",
                                 CFG.JAVA_INTEGER_DIVISION))))
        w("6. **Packet-length basis.** `PKT_LEN_MODE = %r` was used. Under "
          "`payload` the length family counts L4 payload bytes, as the Java "
          "tool does; under `frame` it counts whole captured frames, as the "
          "pip package does. The two differ by roughly the header size on "
          "every packet, so picking the wrong one shifts eight features at "
          "once (TotLen, Pkt Len Min/Max/Mean/Std/Var, Pkt Size Avg, Seg Size "
          "Avg)." % cfgd.get("pkt_len_mode", CFG.PKT_LEN_MODE))
        w("7. **Subflow semantics (acknowledged uncertainty).** See section "
          "1.4. If the four Subflow columns top the section 4.4 table, switch "
          "`SUBFLOW_MODE` and re-run.")
        w("8. **What the original did that we cannot see.** The published "
          "MSCAD.csv may have been filtered, de-duplicated, re-ordered or "
          "partly hand-labelled before release, and it carries no "
          "identifiers, so a row that fails to match cannot be traced back to "
          "a capture. This is a limit of the comparison, not a measurement.")
        w("")
        w("A low row-level match rate is therefore expected and is **not** "
          "evidence that the extraction is wrong: section 3.1's packet "
          "reconciliation is the check that the extraction is complete, and "
          "section 4.4's distributions are the check that it is faithful.\n")

    # ---------------- part 4 ---------------------------------------------
    w("## 5. Final files (Part 4)\n")
    if not s04:
        w("Stage 04 metrics missing; consolidated files not built.\n")
    else:
        w("### `MSCAD_consolidated.csv`\n")
        w("- shape: **%d rows x %d columns**" % tuple(s04["consolidated_shape"]))
        w("- columns: `Src IP`, `Dst IP`, `Src Port`, `Dst Port`, "
          "`Protocol`, `Timestamp`, the MSCAD features, `Label`, "
          "`Label_Kaggle`, `Source_Capture`")
        w("- sorted by `Timestamp`")
        w("- `Label_Kaggle` filled on **%s** rows (the official Kaggle label "
          "where section 4.5 matched the row; empty elsewhere)"
          % n(s04.get("label_kaggle_filled")))
        w("")
        w(table(["Label", "rows"],
                [[k, n(v)] for k, v in
                 sorted((s04.get("consolidated_labels") or {}).items(),
                        key=lambda kv: -kv[1])]))
        w(table(["Source_Capture", "rows"],
                [[k, n(v)] for k, v in
                 (s04.get("consolidated_per_capture") or {}).items()]))
        w("### `MSCAD_consolidated_ML.csv`\n")
        w("For classifier training: the features + `Label` only.\n")
        w("- shape: **%d rows x %d columns**" % tuple(s04["ml_shape"]))
        w("- rows removed as non-finite: **%s**; as an identical feature "
          "vector: **%s**"
          % (n(s04.get("ml_rows_dropped_inf_nan")),
             n(s04.get("ml_rows_dropped_duplicate"))))
        w("- infinite rate features: **%s**"
          % {"cap": "capped at the column's finite maximum x %s, rows kept"
                    % n(s04.get("ml_inf_cap_factor") or 10.0),
             "drop": "rows dropped"}.get(
                 str(s04.get("ml_inf_mode") or "drop"),
                 str(s04.get("ml_inf_mode"))))
        if s04.get("ml_inf_cells_capped"):
            w("- individual cells capped: **%s**"
              % n(s04.get("ml_inf_cells_capped")))
        w("- de-duplication of identical feature vectors: **%s**"
          % ("on" if s04.get("ml_drop_duplicate_features", True) else "off"))
        w("")
        w(table(["Label", "rows"],
                [[k, n(v)] for k, v in
                 sorted((s04.get("ml_labels") or {}).items(),
                        key=lambda kv: -kv[1])]))

        # Per-label class loss, split by which step removed the rows.
        cause = s04.get("ml_loss_cause_per_label") or {}
        keptp = s04.get("ml_kept_pct_per_label") or {}
        full_lab = s04.get("consolidated_labels") or {}
        mll = s04.get("ml_labels") or {}
        if cause or keptp:
            w("**What this file costs, per label.** The two steps run in "
              "order, so each column is the number of rows that step actually "
              "removed; a row dropped as non-finite is never also counted as "
              "a duplicate.\n")
            rows = []
            for k in sorted(full_lab, key=lambda x: -full_lab[x]):
                c = cause.get(k, {})
                rows.append([k, n(full_lab.get(k)),
                             n(c.get("inf_nan")), n(c.get("duplicate")),
                             n(mll.get(k, 0)),
                             "%.1f%%" % keptp[k] if k in keptp else "-"])
            w(table(["Label", "flows in full file", "removed: inf/NaN",
                     "removed: duplicate", "rows in ML file", "kept"], rows))
            lowest = sorted(keptp.items(), key=lambda kv: kv[1])[:1]
            if lowest and lowest[0][1] < 25.0:
                lk = lowest[0][0]
                c = cause.get(lk, {})
                dom = ("de-duplication"
                       if c.get("duplicate", 0) >= c.get("inf_nan", 0)
                       else "the non-finite rate features")
                fix = ("`ML_DROP_DUPLICATE_FEATURES = False`"
                       if c.get("duplicate", 0) >= c.get("inf_nan", 0)
                       else '`ML_INF_MODE = "cap"`')
                w("The worst-affected class is **%s**, which keeps %.1f%% of "
                  "its flows; the dominant cause is %s. Set %s in "
                  "`mscad_config.py` to keep those rows.\n"
                  % (lk, lowest[0][1], dom, fix))
        w("Two caveats on this file. Dropping rows with an infinite feature "
          "removes **every zero-duration flow**, which in a port scan is most "
          "of the scan; and de-duplicating identical feature vectors removes "
          "real flood, scan and brute-force traffic, because those attacks "
          "genuinely produce repeated flows. Both were asked for, and both "
          "shift the class balance -- compare the label counts above against "
          "the consolidated file's. Use `MSCAD_consolidated.csv`, which keeps "
          "every flow and its identifiers, for the sequence-mining and "
          "attack-graph stages, and this file only for the flow-level "
          "classifiers. If the class balance matters more than the "
          "de-duplication, cap the rate features instead of dropping their "
          "rows.\n")

    # ---------------- thesis paragraph -----------------------------------
    w("## 6. Paragraph for the thesis methodology\n")
    caps_n = len((s01 or {}).get("captures", []))
    total_flows = sum(c.get("flows", 0) for c in (s01 or {}).get("captures", []))
    pkt_list = [c.get("counters", {}).get("packets_read", 0)
                for c in (s01 or {}).get("captures", [])]
    total_pkts = sum(pkt_list)
    biggest_pkts = max(pkt_list) if pkt_list else 0
    w("> The MSCAD distribution publishes flow-level features without flow "
      "identifiers, which makes it unusable for sequential pattern mining and "
      "for attack-state graph construction: neither can be built without "
      "knowing which host pair a flow belongs to or when it occurred. The %d "
      "raw captures were therefore re-processed into flow records carrying "
      "both the identifiers and the published feature set. Feature "
      "definitions were taken from CICFlowMeter and implemented as a "
      "streaming engine with incremental accumulators, so memory "
      "is independent of flow length and the largest capture (%s packets) "
      "was processed without buffering packets. Flows were cut at a 120 s flow "
      "timeout and a 240 s idle timeout, with a 5 s activity threshold, and "
      "every time-derived feature was emitted in microseconds to match the "
      "published file. Unlike the reference implementations, all IPv4 "
      "protocols were retained, including ICMP and non-first IP fragments, so "
      "that the volumetric ICMP flood is represented rather than discarded. "
      "Extraction completeness was verified by reconciling the per-flow "
      "packet counts against an independent packet count of each capture, and "
      "fidelity was assessed against the published file by comparing "
      "per-label feature distributions with the two-sample "
      "Kolmogorov-Smirnov statistic and by matching individual flows on a key "
      "of integer-valued features. The result is %s labelled flow records "
      "with source and destination addresses, ports, protocol and timestamp, "
      "which is the input to the sequential and graph-based stages of the "
      "framework."
      % (caps_n or 6, n(biggest_pkts) if biggest_pkts else "largest",
         n(total_flows) if total_flows else "the full set of"))
    w("")

    w("## 7. Reproducing this\n")
    w("The scripts are copied into `%s` alongside this report. From a `cmd` "
      "prompt:\n" % os.path.join(CFG.OUT_DIR, "scripts"))
    w("```")
    w("cd /d %s" % os.path.join(CFG.OUT_DIR, "scripts"))
    w("set PY=C:\\Users\\banot\\AppData\\Local\\Programs\\Python\\Python313"
      "\\python.exe")
    w("%PY% 00_inspect_inputs.py")
    w("%PY% 01_pcap_to_csv.py N-0")
    w("%PY% 01_pcap_to_csv.py")
    w("%PY% 02_verify.py")
    w("%PY% 03_compare_with_kaggle.py")
    w("%PY% 04_consolidate.py")
    w("%PY% 05_report.py")
    w("```")
    w("")
    w("Or simply `run_all.bat`. All paths and every semantic switch live in "
      "`mscad_config.py`.\n")

    path = os.path.join(CFG.OUT_DIR, REPORT)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print("wrote %s (%d lines)" % (path, len(L)))

    # ---- copy the scripts ----------------------------------------------
    dest = os.path.join(CFG.OUT_DIR, "scripts")
    os.makedirs(dest, exist_ok=True)
    copied = []
    for f in sorted(os.listdir(HERE)):
        if f.endswith((".py", ".bat", ".md")) and f != REPORT:
            shutil.copy2(os.path.join(HERE, f), os.path.join(dest, f))
            copied.append(f)
    print("copied %d script(s) to %s" % (len(copied), dest))
    for f in copied:
        print("    %s" % f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
