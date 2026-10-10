"""
Central configuration for the MSCAD PCAP -> flow-CSV regeneration pipeline.

Everything that is machine-specific or that encodes a semantic choice lives
here, so the whole pipeline is reproducible from one file.

Edit the PATHS block if your folders differ.
"""

import os
import sys

# --------------------------------------------------------------------------
# PATHS  (Windows)
# --------------------------------------------------------------------------
# Primary PCAP folder, then fallbacks that are searched in order if the
# primary one does not exist.  resolve_pcap_dir() reports which one it used.
PCAP_DIR_CANDIDATES = [
    r"D:\IDSPROJECT2026\MSCAD\MSCAD Dataset\PCAPs\pcapngtopcap",
    r"D:\IDSPROJECT2026\MSCAD\MSCAD Dataset\MSCAD Dataset\PCAPs\PCAPs\pcapngtopcap",
]
# Root under which to search recursively for a folder named "pcapngtopcap"
# if none of the candidates above exist.
PCAP_SEARCH_ROOT = r"D:\IDSPROJECT2026\MSCAD"

CSV_ORIGINAL_DIR = r"D:\IDSPROJECT2026\MSCAD\CSV_ORIGINAL"
OUT_DIR = r"D:\IDSPROJECT2026\MSCAD\MSCAD_REGENERATED"

# Optional: used by 02_verify.py for the independent IPv4 packet count.
# If this file is missing, the verifier falls back to its own second-opinion
# parser and says so (it never silently skips the check).
TSHARK_EXE = r"C:\Program Files\Wireshark\tshark.exe"

# Derived sub-folders inside OUT_DIR (created automatically).
RAW_SUBDIR = "raw"          # one raw per-capture CSV per capture
METRICS_SUBDIR = "metrics"  # JSON metrics consumed by 05_report.py

# --------------------------------------------------------------------------
# CAPTURES
# --------------------------------------------------------------------------
# key -> (filename stem, official label, description)
# The official label spelling is the dataset's own, typos included
# ("Web_Crwling" is spelled that way in MSCAD).
CAPTURES = [
    ("N-0",    "Normal",        "normal traffic"),
    ("Scan-1", "Port_Scan",     "Full / SYN / FIN / UDP port scans"),
    ("App-01", "DoS slowloris", "application-layer DDoS (HTTP Slowloris)"),
    ("App-02", "ICMP_Flood",    "volume-based DDoS (ICMP flood, IP-fragmented pings)"),
    ("W-B-01", "Web_Crwling",   "web crawling"),
    ("W-B-02", "Brute_Force",   "password cracking"),
]

# Label given to flows in an attack capture that involve no attacker IP.
BENIGN_LABEL = "Benign"

# Candidate file extensions, tried in this order for each capture stem.
PCAP_EXTENSIONS = [".pcap", ".pcapng", ".cap"]

# --------------------------------------------------------------------------
# FLOW TIMEOUTS  (seconds)
# --------------------------------------------------------------------------
FLOW_TIMEOUT = 120.0      # a flow older than this is cut and a new one starts
IDLE_TIMEOUT = 240.0      # a gap this long between packets also cuts the flow
ACTIVITY_TIMEOUT = 5.0    # Active/Idle segmentation threshold
CLUMP_TIMEOUT = 1.0       # subflow + bulk clump threshold
BULK_BOUND = 4            # packets needed before a burst counts as a "bulk"

# Close a TCP flow when a FIN is seen (Java CICFlowMeter behaviour).
CLOSE_FLOW_ON_FIN = True
# Java CICFlowMeter does NOT close on RST; left off for fidelity.
CLOSE_FLOW_ON_RST = False

# How often (in packets) to sweep open flows for expiry.  Patch 7: we never
# rescan all flows per FIN packet, only on this periodic sweep, so cost is
# O(packets) not O(packets * flows).
SWEEP_EVERY_PACKETS = 50_000
PROGRESS_EVERY_PACKETS = 100_000

# --------------------------------------------------------------------------
# SEMANTIC SWITCHES
# --------------------------------------------------------------------------
# Which byte count the "packet length" family of features is built on.
#   "payload" -> L4 payload bytes       (Java CICFlowMeter: getPayloadBytes())
#   "frame"   -> full captured frame    (pip cicflowmeter 0.5.0: len(packet))
# MSCAD.csv was produced by the Java tool, and its Fwd/Bwd Pkt Len Min
# columns contain zeros, which only happens under payload semantics.
# "payload" is therefore the default; switch to "frame" to reproduce the
# pip package's own numbers instead.
PKT_LEN_MODE = "payload"

# Which header length the Fwd/Bwd Header Len features are built on.
#   "l4" -> transport header only (Java: TCP dataofs*4, UDP 8)
#   "ip" -> IP header only        (pip cicflowmeter 0.5.0: ihl*4)
HEADER_LEN_MODE = "l4"

# Std/Var denominator.  Java uses Apache commons-math SummaryStatistics,
# which is bias-corrected (n-1).  numpy's default is population (n).
#   1 -> sample (n-1), Java-compatible
#   0 -> population (n), numpy/pip-compatible
STD_DDOF = 1

# Reproduce Java's integer (truncating) division for Down/Up Ratio, the
# Subflow */b features and the bulk averages.  Java divides long by long.
JAVA_INTEGER_DIVISION = True

# How the Subflow * features are produced.
#   "divide" -> Java CICFlowMeter: direction total / (1 + number of >1 s gaps)
#   "copy"   -> pip cicflowmeter 0.5.0: Subflow * == the direction total
# This is the one feature family whose Java semantics we are least sure of.
# 03_compare.py reports per-feature KS statistics, so if the four Subflow
# columns show up as the most-different features, switch to "copy" and re-run.
SUBFLOW_MODE = "divide"

# Value for Init Fwd/Bwd Win Byts when that direction has no TCP packet.
# The CIC CSV family uses -1.
INIT_WIN_DEFAULT = -1

# Keep flows that only ever saw one packet.  Java drops them when they expire
# on timeout.  We keep them because Part 2 requires every IPv4 packet to be
# accounted for; 02_verify.py reports how many there are so you can see the
# size of this difference against Kaggle.
DROP_SINGLE_PACKET_FLOWS = False

# Add the final (unterminated) Active segment when a flow is written out.
# Java does not, which is why many short flows have Active Mean = 0.
ADD_FINAL_ACTIVE_SEGMENT = False

# --------------------------------------------------------------------------
# PART 4: how MSCAD_consolidated_ML.csv treats the infinite rate features
# --------------------------------------------------------------------------
# Zero-duration flows (a single packet, or several in the same microsecond)
# carry Infinity in Flow Byts/s, Flow Pkts/s, Fwd Pkts/s and Bwd Pkts/s.
#
#   "drop" -> drop those rows entirely (what Part 4 of the task asks for)
#   "cap"  -> keep the rows, replacing +/-inf in each rate column with that
#             column's finite maximum (x ML_INF_CAP_FACTOR)
#
# "drop" is the default because it is what was specified, but be aware of
# what it costs: a port scan is almost entirely single-packet, zero-duration
# flows, so dropping them removes almost the entire Port_Scan class.  On the
# synthetic self-test, Port_Scan kept 2 rows out of 250 (0.8%).  If the
# classifier stages need the class balance more than they need the dropping,
# set this to "cap".  Stage 04 prints the per-label kept-% either way, so the
# cost is always visible rather than silent.
ML_INF_MODE = "drop"
ML_INF_CAP_FACTOR = 10.0

# De-duplicate identical feature vectors in the ML file.  Floods, scans and
# brute-force traffic genuinely produce repeated flows, so this also removes
# real data; it was asked for, and stage 04 reports how many rows it took.
ML_DROP_DUPLICATE_FEATURES = True

# Attacker detection: a Src IP counts as an attacker when its total forward
# packets reach this fraction of the top sender's.
ATTACKER_SHARE = 0.50
ATTACKER_TOP_N_PRINT = 5

# Time features are emitted in MICROSECONDS to match MSCAD.
TIME_UNIT_SCALE = 1_000_000.0

# Timestamp column format.  MSCAD itself has no Timestamp column, so this one
# is ours; it is written in UTC with microsecond precision because the
# sequence-mining / attack-graph stages need a sortable, unambiguous ordering.
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
TIMESTAMP_UTC = True

# --------------------------------------------------------------------------
# PART 3 ROW-MATCHING KEY
# --------------------------------------------------------------------------
MATCH_KEY_FEATURES = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Bwd Pkt Len Max",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd Header Len",
    "Bwd Header Len",
    "Init Bwd Win Byts",
]

IDENTIFIER_COLUMNS = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp"]
LABEL_COLUMN = "Label"


# --------------------------------------------------------------------------
# HELPERS
# --------------------------------------------------------------------------
def resolve_pcap_dir(verbose=True):
    """Return (path, how) for the PCAP folder, searching the fallbacks."""
    for cand in PCAP_DIR_CANDIDATES:
        if os.path.isdir(cand):
            return cand, "configured candidate"
    # Recursive search for a folder literally named pcapngtopcap.
    if os.path.isdir(PCAP_SEARCH_ROOT):
        hits = []
        for root, dirs, _files in os.walk(PCAP_SEARCH_ROOT):
            for d in dirs:
                if d.lower() == "pcapngtopcap":
                    hits.append(os.path.join(root, d))
        if hits:
            hits.sort(key=len)
            if verbose and len(hits) > 1:
                print("  NOTE: several pcapngtopcap folders found:")
                for h in hits:
                    print("        " + h)
            return hits[0], "recursive search under %s" % PCAP_SEARCH_ROOT
    return None, "not found"


def ensure_out_dirs():
    for d in (OUT_DIR,
              os.path.join(OUT_DIR, RAW_SUBDIR),
              os.path.join(OUT_DIR, METRICS_SUBDIR)):
        os.makedirs(d, exist_ok=True)
    return OUT_DIR


def raw_csv_path(capture_key):
    return os.path.join(OUT_DIR, RAW_SUBDIR, "%s_flows.csv" % capture_key)


def metrics_path(name):
    return os.path.join(OUT_DIR, METRICS_SUBDIR, name)


def find_capture_file(pcap_dir, stem):
    """Find the capture file for a stem, case-insensitively."""
    if not pcap_dir or not os.path.isdir(pcap_dir):
        return None
    entries = os.listdir(pcap_dir)
    lower = {e.lower(): e for e in entries}
    for ext in PCAP_EXTENSIONS:
        want = (stem + ext).lower()
        if want in lower:
            return os.path.join(pcap_dir, lower[want])
    # Looser match: any file whose stem matches ignoring case/extension.
    for e in entries:
        base, ext = os.path.splitext(e)
        if base.lower() == stem.lower() and ext.lower() in PCAP_EXTENSIONS:
            return os.path.join(pcap_dir, e)
    return None


def apply_overrides(argv=None):
    """Allow `--out-dir X`, `--pcap-dir X`, `--csv-dir X`, `--pkt-len-mode X`
    on the command line of any stage script."""
    argv = list(sys.argv[1:] if argv is None else argv)
    g = globals()
    mapping = {
        "--out-dir": "OUT_DIR",
        "--csv-dir": "CSV_ORIGINAL_DIR",
        "--pkt-len-mode": "PKT_LEN_MODE",
        "--header-len-mode": "HEADER_LEN_MODE",
        "--tshark": "TSHARK_EXE",
    }
    i = 0
    rest = []
    while i < len(argv):
        a = argv[i]
        if a == "--pcap-dir" and i + 1 < len(argv):
            g["PCAP_DIR_CANDIDATES"] = [argv[i + 1]]
            i += 2
        elif a in mapping and i + 1 < len(argv):
            g[mapping[a]] = argv[i + 1]
            i += 2
        else:
            rest.append(a)
            i += 1
    return rest
