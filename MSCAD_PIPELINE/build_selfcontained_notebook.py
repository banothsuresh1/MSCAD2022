# -*- coding: utf-8 -*-
"""Rebuild MSCAD_pipeline_selfcontained.ipynb from the .py sources.

The notebook and the scripts must never diverge, so the notebook is generated
from the same files rather than maintained by hand. Run this after changing
any of the modules or stage scripts:

    python build_selfcontained_notebook.py

Needs `nbformat` (ships with Anaconda).
"""
import io, os, re, sys
import nbformat as nbf

SRC = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SRC, "MSCAD_pipeline_selfcontained.ipynb")


def read(name):
    with io.open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()


def strip_docstring(s):
    """Remove the leading module docstring."""
    m = re.match(r'\s*"""', s)
    if not m:
        return s
    end = s.index('"""', m.end())
    return s[end + 3:].lstrip("\n")


def drop_lines(s, patterns):
    keep = []
    for line in s.split("\n"):
        if any(re.search(p, line) for p in patterns):
            continue
        keep.append(line)
    return "\n".join(keep)


DROP = [
    r"^import mscad_config as CFG",
    r"^import mscad_names as N",
    r"^import mscad_schema as SCH",
    r"^from mscad_flowmeter import",
    r"^sys\.path\.insert\(0, os\.path\.dirname",
    r"^ARGS = CFG\.apply_overrides\(\)",
    r"^CFG\.apply_overrides\(\)",
    r"^if __name__ == \"__main__\":",
    r"^    sys\.exit\(main\(\)\)",
]


def prep(name, rename_main=None):
    s = strip_docstring(read(name))
    s = drop_lines(s, DROP)
    s = re.sub(r"\bN\.", "", s)
    s = re.sub(r"\bSCH\.", "", s)
    if rename_main:
        s = s.replace("def main():", "def %s:" % rename_main, 1)
    # the CLI took capture names from argv; in the notebook they are a parameter
    s = s.replace('wanted = [a for a in ARGS if not a.startswith("-")]',
                  'wanted = list(captures or [])')
    assert "ARGS" not in s, "ARGS still referenced in %s" % name
    # tidy runs of blank lines
    s = re.sub(r"\n{4,}", "\n\n\n", s).strip("\n")
    return s + "\n"


cells = []
md = lambda t: cells.append(nbf.v4.new_markdown_cell(t.strip()))
co = lambda t: cells.append(nbf.v4.new_code_cell(t.rstrip()))

# ------------------------------------------------------------------ intro
md(u"""
# MSCAD regeneration pipeline — self-contained notebook

Regenerates flow records **with flow identifiers** (Src/Dst IP, ports, protocol,
timestamp) from the raw MSCAD PCAPs, verifies the extraction, compares it against the
original Kaggle `MSCAD.csv`, and writes the consolidated CSVs plus a report.

The Kaggle file carries the CICFlowMeter features and a `Label` but no identifiers, so
PrefixSpan sequence mining and the attack-state graph cannot be built from it. This
supplies them.

**Everything is in this notebook.** No other file is needed — no `.py` imports, no
`pip install` beyond what Anaconda already has (`numpy`, `scipy`, `pandas`).

### How to use it

1. Run section 1 (environment check).
2. Edit section 2 (paths) — the only cell you should need to change.
3. Run sections 3–5 once; they only define code.
4. Run section 6 cell by cell: inspect inputs, N-0 test, all six, verify, compare,
   consolidate, report.
5. Section 7 loads the result and builds the per-host-pair label sequences.

Memory is safe in-kernel: the engine keeps no packets, only per-flow accumulators, and
a 704,000-packet capture was measured at a flat 53 MB. If you still want a clean slate
between stages, use *Kernel → Restart* and re-run sections 2–5.
""")

# ------------------------------------------------------------------ 1 env
md(u"## 1. Environment check")
co(u'''import os, sys, platform, importlib

print("Python    :", sys.version.split()[0])
print("executable:", sys.executable)
print("platform  :", platform.platform())
if sys.version_info < (3, 8):
    print("\\n*** Python 3.8+ required ***")

missing = []
for pkg in ("numpy", "scipy", "pandas"):
    try:
        m = importlib.import_module(pkg)
        print("%-8s  : %s" % (pkg, getattr(m, "__version__", "?")))
    except ImportError:
        missing.append(pkg)
        print("%-8s  : MISSING" % pkg)
try:
    import scapy
    print("%-8s  : %s (optional)" % ("scapy", scapy.__version__))
except ImportError:
    print("%-8s  : not installed (optional, only for .pcapng input)" % "scapy")

if missing:
    print("\\nInstall into THIS kernel with:")
    print("    %s -m pip install %s" % (sys.executable, " ".join(missing)))
else:
    print("\\nAll required packages present.")''')

# ------------------------------------------------------------------ 2 config
md(u"""
## 2. Configuration — edit this cell

Paths first. Everything below them is a documented semantic switch; the defaults match
the **Java** CICFlowMeter, which is the tool that produced the Kaggle `MSCAD.csv` we
compare against. Section 6.8 of this notebook tells you which switch to change if a
feature family looks wrong.
""")
co(u'''import os


class CFG:
    # ---------------- PATHS: edit these ------------------------------
    PCAP_DIR_CANDIDATES = [
        r"D:\\IDSPROJECT2026\\MSCAD\\MSCAD Dataset\\PCAPs\\pcapngtopcap",
        r"D:\\IDSPROJECT2026\\MSCAD\\MSCAD Dataset\\MSCAD Dataset\\PCAPs\\PCAPs\\pcapngtopcap",
    ]
    PCAP_SEARCH_ROOT = r"D:\\IDSPROJECT2026\\MSCAD"
    CSV_ORIGINAL_DIR = r"D:\\IDSPROJECT2026\\MSCAD\\CSV_ORIGINAL"
    OUT_DIR = r"D:\\IDSPROJECT2026\\MSCAD\\MSCAD_REGENERATED"
    TSHARK_EXE = r"C:\\Program Files\\Wireshark\\tshark.exe"   # optional

    RAW_SUBDIR = "raw"
    METRICS_SUBDIR = "metrics"

    # ---------------- captures --------------------------------------
    # key, official label (dataset's own spelling), description
    CAPTURES = [
        ("N-0",    "Normal",        "normal traffic"),
        ("Scan-1", "Port_Scan",     "Full / SYN / FIN / UDP port scans"),
        ("App-01", "DoS slowloris", "application-layer DDoS (HTTP Slowloris)"),
        ("App-02", "ICMP_Flood",    "volume-based DDoS (ICMP flood, fragmented pings)"),
        ("W-B-01", "Web_Crwling",   "web crawling"),
        ("W-B-02", "Brute_Force",   "password cracking"),
    ]
    BENIGN_LABEL = "Benign"
    PCAP_EXTENSIONS = [".pcap", ".pcapng", ".cap"]

    # ---------------- timeouts (seconds) ----------------------------
    FLOW_TIMEOUT = 120.0      # a flow older than this is cut, a new one starts
    IDLE_TIMEOUT = 240.0      # a gap this long also cuts the flow
    ACTIVITY_TIMEOUT = 5.0    # Active/Idle segmentation threshold
    CLUMP_TIMEOUT = 1.0       # subflow + bulk clump threshold
    BULK_BOUND = 4            # packets before a burst counts as a "bulk"
    CLOSE_FLOW_ON_FIN = True  # Java CICFlowMeter behaviour
    CLOSE_FLOW_ON_RST = False # Java does not close on RST

    SWEEP_EVERY_PACKETS = 50000
    PROGRESS_EVERY_PACKETS = 100000

    # ---------------- semantic switches -----------------------------
    # "payload" = L4 payload bytes (Java getPayloadBytes); "frame" = whole
    # captured frame (pip cicflowmeter len(packet)). The CIC CSV family has
    # ZEROS in Fwd/Bwd Pkt Len Min, which only happens under payload bytes.
    PKT_LEN_MODE = "payload"
    # "l4" = transport header only (Java); "ip" = IP header (pip ihl*4)
    HEADER_LEN_MODE = "l4"
    # 1 = bias-corrected n-1 (Java commons-math); 0 = population n (numpy)
    STD_DDOF = 1
    # "divide" = total / (1 + >1s gaps), as Java; "copy" = Subflow == total, as pip
    SUBFLOW_MODE = "divide"
    # Java truncates long/long for Down/Up Ratio, Subflow and bulk averages
    JAVA_INTEGER_DIVISION = True
    # Init Fwd/Bwd Win Byts when that direction has no TCP packet (CIC uses -1)
    INIT_WIN_DEFAULT = -1
    # Java drops 1-packet flows on timeout; we keep them so every packet is
    # accounted for in the Part 2 reconciliation
    DROP_SINGLE_PACKET_FLOWS = False
    # Java does not add the final unterminated Active segment
    ADD_FINAL_ACTIVE_SEGMENT = False

    # ---------------- labelling -------------------------------------
    ATTACKER_SHARE = 0.50     # Src IP is an attacker at >= this share of top sender
    ATTACKER_TOP_N_PRINT = 5

    # ---------------- output ----------------------------------------
    TIME_UNIT_SCALE = 1000000.0          # time features are in MICROSECONDS
    TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
    TIMESTAMP_UTC = True

    MATCH_KEY_FEATURES = [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts",
        "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Bwd Pkt Len Max",
        "Flow IAT Max", "Flow IAT Min", "Fwd Header Len", "Bwd Header Len",
        "Init Bwd Win Byts",
    ]
    IDENTIFIER_COLUMNS = ["Src IP", "Dst IP", "Src Port", "Dst Port",
                          "Protocol", "Timestamp"]
    LABEL_COLUMN = "Label"

    # ---------------- helpers ---------------------------------------
    @staticmethod
    def resolve_pcap_dir(verbose=True):
        """Return (path, how). Falls back to searching for 'pcapngtopcap'."""
        for cand in CFG.PCAP_DIR_CANDIDATES:
            if os.path.isdir(cand):
                return cand, "configured candidate"
        if os.path.isdir(CFG.PCAP_SEARCH_ROOT):
            hits = []
            for root, dirs, _files in os.walk(CFG.PCAP_SEARCH_ROOT):
                for d in dirs:
                    if d.lower() == "pcapngtopcap":
                        hits.append(os.path.join(root, d))
            if hits:
                hits.sort(key=len)
                if verbose and len(hits) > 1:
                    print("  NOTE: several pcapngtopcap folders found:")
                    for h in hits:
                        print("        " + h)
                return hits[0], "recursive search under %s" % CFG.PCAP_SEARCH_ROOT
        return None, "not found"

    @staticmethod
    def ensure_out_dirs():
        for d in (CFG.OUT_DIR,
                  os.path.join(CFG.OUT_DIR, CFG.RAW_SUBDIR),
                  os.path.join(CFG.OUT_DIR, CFG.METRICS_SUBDIR)):
            if not os.path.isdir(d):
                os.makedirs(d)
        return CFG.OUT_DIR

    @staticmethod
    def raw_csv_path(capture_key):
        return os.path.join(CFG.OUT_DIR, CFG.RAW_SUBDIR,
                            "%s_flows.csv" % capture_key)

    @staticmethod
    def metrics_path(name):
        return os.path.join(CFG.OUT_DIR, CFG.METRICS_SUBDIR, name)

    @staticmethod
    def find_capture_file(pcap_dir, stem):
        """Find a capture file for a stem, case-insensitively."""
        if not pcap_dir or not os.path.isdir(pcap_dir):
            return None
        entries = os.listdir(pcap_dir)
        lower = dict((e.lower(), e) for e in entries)
        for ext in CFG.PCAP_EXTENSIONS:
            want = (stem + ext).lower()
            if want in lower:
                return os.path.join(pcap_dir, lower[want])
        for e in entries:
            base, ext = os.path.splitext(e)
            if base.lower() == stem.lower() and ext.lower() in CFG.PCAP_EXTENSIONS:
                return os.path.join(pcap_dir, e)
        return None


print("config loaded")
print("  out dir :", CFG.OUT_DIR)
for lbl, p in (("pcap dir", CFG.PCAP_DIR_CANDIDATES[0]),
               ("csv dir ", CFG.CSV_ORIGINAL_DIR)):
    print("  %s: %s   %s" % (lbl, p, "EXISTS" if os.path.isdir(p) else "*** MISSING ***"))
print("  tshark  : %s   %s" % (CFG.TSHARK_EXE,
                               "found" if os.path.isfile(CFG.TSHARK_EXE) else "not found (optional)"))
print("\\ntimeouts: flow %.0fs | idle %.0fs | activity %.0fs | clump %.0fs"
      % (CFG.FLOW_TIMEOUT, CFG.IDLE_TIMEOUT, CFG.ACTIVITY_TIMEOUT, CFG.CLUMP_TIMEOUT))
print("modes   : pkt-len %r | header-len %r | std ddof %d | subflow %r"
      % (CFG.PKT_LEN_MODE, CFG.HEADER_LEN_MODE, CFG.STD_DDOF, CFG.SUBFLOW_MODE))
print("time features in MICROSECONDS")''')

# ------------------------------------------------------------------ 3 names
md(u"""
## 3. Feature name tables

The 76 CICFlowMeter features with every alias (CICFlowMeter V3 / CIC-IDS2017 and
V4 / CSE-CIC-IDS2018 naming). The pipeline never hard-codes "the 66 MSCAD columns":
it reads the real header from your Kaggle file and resolves each name through
`NAME_TO_KEY`, so whichever 66 of the 76 MSCAD carries, in whatever order, the output
matches. Any header name that cannot be resolved is reported, never guessed.
""")
co(prep("mscad_names.py"))

# ------------------------------------------------------------------ 4 engine
md(u"""
## 4. The patched flow engine

Feature definitions come from the Python `cicflowmeter` 0.5.0 package, reimplemented
here as a streaming engine keeping that package's own field names, with numeric
definitions following the Java CICFlowMeter.

A reimplementation rather than a monkey-patch was necessary: the package's feature
classes take live scapy `Packet` objects and keep every packet of a flow in
`Flow.packets`, so including non-TCP/UDP traffic, dropping the retained packets and
reading real TCP flags all change its *data model*, not just its behaviour.

**Patches 1–8** (as specified) plus **two more bugs found by reading the 0.5.0 source**:
its `update_subflow` compares `packet.time` against an already-advanced
`latest_timestamp`, so every Active/Idle feature came out identically 0; and
`get_statistics` returns zeros unless `len > 1`, so a two-packet flow reported
Flow IAT Mean/Max/Min = 0. Both are fixed. Full notes are in the cell's docstrings.
""")
co(prep("mscad_flowmeter.py"))

# ------------------------------------------------------------------ 5 schema
md(u"""
## 5. Locating the Kaggle file and deriving the output schema
""")
co(prep("mscad_schema.py"))

# ------------------------------------------------------------------ 6 stages
md(u"""
## 6. The pipeline

Each stage is defined then run. Definition cells print nothing; the run cells do the
work and print the tables.
""")

md(u"### 6.1 Stage 00 — inspect the inputs  *(definition)*")
co(prep("00_inspect_inputs.py", rename_main="stage_00()"))
md(u"""
### 6.2 Stage 00 — run

Checks both input folders and lists them, searching for `pcapngtopcap` if the
configured paths are missing and reporting which one it used. Then prints the original
Kaggle file's shape, every column name, and its Label counts.

Reads only — it never modifies, moves or deletes anything in the input folders.
""")
co(u"stage_00()")

md(u"### 6.3 Stage 01 — PCAP to CSV  *(definition)*")
co(prep("01_pcap_to_csv.py", rename_main="stage_01(captures=None)"))
md(u"""
### 6.4 Stage 01a — N-0 only, the quick test

**Check this before the full run:**

- `packets read` minus `IPv4 packets in flows` must equal the non-IPv4 count and nothing else
- the feature column count matches your Kaggle file (66)
- no column reported as unmappable
- `Flow Duration` looks like microseconds — tens of thousands for a short session
""")
co(u'stage_01(["N-0"])')
md(u"Peek at the N-0 rows:")
co(u'''import pandas as pd
pd.set_option("display.width", 220)
pd.set_option("display.max_columns", 40)

_p = CFG.raw_csv_path("N-0")
if os.path.isfile(_p):
    _df = pd.read_csv(_p)
    print("shape:", _df.shape)
    _cols = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp",
             "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts",
             "Fwd Pkt Len Min", "Fwd Pkt Len Max", "Flow IAT Mean",
             "Fwd Header Len", "Init Bwd Win Byts", "Label"]
    print(_df[[c for c in _cols if c in _df.columns]].head(10).to_string())
    print("\\npackets accounted for in flows:",
          int(_df["Tot Fwd Pkts"].sum() + _df["Tot Bwd Pkts"].sum()))
    print("protocols (6=TCP, 17=UDP, 1=ICMP):", dict(_df["Protocol"].value_counts()))
else:
    print("not found yet:", _p)''')

md(u"""
### 6.5 Stage 01b — all six captures

Progress prints every 100,000 packets. Each attack capture is read twice — once to find
the attacker IPs, once to write labelled flows — so nothing is held in memory. The top
5 senders per capture are printed so you can check the attacker detection yourself.

Expect a couple of minutes, not 10–20: a 704,000-packet capture measured 19.5 s.
""")
co(u"stage_01()")

md(u"### 6.6 Stage 02 — verify the extraction  *(definition)*")
co(prep("02_verify.py", rename_main="stage_02(captures=None)"))
md(u"""
### 6.7 Stage 02 — run

The first table is the one that matters: `IPv4 in flows` must equal the independent
counts **exactly**. If it does, no packet was lost or double-counted.

In the sanity table everything should be 0 except `inf` (zero-duration flows' rate
features — normal CICFlowMeter behaviour), `1-pkt flws` and `dup feat rows`, which are
expected in scans and floods and are counted rather than dropped.
""")
co(u"stage_02()")

md(u"### 6.8 Stage 03 — compare with the Kaggle file  *(definition)*")
co(prep("03_compare_with_kaggle.py", rename_main="stage_03()"))
md(u"""
### 6.9 Stage 03 — run

Schema, rows per label, the microseconds units check, per-feature Kolmogorov–Smirnov
statistics per label, and row-level matching on the integer-feature key.

**How to read section 3.4:** if the four `Subflow` columns top the KS table, set
`CFG.SUBFLOW_MODE = "copy"` in section 2 and re-run stage 01. If the `Std`/`Var`
columns or `Down/Up Ratio` lead it, check `CFG.STD_DDOF` and
`CFG.JAVA_INTEGER_DIVISION`. If the `TotLen` / `Pkt Len` family leads it, try
`CFG.PKT_LEN_MODE = "frame"`.

**How to read section 3.5:** a low match rate is expected and is *not* evidence the
extraction is wrong — stage 02's packet reconciliation is the completeness check.
Section 4.6 of the generated report explains each cause.
""")
co(u"stage_03()")

md(u"### 6.10 Stage 04 — consolidated CSVs  *(definition)*")
co(prep("04_consolidate.py", rename_main="stage_04()"))
md(u"""
### 6.11 Stage 04 — run

- `MSCAD_consolidated.csv` — identifiers + features + `Label` + `Label_Kaggle` +
  `Source_Capture`, sorted by `Timestamp`. **This is the file for PrefixSpan and the
  attack-state graph.**
- `MSCAD_consolidated_ML.csv` — features + `Label` only, infinities dropped and
  identical feature vectors de-duplicated, for RF / XGBoost / LSTM / CNN.
""")
co(u"stage_04()")

md(u"### 6.12 Stage 05 — the report  *(definition)*")
co(prep("05_report.py", rename_main="stage_05()").replace(
    'HERE = os.path.dirname(os.path.abspath(__file__))',
    'HERE = os.getcwd()   # notebook folder: whatever .py/.ipynb is here gets copied'))
md(u"""
### 6.13 Stage 05 — run

Writes `MSCAD_regeneration_report.md` into the output folder: the method, every table
above, the file descriptions, and a paragraph you can adapt for your thesis
methodology. It also copies whatever scripts/notebooks are in the current folder into
`<out>\\scripts` so the run is reproducible.
""")
co(u"stage_05()")

# ------------------------------------------------------------------ 7 explore
md(u"## 7. Load the result and sanity-check it here")
co(u'''cons = os.path.join(CFG.OUT_DIR, "MSCAD_consolidated.csv")
mlf = os.path.join(CFG.OUT_DIR, "MSCAD_consolidated_ML.csv")
full = None

if os.path.isfile(cons):
    full = pd.read_csv(cons, low_memory=False)
    print("MSCAD_consolidated.csv :", full.shape)
    print("\\nlabels:")
    print(full["Label"].value_counts().to_string())
    print("\\nper capture:")
    print(full["Source_Capture"].value_counts().to_string())
    print("\\nLabel_Kaggle filled on %d rows"
          % int(full["Label_Kaggle"].notna().sum()))
    print("\\ntime span: %s  ->  %s"
          % (full["Timestamp"].min(), full["Timestamp"].max()))
    print("\\nfirst rows:")
    print(full[["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
                "Timestamp", "Label", "Source_Capture"]].head(8).to_string())
else:
    print("not found yet:", cons)

if os.path.isfile(mlf):
    ml = pd.read_csv(mlf, low_memory=False)
    print("\\nMSCAD_consolidated_ML.csv :", ml.shape)
    print(ml["Label"].value_counts().to_string())
    print("\\nNOTE: dropping infinite rows removes every zero-duration flow,")
    print("which in a port scan is most of the scan; and de-duplicating identical")
    print("feature vectors removes real flood/scan/brute-force traffic. Compare the")
    print("two label tables above before training -- the class balance differs.")''')

md(u"""
## 8. The sequence view — what the regeneration was for

Grouping the consolidated flows per host pair, in time order, gives the labelled
sequences PrefixSpan takes as input. None of this is possible from the Kaggle file,
which has no identifiers and no timestamp.
""")
co(u'''if full is not None:
    seq = (full.sort_values("Timestamp")
               .groupby(["Src IP", "Dst IP"])["Label"]
               .apply(list))
    print("host pairs with at least one flow    :", len(seq))
    multi = seq[seq.map(len) > 1]
    print("host pairs with a multi-flow sequence:", len(multi))
    print("\\nlongest 10 sequences (first 12 flows shown):")
    for (s, d), labs in multi.sort_values(key=lambda x: x.map(len),
                                          ascending=False).head(10).items():
        print("  %-16s -> %-16s  n=%-7d %s%s"
              % (s, d, len(labs), " > ".join(labs[:12]),
                 " > ..." if len(labs) > 12 else ""))

    print("\\ndistinct attack-stage transitions observed per host pair:")
    from collections import Counter as _C
    trans = _C()
    for labs in multi:
        for a, b in zip(labs, labs[1:]):
            if a != b:
                trans[(a, b)] += 1
    if trans:
        for (a, b), n in trans.most_common(20):
            print("  %-16s -> %-16s  %d" % (a, b, n))
    else:
        print("  (none: no host pair changed label between consecutive flows)")
else:
    print("run stage 04 first")''')

nb = nbf.v4.new_notebook()
nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {"display_name": "Python 3 (ipykernel)", "language": "python",
                   "name": "python3"},
    "language_info": {"name": "python", "version": "3.9.0",
                      "mimetype": "text/x-python", "file_extension": ".py",
                      "pygments_lexer": "ipython3",
                      "nbconvert_exporter": "python",
                      "codemirror_mode": {"name": "ipython", "version": 3}},
}
with io.open(OUT, "w", encoding="utf-8") as fh:
    nbf.write(nb, fh)
ncode = sum(1 for c in cells if c.cell_type == "code")
print("wrote %s" % OUT)
print("  %d cells (%d code, %d markdown)" % (len(cells), ncode, len(cells) - ncode))
