# MSCAD regeneration pipeline

Regenerates flow-level records **with flow identifiers** (Src/Dst IP, ports,
protocol, timestamp) from the raw MSCAD PCAPs, verifies the extraction,
compares it against the original Kaggle `MSCAD.csv`, and builds the final
consolidated CSVs.

The Kaggle file has the CICFlowMeter features and a `Label` but no
identifiers, so sequential pattern mining (PrefixSpan) and attack-state graph
construction cannot be done from it. This pipeline supplies them.

---

## Important: where this was written vs. where it must run

This code was written and tested in a Linux cloud container that **has no
access to your `D:` drive**. Everything in Parts 1-4 therefore has to run on
your own Windows machine; no number in any report is real until you run it
there.

What *was* verified here, on synthetic captures (`make_test_fixture.py`):

| Check | Result |
|---|---|
| All five stages run end to end | pass |
| Packet conservation (`Tot Fwd + Tot Bwd` = independent IPv4 count) | exact on all 6 synthetic captures |
| Duplicate flows / NaN / negatives / min>max / bad ports | 0 |
| ICMP kept, with Port 0 and Protocol 1 | yes |
| IP-fragmented pings kept (36 non-first fragments) | yes |
| ARP + IPv6 excluded and counted separately | yes |
| 120 s flow timeout and 240 s idle timeout both cut flows | yes |
| Row matching + label confusion table | 7/7 matched rows, 100% label agreement |
| Scale: 704,000-packet brute-force capture | 19.5 s, peak RSS 53 MB, flat throughput |
| Re-verified end to end after the Part 4 switches were added | all 6 stages exit 0, verdict unchanged |

Run `selftest.bat` on your machine to reproduce that table before pointing the
pipeline at the real data.

---

## Quick start A: Anaconda Jupyter (recommended)

Open **`MSCAD_pipeline.ipynb`** in Jupyter and run the cells in order. Cell 2
is the only one you may need to edit (the three folder paths).

```
conda activate base
cd /d D:\IDSPROJECT2026\MSCAD\pipeline\MSCAD_PIPELINE
jupyter notebook MSCAD_pipeline.ipynb
```

The notebook runs each stage as a **subprocess, not inside the kernel**. The
flow data therefore never enters the kernel's memory, so no capture can crash
it however large, and each stage starts from clean state. Output streams into
the cell as it runs. The last two cells load the result and build the
per-host-pair label sequences that PrefixSpan takes as input.

Anaconda already ships `numpy`, `scipy` and `pandas`, which is all the
`.pcap` path needs -- cell 1 checks and tells you the exact `pip install`
line if anything is missing. `scapy` is only needed for `.pcapng` input and
for the synthetic self-test; `tshark` is optional, because the verifier has
its own independent packet counter built in.

---

## Quick start B: cmd

```
cd /d <folder containing these scripts>

REM 0) prove it works on your machine, using synthetic captures only
selftest.bat

REM 1) check the real inputs and convert N-0 as a quick test
run_test_N0.bat

REM 2) the full run
run_all.bat
```

Or stage by stage:

```
set PY=C:\Users\banot\AppData\Local\Programs\Python\Python313\python.exe
%PY% 00_inspect_inputs.py
%PY% 01_pcap_to_csv.py N-0
%PY% 01_pcap_to_csv.py
%PY% 02_verify.py
%PY% 03_compare_with_kaggle.py
%PY% 04_consolidate.py
%PY% 05_report.py
```

Every stage accepts `--pcap-dir`, `--csv-dir`, `--out-dir`, `--pkt-len-mode`,
`--header-len-mode` and `--tshark` to override `mscad_config.py` for one run.

Requirements for `.pcap` input: `numpy`, `scipy`, `pandas` -- all three ship
with Anaconda. `scapy` is needed only for `.pcapng` input and for
`make_test_fixture.py`. `tshark` is optional: stage 02 has its own
independent raw-bytes packet counter that needs no third-party package, and
it reports which counts it managed to take. The `cicflowmeter` package itself
is **not** imported at runtime (see below), so a broken install of it cannot
break this pipeline. No Python 3.10+ syntax is used, so any Anaconda Python
3.8+ works.

---

## Files

| File | What it is |
|---|---|
| `mscad_config.py` | **All** paths, timeouts and semantic switches. The only file you should need to edit. |
| `mscad_names.py` | The 76 CICFlowMeter features and every alias (V3/CIC-IDS2017 and V4/CSE-CIC-IDS2018 naming), for mapping the original header. |
| `mscad_schema.py` | Finds the original Kaggle file and derives the output column layout from its real header. |
| `mscad_flowmeter.py` | The patched flow/feature engine. |
| `00_inspect_inputs.py` | Checks both input folders, lists them, shows the original file's shape, columns and Label counts. |
| `01_pcap_to_csv.py` | Part 1: PCAP to flow CSV, per capture, into `raw\`. |
| `02_verify.py` | Part 2: packet accounting and data sanity. |
| `03_compare_with_kaggle.py` | Part 3: schema, rows/label, units, per-feature KS, row matching. |
| `04_consolidate.py` | Part 4: `MSCAD_consolidated.csv` and `MSCAD_consolidated_ML.csv`. |
| `05_report.py` | Part 5: writes `MSCAD_regeneration_report.md` and copies these scripts into the output folder. |
| `make_test_fixture.py` | Builds the synthetic captures and a stand-in Kaggle file for `selftest.bat`. |
| `MSCAD_pipeline.ipynb` | Jupyter driver: one cell per stage, each run as a subprocess, plus result loading and the sequence view. |

Stages 00-04 each write a JSON file into `metrics\`; stage 05 renders the
report from those, so a number missing from a run shows up as
"not measured" rather than being invented.

---

## Why the engine is a reimplementation

`cicflowmeter` 0.5.0 defines the right features, but its feature classes take
live scapy `Packet` objects and keep every packet of a flow in
`Flow.packets`. Including non-TCP/UDP traffic, dropping the retained packets
and reading real TCP flags all change its *data model*, not just its
behaviour, so they cannot be applied as monkey-patches. `mscad_flowmeter.py`
therefore reimplements the same feature set, keeping the package's own field
names (`tot_fwd_pkts`, `flow_byts_s`, `cwr_flag_count`, ...) so the mapping to
the MSCAD column names stays one-to-one and auditable. The numeric
definitions follow the **Java** CICFlowMeter, because that is the tool that
produced the Kaggle `MSCAD.csv`.

### Patches

1. **CLI crash** -- no CLI is used; the engine is a library.
2. **Non-TCP/UDP dropped** -- all IPv4 packets are kept. ICMP and other IP
   protocols form flows keyed `(src, dst, 0, 0, proto)`: Port 0, Protocol 1
   for ICMP. Non-first IP fragments have no transport header and join the same
   port-0 flow, which is what keeps App-02's fragmented pings.
3. **BPF filter needs tcpdump** -- no capture filter is ever set.
4. **FIN read from IP flags** -- all eight TCP flags are read from the TCP
   flags byte.
5. **First packet counted twice** -- each packet is added exactly once.
6. **Every packet retained in memory** -- nothing per-packet is retained at
   all. Each feature is an incremental accumulator (Welford mean/variance plus
   min/max/sum), so memory is O(open flows) regardless of flow length.
7. **Full rescan after every FIN** -- timeouts are checked on the packet's own
   flow, plus a periodic sweep every 50,000 packets.
8. **Timeouts** -- flow 120 s, idle 240 s, activity 5 s, clump 1 s.

Two more bugs found while reading the 0.5.0 source and fixed here:

9. `Flow.update_subflow` compares `packet.time` with `self.latest_timestamp`
   *after* that field has been set to `packet.time`, so the difference is
   always 0, `update_active_idle` is never reached and **every Active/Idle
   feature is identically 0**. `last_active` also starts at 0, so a first idle
   value would have been ~1.7e9 seconds.
10. `get_statistics` returns zeros unless `len(list) > 1`, so a two-packet
    flow (one IAT) reports **Flow IAT Mean/Max/Min = 0**.

### Units

Packet times are carried as **integer microseconds** end to end (a pcap record
gives seconds + microseconds, so this is exact). Flow Duration, every IAT and
every Active/Idle feature are emitted in **microseconds**, matching MSCAD.
Packet lengths come from the bytes in the capture; packets are never rebuilt.

### Semantic switches (`mscad_config.py`)

Set to Java-compatible defaults, since that is what the comparison target was
built with. Each is a one-line change if you want the other behaviour.

| Switch | Default | Other value |
|---|---|---|
| `PKT_LEN_MODE` | `payload` (Java `getPayloadBytes()`) | `frame` (pip `len(packet)`) |
| `HEADER_LEN_MODE` | `l4` (TCP `dataofs*4`, UDP 8) | `ip` (pip `ihl*4`) |
| `STD_DDOF` | `1` (commons-math, n-1) | `0` (numpy, n) |
| `SUBFLOW_MODE` | `divide` (Java) | `copy` (pip) |
| `JAVA_INTEGER_DIVISION` | `True` | `False` |
| `INIT_WIN_DEFAULT` | `-1` (CIC convention) | `0` |
| `DROP_SINGLE_PACKET_FLOWS` | `False` (packets conserve) | `True` (closer row count) |
| `ADD_FINAL_ACTIVE_SEGMENT` | `False` (Java) | `True` |
| `ML_INF_MODE` | `drop` (Part 4 as specified) | `cap` (keep the row, cap the rate feature) |
| `ML_DROP_DUPLICATE_FEATURES` | `True` (Part 4 as specified) | `False` (keep repeated flows) |

`PKT_LEN_MODE = "payload"` is the one worth understanding: the CIC CSV family
carries **zeros** in `Fwd Pkt Len Min` / `Bwd Pkt Len Min`, which can only
happen if the length family counts L4 payload bytes (a bare ACK has none). The
pip package counts whole frames instead, which would put a floor of ~54 bytes
on those columns. `SUBFLOW_MODE` is the switch I am least sure of -- if the
four `Subflow` columns top the KS table in section 4.4 of the report, flip it
and re-run.

### The ML file and class balance

`MSCAD_consolidated_ML.csv` is built exactly as Part 4 asks: rows with an
infinite rate feature are dropped and identical feature vectors are
de-duplicated. Both steps remove real attack traffic, and the amount is not
small -- on the synthetic self-test `Port_Scan` keeps **2 of 250** flows
(0.8%), because a port scan is almost entirely single-packet, zero-duration
flows whose `Flow Byts/s` is `Infinity`.

Stage 04 therefore prints, and the report tabulates, a per-label breakdown of
**which step removed how many rows**, plus the kept-%, and names the dominant
cause for the worst-affected class. Nothing is lost silently.

Two switches change it without touching any other stage:

* `ML_INF_MODE = "cap"` keeps those rows, replacing `+/-inf` in each rate
  column with that column's finite maximum times `ML_INF_CAP_FACTOR` (10 by
  default). The written file is then guaranteed finite, which is what the
  LSTM/CNN scalers need.
* `ML_DROP_DUPLICATE_FEATURES = False` keeps genuinely repeated flood and scan
  flows.

Defaults stay at the specified behaviour, so the file you get out of the box is
the one Part 4 describes. Use `MSCAD_consolidated.csv` -- which keeps every
flow and its identifiers -- for the PrefixSpan and attack-graph stages
regardless.

### Zero-duration flows

The Java tool divides by 0.0 and writes `Infinity` for the rate features (and
`NaN` when the numerator is 0 too). This pipeline always writes `Infinity`, so
any `NaN` in the output is a genuine defect and the Part 2 NaN check stays
meaningful. Stage 02 reports the zero-duration flow count separately.
