# MSCAD_pipeline.ipynb

A single self-contained notebook that reproduces the whole MSCAD regeneration
pipeline on **Kernel -> Restart & Run All**.

Copy `MSCAD_pipeline.ipynb` into
`D:\IDSPROJECT2026\MSCAD\MSCAD_REGENERATED\` and open it there.

## Self-contained

Nothing is imported from `scripts\`. The patched CICFlowMeter engine, the
feature-name tables and the schema resolver are all inlined, taken verbatim
from `mscad_flowmeter.py`, `mscad_names.py` and `mscad_schema.py`, so the
notebook and the scripts cannot drift apart. `cicflowmeter` itself is reported
in step 2 for the record but never imported, so a broken install of it cannot
break the run.

## Layout

| Step | What |
|---|---|
| 0 | title, inputs, outputs, runtime per step |
| 1 | settings: paths + `RUN_EXTRACTION`, `ONLY`, `ATTACKER_IP`, `WRITE_TO_MAIN` |
| 2 | environment check (versions, folders, tshark) |
| 3 | the patched engine, inlined, with the patch table |
| 3b | the 66 output columns, read from the original Kaggle header |
| 4 | extraction (PCAP -> flows), only if `RUN_EXTRACTION = True` |
| 5 | labelling from `raw\`, attackers + top-5 senders per capture |
| 6 | verification: packet completeness, data sanity, identical rows |
| 7 | comparison with Kaggle: schema, rows, units, KS, row matching |
| 8 | three figures, inline and as PNG |
| 9 | `MSCAD_consolidated.csv` + `MSCAD_consolidated_ML.csv` |
| 9b | diff of the new files against the existing ones |
| 10 | output-file table + a pass/fail list of every check |

## Safety

`WRITE_TO_MAIN = False` by default: the run writes into
`MSCAD_REGENERATED\notebook_test\` and your current `MSCAD_consolidated.csv`
is not touched. Step 9b diffs the two. Only once it prints `IDENTICAL` should
you set `WRITE_TO_MAIN = True` and re-run.

## Why `RUN_EXTRACTION = False` loses nothing

Extraction's pass 1 finds attackers as `sum(Tot Fwd Pkts)` grouped by `Src IP`,
taking every IP at >= 50% of the top sender. That quantity is still fully
present in the raw CSVs, so step 5 reproduces the same attacker set without
reading a single packet. Step 5 also compares its recomputed label against the
`Label` already stored in `raw\` and reports any disagreement.

## Verified

Executed head to tail with `jupyter nbconvert --to notebook --execute` on a
synthetic fixture, in three configurations:

| Configuration | Result |
|---|---|
| `RUN_EXTRACTION = False` | 27/27 cells clean, 15/15 checks pass, output **byte-identical** to the `scripts\` pipeline |
| `RUN_EXTRACTION = True` | same, re-deriving every flow from the PCAPs |
| `ONLY = "N-0"` + `ATTACKER_IP` override | clean; step 9b correctly reports a difference (one capture vs six) |

The cell outputs saved in the `.ipynb` are from that fixture, not from MSCAD --
see the banner at the top of the notebook.
