"""
Stage 04 -- the final consolidated CSVs (Part 4).

MSCAD_consolidated.csv
    Src IP, Dst IP, Src Port, Dst Port, Protocol, Timestamp,
    <the MSCAD features>, Label, Label_Kaggle, Source_Capture
    sorted by Timestamp.  Label_Kaggle carries the official Kaggle label
    where stage 03 matched the row to a unique original row, else empty.

MSCAD_consolidated_ML.csv
    the features + Label only, with infinities dropped and identical feature
    vectors de-duplicated -- ready for RF / XGBoost / LSTM / CNN training.
"""

import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG   # noqa: E402
import mscad_schema as SCH   # noqa: E402

ARGS = CFG.apply_overrides()

CONSOLIDATED = "MSCAD_consolidated.csv"
ML = "MSCAD_consolidated_ML.csv"


def main():
    CFG.ensure_out_dirs()
    print("=" * 78)
    print("STAGE 04 -- consolidated CSVs")
    print("=" * 78)

    schema = SCH.build_schema()
    feats = schema.feature_display

    frames = []
    for key, _label, _desc in CFG.CAPTURES:
        p = CFG.raw_csv_path(key)
        if not os.path.isfile(p):
            print("  NOTE: %s missing, not included" % p)
            continue
        d = pd.read_csv(p, low_memory=False, skipinitialspace=True,
                        keep_default_na=False, na_values=["", "nan", "NaN"],
                        dtype={"Timestamp": str})
        d.columns = SCH.clean_names(d.columns)
        d["Source_Capture"] = key
        d["_row"] = np.arange(len(d))
        frames.append(d)
        print("  %-8s %10s flows" % (key, "{:,}".format(len(d))))
    if not frames:
        print("FATAL: no regenerated CSVs found in %s"
              % os.path.join(CFG.OUT_DIR, CFG.RAW_SUBDIR))
        return 2
    df = pd.concat(frames, ignore_index=True)
    print("  %-8s %10s flows total" % ("ALL", "{:,}".format(len(df))))

    # ---- Label_Kaggle from stage 03 -------------------------------------
    mpath = CFG.metrics_path("03_matched_labels.csv")
    df["Label_Kaggle"] = ""
    if os.path.isfile(mpath):
        m = pd.read_csv(mpath)
        if len(m):
            m["_row"] = m["_row"].astype(int)
            df = df.merge(m, on=["Source_Capture", "_row"], how="left",
                          suffixes=("", "_m"))
            df["Label_Kaggle"] = df["Label_Kaggle_m"].fillna("")
            df = df.drop(columns=[c for c in df.columns
                                  if c.endswith("_m")])
        print("  Label_Kaggle filled from %s: %d rows"
              % (os.path.basename(mpath), int((df["Label_Kaggle"] != "").sum())))
    else:
        print("  NOTE: %s not found; Label_Kaggle left empty everywhere "
              "(run 03_compare_with_kaggle.py first)" % mpath)

    # ---- sort and write the consolidated file ---------------------------
    df = df.sort_values("Timestamp", kind="mergesort").reset_index(drop=True)
    cols = (list(CFG.IDENTIFIER_COLUMNS) + list(feats)
            + [CFG.LABEL_COLUMN, "Label_Kaggle", "Source_Capture"])
    cols = [c for c in cols if c in df.columns]
    outp = os.path.join(CFG.OUT_DIR, CONSOLIDATED)
    df[cols].to_csv(outp, index=False)
    print("\nwrote %s" % outp)
    print("  shape : %d rows x %d columns" % (len(df), len(cols)))
    print("  labels:")
    lc = df[CFG.LABEL_COLUMN].astype(str).value_counts()
    for k, v in lc.items():
        print("      %-18s %10s" % (k, "{:,}".format(int(v))))
    print("  Label_Kaggle present : %s"
          % "{:,}".format(int((df["Label_Kaggle"].astype(str) != "").sum())))
    print("  per capture:")
    for k, v in df["Source_Capture"].value_counts().items():
        print("      %-10s %10s" % (k, "{:,}".format(int(v))))

    # ---- ML file --------------------------------------------------------
    print("\nbuilding the ML file ...")
    ml = df[[c for c in feats if c in df.columns]
            + [CFG.LABEL_COLUMN]].copy()
    for c in ml.columns[:-1]:
        if ml[c].dtype == object:
            ml[c] = pd.to_numeric(
                ml[c].replace({"Infinity": np.inf, "-Infinity": -np.inf,
                               "inf": np.inf, "-inf": -np.inf}),
                errors="coerce")
    n0 = len(ml)
    fcols = list(ml.columns[:-1])
    inf_mode = str(getattr(CFG, "ML_INF_MODE", "drop")).lower()
    print("  inf handling                            : %s" % inf_mode)

    n_inf_cells = 0
    capped = {}
    if inf_mode == "cap":
        # Keep the row; replace +/-inf with a finite sentinel derived from the
        # column's own finite maximum, so tree models still see "very large"
        # and scaled models (LSTM/CNN) do not receive a non-finite input.
        factor = float(getattr(CFG, "ML_INF_CAP_FACTOR", 10.0))
        for c in fcols:
            col = ml[c]
            isinf = np.isinf(col.to_numpy(dtype="float64", na_value=np.nan))
            k = int(isinf.sum())
            if not k:
                continue
            n_inf_cells += k
            finite_max = col[np.isfinite(
                col.to_numpy(dtype="float64", na_value=np.nan))].max()
            if not np.isfinite(finite_max) or finite_max <= 0:
                finite_max = 1.0
            cap = float(finite_max) * factor
            ml.loc[isinf & (col > 0), c] = cap
            ml.loc[isinf & (col < 0), c] = -cap
            capped[c] = {"cells": k, "cap": cap}
        for c, d in sorted(capped.items()):
            print("      capped %-14s %7s cell(s) at %.6g"
                  % (c, "{:,}".format(d["cells"]), d["cap"]))

    ml[fcols] = ml[fcols].replace([np.inf, -np.inf], np.nan)
    bad = ml[fcols].isna().any(axis=1)
    print("  rows with inf/NaN in a feature, dropped : %s"
          % "{:,}".format(int(bad.sum())))
    lost_inf = (ml.loc[bad, CFG.LABEL_COLUMN].astype(str)
                .value_counts().to_dict())
    ml = ml[~bad]
    n1 = len(ml)
    before_dedup = (ml[CFG.LABEL_COLUMN].astype(str)
                    .value_counts().to_dict())
    if getattr(CFG, "ML_DROP_DUPLICATE_FEATURES", True):
        ml = ml.drop_duplicates(subset=fcols)
    n2 = len(ml)
    print("  identical feature vectors dropped       : %s"
          % "{:,}".format(n1 - n2))
    after_dedup = (ml[CFG.LABEL_COLUMN].astype(str)
                   .value_counts().to_dict())
    lost_dedup = {k: int(v) - int(after_dedup.get(k, 0))
                  for k, v in before_dedup.items()}
    mlp = os.path.join(CFG.OUT_DIR, ML)
    ml.to_csv(mlp, index=False)
    print("\nwrote %s" % mlp)
    print("  shape : %d rows x %d columns" % (ml.shape[0], ml.shape[1]))
    print("  labels:")
    mlc = ml[CFG.LABEL_COLUMN].astype(str).value_counts()
    for k, v in mlc.items():
        print("      %-18s %10s" % (k, "{:,}".format(int(v))))

    # What this file cost, per label, split by which step took the rows --
    # never let the class loss be silent, and never misattribute it.
    print("\n  rows kept per label, and where the rest went:")
    print("      %-18s %10s %9s %9s %10s %7s"
          % ("label", "full", "-inf/NaN", "-dupes", "ML", "kept%"))
    kept_pct, loss_cause = {}, {}
    for k, v in lc.items():
        k = str(k)
        full = int(v)
        kept = int(mlc.get(k, 0))
        d_inf = int(lost_inf.get(k, 0))
        d_dup = int(lost_dedup.get(k, 0))
        pct = 100.0 * kept / full if full else 0.0
        kept_pct[k] = pct
        loss_cause[k] = {"inf_nan": d_inf, "duplicate": d_dup}
        print("      %-18s %10s %9s %9s %10s %6.1f%%"
              % (k, "{:,}".format(full), "{:,}".format(d_inf),
                 "{:,}".format(d_dup), "{:,}".format(kept), pct))

    worst = sorted(kept_pct.items(), key=lambda kv: kv[1])[:1]
    if worst and worst[0][1] < 25.0:
        wk = worst[0][0]
        c = loss_cause[wk]
        print("\n  NOTE: '%s' retains only %.1f%% of its flows in the ML file."
              % (wk, worst[0][1]))
        if c["duplicate"] >= c["inf_nan"]:
            print("        The dominant cause is de-duplication (%s rows vs "
                  "%s for inf/NaN):\n        this attack genuinely produces "
                  "near-identical flows. Set\n        "
                  "ML_DROP_DUPLICATE_FEATURES = False in mscad_config.py to "
                  "keep them."
                  % ("{:,}".format(c["duplicate"]),
                     "{:,}".format(c["inf_nan"])))
        else:
            print("        The dominant cause is inf/NaN in the rate features "
                  "(%s rows vs\n        %s for de-duplication), i.e. "
                  "zero-duration flows. Set\n        ML_INF_MODE = \"cap\" in "
                  "mscad_config.py to keep them."
                  % ("{:,}".format(c["inf_nan"]),
                     "{:,}".format(c["duplicate"])))

    with open(CFG.metrics_path("04_consolidated.json"), "w") as fh:
        json.dump({
            "consolidated_path": outp,
            "consolidated_shape": [int(len(df)), int(len(cols))],
            "consolidated_columns": cols,
            "consolidated_labels": {str(k): int(v) for k, v in lc.items()},
            "consolidated_per_capture": {
                str(k): int(v) for k, v in
                df["Source_Capture"].value_counts().items()},
            "label_kaggle_filled": int(
                (df["Label_Kaggle"].astype(str) != "").sum()),
            "ml_path": mlp,
            "ml_shape": [int(ml.shape[0]), int(ml.shape[1])],
            "ml_labels": {str(k): int(v) for k, v in mlc.items()},
            "ml_rows_dropped_inf_nan": int(n0 - n1),
            "ml_rows_dropped_duplicate": int(n1 - n2),
            "ml_inf_mode": inf_mode,
            "ml_inf_cells_capped": int(n_inf_cells),
            "ml_inf_cap_factor": float(
                getattr(CFG, "ML_INF_CAP_FACTOR", 10.0)),
            "ml_capped_columns": {str(k): v for k, v in capped.items()},
            "ml_kept_pct_per_label": {str(k): round(v, 2)
                                      for k, v in kept_pct.items()},
            "ml_loss_cause_per_label": loss_cause,
            "ml_drop_duplicate_features": bool(
                getattr(CFG, "ML_DROP_DUPLICATE_FEATURES", True)),
        }, fh, indent=2, default=str)
    print("\nMetrics: %s" % CFG.metrics_path("04_consolidated.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
