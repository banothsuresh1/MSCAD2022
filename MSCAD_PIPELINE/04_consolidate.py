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
    ml[fcols] = ml[fcols].replace([np.inf, -np.inf], np.nan)
    bad = ml[fcols].isna().any(axis=1)
    print("  rows with inf/NaN in a feature, dropped : %s"
          % "{:,}".format(int(bad.sum())))
    ml = ml[~bad]
    n1 = len(ml)
    ml = ml.drop_duplicates(subset=fcols)
    n2 = len(ml)
    print("  identical feature vectors dropped       : %s"
          % "{:,}".format(n1 - n2))
    mlp = os.path.join(CFG.OUT_DIR, ML)
    ml.to_csv(mlp, index=False)
    print("\nwrote %s" % mlp)
    print("  shape : %d rows x %d columns" % (ml.shape[0], ml.shape[1]))
    print("  labels:")
    mlc = ml[CFG.LABEL_COLUMN].astype(str).value_counts()
    for k, v in mlc.items():
        print("      %-18s %10s" % (k, "{:,}".format(int(v))))

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
        }, fh, indent=2, default=str)
    print("\nMetrics: %s" % CFG.metrics_path("04_consolidated.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
