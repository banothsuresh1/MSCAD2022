"""
Stage 03 -- compare the regenerated flows with the original Kaggle MSCAD file
(Part 3).

  3.1 schema      : same feature names, same order?
  3.2 rows/label  : original vs regenerated, difference and %
  3.3 units       : median Flow Duration and Flow IAT Mean per label in both
                    (flagging any ~10^6 ratio, i.e. a seconds/microseconds mix-up)
  3.4 per-feature : mean, median and the two-sample Kolmogorov-Smirnov
                    statistic per label; the 10 most different features
  3.5 row match   : integer-feature key, keys unique in the original only;
                    match % per label plus a my-label x Kaggle-label table

It also writes metrics/03_matched_labels.csv, which stage 04 uses to fill the
Label_Kaggle column.
"""

import json
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd
from scipy import stats as sstats

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG   # noqa: E402
import mscad_schema as SCH   # noqa: E402

ARGS = CFG.apply_overrides()

MAX_KS_SAMPLE = 200_000   # cap per side so ks_2samp stays tractable
RNG = np.random.default_rng(20260101)


# --------------------------------------------------------------------------
def to_numeric_block(df, cols):
    out = pd.DataFrame(index=df.index)
    for c in cols:
        s = df[c]
        if s.dtype == object:
            s = s.replace({"Infinity": np.inf, "-Infinity": -np.inf,
                           "inf": np.inf, "-inf": -np.inf, "": np.nan})
        out[c] = pd.to_numeric(s, errors="coerce")
    return out


def load_original(path):
    if path.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path, low_memory=False, skipinitialspace=True)
    df.columns = SCH.clean_names(df.columns)
    return df


def load_regenerated(schema):
    frames = []
    for key, _label, _desc in CFG.CAPTURES:
        p = CFG.raw_csv_path(key)
        if not os.path.isfile(p):
            print("  NOTE: %s missing, not included" % p)
            continue
        d = pd.read_csv(p, low_memory=False, skipinitialspace=True,
                        keep_default_na=False,
                        na_values=["", "nan", "NaN"])
        d.columns = SCH.clean_names(d.columns)
        d["Source_Capture"] = key
        d["_row"] = np.arange(len(d))
        frames.append(d)
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


def ks(a, b):
    a = a[np.isfinite(a)]
    b = b[np.isfinite(b)]
    if len(a) < 2 or len(b) < 2:
        return float("nan"), float("nan"), len(a), len(b)
    if len(a) > MAX_KS_SAMPLE:
        a = RNG.choice(a, MAX_KS_SAMPLE, replace=False)
    if len(b) > MAX_KS_SAMPLE:
        b = RNG.choice(b, MAX_KS_SAMPLE, replace=False)
    r = sstats.ks_2samp(a, b)
    return float(r.statistic), float(r.pvalue), len(a), len(b)


# --------------------------------------------------------------------------
def main():
    CFG.ensure_out_dirs()
    print("=" * 78)
    print("STAGE 03 -- comparison with the original Kaggle MSCAD file")
    print("=" * 78)

    orig_path, _cands = SCH.find_original_file()
    if orig_path is None:
        print("FATAL: no original MSCAD csv/xlsx found in %s"
              % CFG.CSV_ORIGINAL_DIR)
        return 2
    print("original    : %s" % orig_path)

    schema = SCH.build_schema(orig_path)
    orig = load_original(orig_path)
    regen = load_regenerated(schema)
    if regen is None:
        print("FATAL: no regenerated CSVs in %s"
              % os.path.join(CFG.OUT_DIR, CFG.RAW_SUBDIR))
        return 2
    print("regenerated : %d flows from %d captures"
          % (len(regen), regen["Source_Capture"].nunique()))

    out = {"original_file": orig_path,
           "original_shape": list(orig.shape),
           "regenerated_shape": [int(len(regen)),
                                 int(len(schema.feature_display))]}

    # ---- 3.1 schema -----------------------------------------------------
    print("\n" + "=" * 78)
    print("3.1  SCHEMA")
    print("=" * 78)
    feats = schema.feature_display
    orig_label_col = next((c for c in ("Label", "label", "Labels")
                           if c in orig.columns), None)
    orig_feats = [c for c in orig.columns if c != orig_label_col]
    missing_in_regen = [c for c in orig_feats if c not in regen.columns]
    extra_in_regen = [c for c in feats if c not in orig.columns]
    same_order = (list(feats) ==
                  [c for c in orig_feats if c in feats])
    print("original feature columns    : %d" % len(orig_feats))
    print("regenerated feature columns : %d" % len(feats))
    print("names and order identical   : %s" % ("YES" if
          (not missing_in_regen and not extra_in_regen and same_order)
          else "NO"))
    if missing_in_regen:
        print("  in original but NOT regenerated (%d): %s"
              % (len(missing_in_regen), ", ".join(map(str, missing_in_regen))))
    if extra_in_regen:
        print("  regenerated but NOT in original (%d): %s"
              % (len(extra_in_regen), ", ".join(map(str, extra_in_regen))))
    if schema.unknown:
        print("  original columns that could not be mapped to a "
              "CICFlowMeter feature (%d): %s"
              % (len(schema.unknown), ", ".join(map(str, schema.unknown))))
    out["schema"] = {
        "original_feature_columns": [str(c) for c in orig_feats],
        "regenerated_feature_columns": list(feats),
        "missing_in_regenerated": [str(c) for c in missing_in_regen],
        "extra_in_regenerated": [str(c) for c in extra_in_regen],
        "same_names_and_order": bool(not missing_in_regen
                                     and not extra_in_regen and same_order),
        "unmapped_original_columns": [str(c) for c in schema.unknown],
    }

    common = [c for c in feats if c in orig.columns]
    print("common features used for the comparisons below: %d" % len(common))
    out["common_features"] = common

    if orig_label_col is None:
        print("FATAL: original file has no Label column")
        return 2

    # ---- 3.2 rows per label ---------------------------------------------
    print("\n" + "=" * 78)
    print("3.2  ROWS PER LABEL")
    print("=" * 78)
    oc = orig[orig_label_col].astype(str).value_counts()
    rc = regen[CFG.LABEL_COLUMN].astype(str).value_counts()
    labels = sorted(set(oc.index) | set(rc.index))
    print("%-18s %12s %14s %12s %10s" % ("label", "Kaggle", "regenerated",
                                         "difference", "diff %"))
    print("-" * 70)
    rows32 = []
    for lab in labels:
        o = int(oc.get(lab, 0))
        r = int(rc.get(lab, 0))
        d = r - o
        pct = (100.0 * d / o) if o else float("nan")
        rows32.append({"label": lab, "kaggle": o, "regenerated": r,
                       "difference": d, "diff_pct": pct})
        print("%-18s %12s %14s %12s %10s"
              % (lab, "{:,}".format(o), "{:,}".format(r),
                 "{:+,}".format(d),
                 "-" if o == 0 else "%+.1f%%" % pct))
    print("-" * 70)
    print("%-18s %12s %14s %12s"
          % ("TOTAL", "{:,}".format(int(oc.sum())),
             "{:,}".format(int(rc.sum())),
             "{:+,}".format(int(rc.sum() - oc.sum()))))
    only_o = sorted(set(oc.index) - set(rc.index))
    only_r = sorted(set(rc.index) - set(oc.index))
    if only_o:
        print("labels only in Kaggle      : %s" % ", ".join(only_o))
    if only_r:
        print("labels only in regenerated : %s" % ", ".join(only_r))
    out["rows_per_label"] = rows32
    out["labels_only_kaggle"] = only_o
    out["labels_only_regenerated"] = only_r

    shared_labels = [l for l in labels
                     if oc.get(l, 0) > 0 and rc.get(l, 0) > 0]

    # ---- 3.3 units ------------------------------------------------------
    print("\n" + "=" * 78)
    print("3.3  UNITS CHECK  (both files should be in MICROSECONDS)")
    print("=" * 78)
    unit_cols = [c for c in ("Flow Duration", "Flow IAT Mean") if c in common]
    rows33 = []
    if not unit_cols:
        print("Flow Duration / Flow IAT Mean not available in both files.")
    else:
        print("%-18s %-16s %16s %16s %10s %s"
              % ("label", "feature", "Kaggle median", "regen median",
                 "ratio", "verdict"))
        print("-" * 100)
        for lab in shared_labels:
            ob = to_numeric_block(orig[orig[orig_label_col].astype(str) == lab],
                                  unit_cols)
            rb = to_numeric_block(regen[regen[CFG.LABEL_COLUMN].astype(str)
                                        == lab], unit_cols)
            for c in unit_cols:
                om = float(np.nanmedian(ob[c].to_numpy(dtype="float64"))) \
                    if len(ob) else float("nan")
                rm = float(np.nanmedian(rb[c].to_numpy(dtype="float64"))) \
                    if len(rb) else float("nan")
                ratio = (om / rm) if (rm not in (0,) and np.isfinite(rm)
                                      and np.isfinite(om) and rm != 0) \
                    else float("nan")
                verdict = "ok"
                if np.isfinite(ratio):
                    if 1e5 < ratio < 1e7:
                        verdict = "*** Kaggle looks 10^6 LARGER (unit mismatch)"
                    elif 1e-7 < ratio < 1e-5:
                        verdict = "*** regen looks 10^6 LARGER (unit mismatch)"
                rows33.append({"label": lab, "feature": c,
                               "kaggle_median": om, "regen_median": rm,
                               "ratio": ratio, "verdict": verdict})
                print("%-18s %-16s %16.3f %16.3f %10s %s"
                      % (lab, c, om, rm,
                         "-" if not np.isfinite(ratio) else "%.4g" % ratio,
                         verdict))
    out["units_check"] = rows33

    # ---- 3.4 per-feature distributions ---------------------------------
    print("\n" + "=" * 78)
    print("3.4  PER-FEATURE DISTRIBUTION COMPARISON PER LABEL")
    print("=" * 78)
    per_label = {}
    for lab in shared_labels:
        ob = to_numeric_block(orig[orig[orig_label_col].astype(str) == lab],
                              common)
        rb = to_numeric_block(regen[regen[CFG.LABEL_COLUMN].astype(str) == lab],
                              common)
        recs = []
        for c in common:
            a = ob[c].to_numpy(dtype="float64")
            b = rb[c].to_numpy(dtype="float64")
            st, pv, na, nb = ks(a, b)
            with np.errstate(all="ignore"):
                recs.append({
                    "feature": c,
                    "kaggle_mean": float(np.nanmean(a[np.isfinite(a)]))
                    if np.isfinite(a).any() else float("nan"),
                    "regen_mean": float(np.nanmean(b[np.isfinite(b)]))
                    if np.isfinite(b).any() else float("nan"),
                    "kaggle_median": float(np.nanmedian(a[np.isfinite(a)]))
                    if np.isfinite(a).any() else float("nan"),
                    "regen_median": float(np.nanmedian(b[np.isfinite(b)]))
                    if np.isfinite(b).any() else float("nan"),
                    "ks": st, "ks_p": pv, "n_kaggle": na, "n_regen": nb,
                })
        recs.sort(key=lambda d: (-(d["ks"] if d["ks"] == d["ks"] else -1)))
        per_label[lab] = recs
        print("\n--- %s   (Kaggle n=%d, regenerated n=%d)  10 most different "
              "features by KS ---" % (lab, int(oc.get(lab, 0)),
                                      int(rc.get(lab, 0))))
        print("%-22s %14s %14s %14s %14s %8s"
              % ("feature", "Kaggle mean", "regen mean", "Kaggle med",
                 "regen med", "KS"))
        for d in recs[:10]:
            print("%-22s %14.4g %14.4g %14.4g %14.4g %8s"
                  % (d["feature"][:22], d["kaggle_mean"], d["regen_mean"],
                     d["kaggle_median"], d["regen_median"],
                     "-" if d["ks"] != d["ks"] else "%.4f" % d["ks"]))
    out["per_feature_by_label"] = per_label

    if per_label:
        avg = {}
        for lab, recs in per_label.items():
            for d in recs:
                if d["ks"] == d["ks"]:
                    avg.setdefault(d["feature"], []).append(d["ks"])
        overall = sorted(((f, float(np.mean(v))) for f, v in avg.items()),
                         key=lambda kv: -kv[1])
        print("\n--- 10 most different features averaged over all shared "
              "labels ---")
        print("%-28s %10s" % ("feature", "mean KS"))
        for f, v in overall[:10]:
            print("%-28s %10.4f" % (f, v))
        out["overall_worst_features"] = [{"feature": f, "mean_ks": v}
                                         for f, v in overall]

    # ---- 3.5 row-level matching -----------------------------------------
    print("\n" + "=" * 78)
    print("3.5  ROW-LEVEL MATCHING")
    print("=" * 78)
    key_cols = [c for c in CFG.MATCH_KEY_FEATURES if c in common]
    dropped = [c for c in CFG.MATCH_KEY_FEATURES if c not in common]
    print("key features used (%d): %s" % (len(key_cols), ", ".join(key_cols)))
    if dropped:
        print("key features unavailable in both files, dropped: %s"
              % ", ".join(dropped))
    out["match_key_features"] = key_cols
    out["match_key_dropped"] = dropped

    matched_rows = pd.DataFrame(columns=["Source_Capture", "_row",
                                         "Label_Kaggle"])
    if not key_cols:
        print("no usable key features; row matching skipped")
        out["row_matching"] = {"skipped": "no usable key features"}
    else:
        ob = to_numeric_block(orig, key_cols)
        rb = to_numeric_block(regen, key_cols)
        o_ok = np.isfinite(ob.to_numpy(dtype="float64")).all(axis=1)
        r_ok = np.isfinite(rb.to_numpy(dtype="float64")).all(axis=1)
        print("original rows with a complete finite key    : %d / %d"
              % (int(o_ok.sum()), len(orig)))
        print("regenerated rows with a complete finite key : %d / %d"
              % (int(r_ok.sum()), len(regen)))

        def mkkeys(block, mask):
            """Integer key tuples. Plain Python tuples in a dict, not a
            pandas Index: an Index of tuples silently becomes a MultiIndex."""
            arr = np.rint(block.to_numpy(dtype="float64")[mask]).astype(
                "int64", copy=False)
            return list(map(tuple, arr))

        o_keys = mkkeys(ob, o_ok)
        r_keys = mkkeys(rb, r_ok)
        o_lab = orig.loc[o_ok, orig_label_col].astype(str).to_numpy()

        counts = Counter(o_keys)
        lut = {}
        for k, lab in zip(o_keys, o_lab):
            if counts[k] == 1:
                lut[k] = lab
        print("distinct keys in the original               : %d"
              % len(counts))
        print("keys unique in the original (usable)        : %d  (%.1f%% of "
              "its rows)" % (len(lut),
                             100.0 * len(lut) / max(1, len(o_keys))))

        r_idx = np.flatnonzero(r_ok)
        regen["Label_Kaggle"] = ""
        hit_idx, hit_lab = [], []
        for pos, k in zip(r_idx, r_keys):
            lab = lut.get(k)
            if lab is not None:
                hit_idx.append(pos)
                hit_lab.append(lab)
        if hit_idx:
            regen.loc[regen.index[hit_idx], "Label_Kaggle"] = hit_lab

        total_matched = len(hit_idx)
        print("\nregenerated rows matched to a unique original row: %d / %d "
              "(%.2f%%)" % (total_matched, len(regen),
                            100.0 * total_matched / max(1, len(regen))))

        print("\nmatch rate per regenerated label:")
        print("%-18s %12s %12s %10s" % ("my label", "rows", "matched", "%"))
        print("-" * 56)
        rows35 = []
        for lab in sorted(regen[CFG.LABEL_COLUMN].astype(str).unique()):
            sel = regen[CFG.LABEL_COLUMN].astype(str) == lab
            n = int(sel.sum())
            m = int((sel & (regen["Label_Kaggle"] != "")).sum())
            rows35.append({"label": lab, "rows": n, "matched": m,
                           "pct": 100.0 * m / n if n else 0.0})
            print("%-18s %12s %12s %9.2f%%"
                  % (lab, "{:,}".format(n), "{:,}".format(m),
                     100.0 * m / n if n else 0))

        print("\nmatch rate per capture:")
        print("%-10s %12s %12s %10s" % ("capture", "rows", "matched", "%"))
        print("-" * 48)
        rows35c = []
        for cap in [c[0] for c in CFG.CAPTURES]:
            sel = regen["Source_Capture"] == cap
            n = int(sel.sum())
            if not n:
                continue
            m = int((sel & (regen["Label_Kaggle"] != "")).sum())
            rows35c.append({"capture": cap, "rows": n, "matched": m,
                            "pct": 100.0 * m / n})
            print("%-10s %12s %12s %9.2f%%"
                  % (cap, "{:,}".format(n), "{:,}".format(m), 100.0 * m / n))

        print("\nconfusion table for matched rows  (rows = my label, "
              "columns = Kaggle label):")
        sub = regen[regen["Label_Kaggle"] != ""]
        if len(sub):
            ct = pd.crosstab(sub[CFG.LABEL_COLUMN].astype(str),
                             sub["Label_Kaggle"].astype(str))
            with pd.option_context("display.width", 200,
                                   "display.max_columns", 50):
                print(ct.to_string())
            agree = int(sum(ct.loc[l, l] for l in ct.index
                            if l in ct.columns))
            print("\nlabel agreement on matched rows: %d / %d (%.2f%%)"
                  % (agree, len(sub), 100.0 * agree / len(sub)))
            out["confusion_matched"] = ct.to_dict()
            out["label_agreement_matched"] = {
                "agree": agree, "total": int(len(sub)),
                "pct": 100.0 * agree / len(sub)}
        else:
            print("(no matched rows)")

        out["row_matching"] = {
            "total_regenerated": int(len(regen)),
            "total_matched": total_matched,
            "match_pct": 100.0 * total_matched / max(1, len(regen)),
            "original_rows_with_key": int(o_ok.sum()),
            "regen_rows_with_key": int(r_ok.sum()),
            "distinct_original_keys": int(len(counts)),
            "unique_original_keys": int(len(lut)),
            "per_label": rows35,
            "per_capture": rows35c,
        }
        matched_rows = regen.loc[regen["Label_Kaggle"] != "",
                                 ["Source_Capture", "_row", "Label_Kaggle"]]

    matched_rows.to_csv(CFG.metrics_path("03_matched_labels.csv"),
                        index=False)
    print("\nwrote %s (%d matched rows) for stage 04"
          % (CFG.metrics_path("03_matched_labels.csv"), len(matched_rows)))

    with open(CFG.metrics_path("03_comparison.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print("Metrics: %s" % CFG.metrics_path("03_comparison.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
