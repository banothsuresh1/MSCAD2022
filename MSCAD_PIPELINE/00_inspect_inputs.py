"""
Stage 00 -- check the input folders and describe the original Kaggle file.

Reads only; never modifies, moves or deletes anything in the input folders.
Writes one JSON metrics file into OUT_DIR\\metrics for the final report.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mscad_config as CFG  # noqa: E402
import mscad_schema as SCH  # noqa: E402

CFG.apply_overrides()


def main():
    print("=" * 78)
    print("STAGE 00 -- input inspection")
    print("=" * 78)
    report = {}

    # ---- PCAP folder ----------------------------------------------------
    pcap_dir, how = CFG.resolve_pcap_dir()
    print("\n[1] PCAP folder")
    for cand in CFG.PCAP_DIR_CANDIDATES:
        print("    candidate : %s  -> %s"
              % (cand, "EXISTS" if os.path.isdir(cand) else "missing"))
    if pcap_dir is None:
        print("    RESULT    : NOT FOUND (searched %s)" % CFG.PCAP_SEARCH_ROOT)
        report["pcap_dir"] = None
    else:
        print("    USING     : %s" % pcap_dir)
        print("    found via : %s" % how)
        report["pcap_dir"] = pcap_dir
        report["pcap_dir_how"] = how
        entries = sorted(os.listdir(pcap_dir))
        print("    contents  : %d entries" % len(entries))
        listing = []
        for e in entries:
            full = os.path.join(pcap_dir, e)
            size = os.path.getsize(full) if os.path.isfile(full) else 0
            listing.append({"name": e, "bytes": size})
            print("        %-28s %14s bytes" % (e, "{:,}".format(size)))
        report["pcap_dir_contents"] = listing

        print("\n    capture -> file resolution:")
        resolved = {}
        for key, label, desc in CFG.CAPTURES:
            f = CFG.find_capture_file(pcap_dir, key)
            resolved[key] = f
            print("        %-7s %-14s %s"
                  % (key, label, f if f else "*** NOT FOUND ***"))
        report["capture_files"] = resolved
        missing = [k for k, v in resolved.items() if not v]
        if missing:
            print("    WARNING: no file found for: %s" % ", ".join(missing))

    # ---- Original CSV folder -------------------------------------------
    print("\n[2] Original Kaggle CSV folder")
    print("    path      : %s  -> %s"
          % (CFG.CSV_ORIGINAL_DIR,
             "EXISTS" if os.path.isdir(CFG.CSV_ORIGINAL_DIR) else "missing"))
    orig, all_cands = SCH.find_original_file()
    report["csv_original_dir"] = CFG.CSV_ORIGINAL_DIR
    report["csv_original_candidates"] = all_cands
    report["original_file"] = orig
    if all_cands:
        print("    contents  :")
        for c in all_cands:
            print("        %-40s %14s bytes"
                  % (os.path.basename(c), "{:,}".format(os.path.getsize(c))))
    if orig is None:
        print("    RESULT    : no MSCAD csv/xlsx found")
    else:
        print("    USING     : %s" % orig)
        describe_original(orig, report)

    # ---- Schema ---------------------------------------------------------
    print("\n[3] Output schema")
    schema = SCH.build_schema(orig)
    print("    " + schema.describe().replace("\n", "\n    "))
    report["schema_source"] = schema.source
    report["schema_feature_count"] = len(schema.features)
    report["schema_features"] = schema.feature_display
    report["schema_unmapped"] = schema.unknown

    # ---- Output folder --------------------------------------------------
    CFG.ensure_out_dirs()
    print("\n[4] Output folder")
    print("    %s (created if absent)" % CFG.OUT_DIR)
    print("    %s" % os.path.join(CFG.OUT_DIR, CFG.RAW_SUBDIR))
    print("    %s" % os.path.join(CFG.OUT_DIR, CFG.METRICS_SUBDIR))

    with open(CFG.metrics_path("00_inputs.json"), "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print("\nWrote %s" % CFG.metrics_path("00_inputs.json"))
    return 0


def describe_original(path, report):
    import pandas as pd
    if path.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path, low_memory=False, skipinitialspace=True)
    raw_cols = list(df.columns)
    df.columns = SCH.clean_names(raw_cols)

    print("    shape     : %d rows x %d columns" % (df.shape[0], df.shape[1]))
    report["original_shape"] = list(df.shape)
    report["original_columns_raw"] = [str(c) for c in raw_cols]
    report["original_columns_clean"] = [str(c) for c in df.columns]

    print("    columns   :")
    for i, c in enumerate(df.columns, 1):
        print("        %3d. %s" % (i, c))

    lab = None
    for cand in ("Label", "label", "Labels"):
        if cand in df.columns:
            lab = cand
            break
    if lab is None:
        print("    WARNING: no Label column found")
        report["original_label_counts"] = {}
    else:
        counts = df[lab].value_counts(dropna=False)
        print("    Label counts (column %r):" % lab)
        total = int(counts.sum())
        for k, v in counts.items():
            print("        %-18s %8d  (%5.2f%%)" % (k, v, 100.0 * v / total))
        print("        %-18s %8d" % ("TOTAL", total))
        report["original_label_counts"] = {str(k): int(v)
                                           for k, v in counts.items()}
        report["original_label_column"] = lab


if __name__ == "__main__":
    sys.exit(main())
