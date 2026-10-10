"""
Locating and reading the original Kaggle MSCAD file, and deriving the output
schema from its real header.

The pipeline never hard-codes "the 66 MSCAD feature names".  It reads them
out of the original file so the regenerated CSV carries exactly those names,
in exactly that order.
"""

import csv
import glob
import os

import mscad_config as CFG
import mscad_names as N


def find_original_file(csv_dir=None):
    """Return the most likely original MSCAD file in CSV_ORIGINAL, or None."""
    csv_dir = csv_dir or CFG.CSV_ORIGINAL_DIR
    if not os.path.isdir(csv_dir):
        return None, []
    cands = []
    for ext in ("*.csv", "*.CSV", "*.xlsx", "*.XLSX", "*.xls"):
        cands.extend(glob.glob(os.path.join(csv_dir, ext)))
    cands = sorted(set(cands))
    if not cands:
        return None, []

    def score(p):
        base = os.path.basename(p).lower()
        s = 0
        if "mscad" in base:
            s -= 100
        if base.endswith(".csv"):
            s -= 10
        s += len(base)
        return s

    return sorted(cands, key=score)[0], cands


def read_header(path):
    """Read just the header row of a csv/xlsx file."""
    if path.lower().endswith((".xlsx", ".xls")):
        import pandas as pd
        return list(pd.read_excel(path, nrows=0).columns)
    with open(path, "r", newline="", encoding="utf-8-sig", errors="replace") as fh:
        for row in csv.reader(fh):
            return row
    return []


def clean_names(names):
    """Strip surrounding whitespace and quotes, as Part 3 requires."""
    return [str(n).strip().strip('"').strip("'").strip() for n in names]


class Schema:
    """The output column layout.

    features : [(display_name, internal_key), ...] in original-file order
    unknown  : original header names that could not be mapped
    source   : where the layout came from
    """

    def __init__(self, features, unknown, source, original_header=None):
        self.features = features
        self.unknown = unknown
        self.source = source
        self.original_header = original_header or []

    @property
    def feature_display(self):
        return [d for d, _k in self.features]

    @property
    def feature_keys(self):
        return [k for _d, k in self.features]

    @property
    def out_columns(self):
        return (list(CFG.IDENTIFIER_COLUMNS) + self.feature_display
                + [CFG.LABEL_COLUMN])

    def describe(self):
        lines = ["Output schema source: %s" % self.source,
                 "Feature columns: %d" % len(self.features)]
        if self.unknown:
            lines.append("UNMAPPED original columns (%d): %s"
                         % (len(self.unknown), ", ".join(map(str, self.unknown))))
        else:
            lines.append("UNMAPPED original columns: none")
        return "\n".join(lines)


def build_schema(path=None, verbose=True):
    """Build the output schema from the original file, or fall back to the
    canonical 76 CICFlowMeter features if the original cannot be read."""
    if path is None:
        path, _all = find_original_file()
    if path and os.path.isfile(path):
        header = clean_names(read_header(path))
        feats, idents, unknown = N.resolve_header(header)
        # Drop duplicate keys, keeping the first occurrence.
        seen, uniq = set(), []
        for disp, key in feats:
            if key in seen:
                unknown.append("%s (duplicate of %s)" % (disp, key))
                continue
            seen.add(key)
            uniq.append((disp, key))
        if uniq:
            return Schema(uniq, unknown,
                          "original header of %s" % os.path.basename(path),
                          header)
        if verbose:
            print("  WARNING: no feature columns recognised in %s" % path)
    if verbose:
        print("  WARNING: original MSCAD file not readable; falling back to "
              "the canonical 76 CICFlowMeter feature names.")
    return Schema(list(N.CANONICAL_FEATURES), [],
                  "fallback: canonical 76 CICFlowMeter features", [])
