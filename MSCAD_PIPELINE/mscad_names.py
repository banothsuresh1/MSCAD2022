"""
Mapping between the internal (pip-cicflowmeter 0.5.0) feature keys and the
display names used in the MSCAD / CIC CSV family.

The pipeline never hard-codes "the 66 MSCAD columns".  It reads the real
header out of the original Kaggle CSV and resolves each name through
NAME_TO_KEY below, so whichever 66 of the 76 CICFlowMeter features MSCAD
happens to carry, and in whatever order, the output matches it exactly.
Any header name that cannot be resolved is reported, never guessed.

Both naming families are accepted:
  * CICFlowMeter V4 / CSE-CIC-IDS2018 style  ("Tot Fwd Pkts", "Flow Byts/s")
  * CICFlowMeter V3 / CIC-IDS2017 style      ("Total Fwd Packets", "Flow Bytes/s")
"""

import re

# --------------------------------------------------------------------------
# The 76 CICFlowMeter features, in canonical CSE-CIC-IDS2018 column order.
# (display name, internal key)
# --------------------------------------------------------------------------
CANONICAL_FEATURES = [
    ("Flow Duration",        "flow_duration"),
    ("Tot Fwd Pkts",         "tot_fwd_pkts"),
    ("Tot Bwd Pkts",         "tot_bwd_pkts"),
    ("TotLen Fwd Pkts",      "totlen_fwd_pkts"),
    ("TotLen Bwd Pkts",      "totlen_bwd_pkts"),
    ("Fwd Pkt Len Max",      "fwd_pkt_len_max"),
    ("Fwd Pkt Len Min",      "fwd_pkt_len_min"),
    ("Fwd Pkt Len Mean",     "fwd_pkt_len_mean"),
    ("Fwd Pkt Len Std",      "fwd_pkt_len_std"),
    ("Bwd Pkt Len Max",      "bwd_pkt_len_max"),
    ("Bwd Pkt Len Min",      "bwd_pkt_len_min"),
    ("Bwd Pkt Len Mean",     "bwd_pkt_len_mean"),
    ("Bwd Pkt Len Std",      "bwd_pkt_len_std"),
    ("Flow Byts/s",          "flow_byts_s"),
    ("Flow Pkts/s",          "flow_pkts_s"),
    ("Flow IAT Mean",        "flow_iat_mean"),
    ("Flow IAT Std",         "flow_iat_std"),
    ("Flow IAT Max",         "flow_iat_max"),
    ("Flow IAT Min",         "flow_iat_min"),
    ("Fwd IAT Tot",          "fwd_iat_tot"),
    ("Fwd IAT Mean",         "fwd_iat_mean"),
    ("Fwd IAT Std",          "fwd_iat_std"),
    ("Fwd IAT Max",          "fwd_iat_max"),
    ("Fwd IAT Min",          "fwd_iat_min"),
    ("Bwd IAT Tot",          "bwd_iat_tot"),
    ("Bwd IAT Mean",         "bwd_iat_mean"),
    ("Bwd IAT Std",          "bwd_iat_std"),
    ("Bwd IAT Max",          "bwd_iat_max"),
    ("Bwd IAT Min",          "bwd_iat_min"),
    ("Fwd PSH Flags",        "fwd_psh_flags"),
    ("Bwd PSH Flags",        "bwd_psh_flags"),
    ("Fwd URG Flags",        "fwd_urg_flags"),
    ("Bwd URG Flags",        "bwd_urg_flags"),
    ("Fwd Header Len",       "fwd_header_len"),
    ("Bwd Header Len",       "bwd_header_len"),
    ("Fwd Pkts/s",           "fwd_pkts_s"),
    ("Bwd Pkts/s",           "bwd_pkts_s"),
    ("Pkt Len Min",          "pkt_len_min"),
    ("Pkt Len Max",          "pkt_len_max"),
    ("Pkt Len Mean",         "pkt_len_mean"),
    ("Pkt Len Std",          "pkt_len_std"),
    ("Pkt Len Var",          "pkt_len_var"),
    ("FIN Flag Cnt",         "fin_flag_cnt"),
    ("SYN Flag Cnt",         "syn_flag_cnt"),
    ("RST Flag Cnt",         "rst_flag_cnt"),
    ("PSH Flag Cnt",         "psh_flag_cnt"),
    ("ACK Flag Cnt",         "ack_flag_cnt"),
    ("URG Flag Cnt",         "urg_flag_cnt"),
    ("CWE Flag Count",       "cwr_flag_count"),
    ("ECE Flag Cnt",         "ece_flag_cnt"),
    ("Down/Up Ratio",        "down_up_ratio"),
    ("Pkt Size Avg",         "pkt_size_avg"),
    ("Fwd Seg Size Avg",     "fwd_seg_size_avg"),
    ("Bwd Seg Size Avg",     "bwd_seg_size_avg"),
    ("Fwd Byts/b Avg",       "fwd_byts_b_avg"),
    ("Fwd Pkts/b Avg",       "fwd_pkts_b_avg"),
    ("Fwd Blk Rate Avg",     "fwd_blk_rate_avg"),
    ("Bwd Byts/b Avg",       "bwd_byts_b_avg"),
    ("Bwd Pkts/b Avg",       "bwd_pkts_b_avg"),
    ("Bwd Blk Rate Avg",     "bwd_blk_rate_avg"),
    ("Subflow Fwd Pkts",     "subflow_fwd_pkts"),
    ("Subflow Fwd Byts",     "subflow_fwd_byts"),
    ("Subflow Bwd Pkts",     "subflow_bwd_pkts"),
    ("Subflow Bwd Byts",     "subflow_bwd_byts"),
    ("Init Fwd Win Byts",    "init_fwd_win_byts"),
    ("Init Bwd Win Byts",    "init_bwd_win_byts"),
    ("Fwd Act Data Pkts",    "fwd_act_data_pkts"),
    ("Fwd Seg Size Min",     "fwd_seg_size_min"),
    ("Active Mean",          "active_mean"),
    ("Active Std",           "active_std"),
    ("Active Max",           "active_max"),
    ("Active Min",           "active_min"),
    ("Idle Mean",            "idle_mean"),
    ("Idle Std",             "idle_std"),
    ("Idle Max",             "idle_max"),
    ("Idle Min",             "idle_min"),
]

CANONICAL_DISPLAY = [d for d, _k in CANONICAL_FEATURES]
CANONICAL_KEYS = [k for _d, k in CANONICAL_FEATURES]

# --------------------------------------------------------------------------
# Alternate spellings (CICFlowMeter V3 / CIC-IDS2017 and common variants).
# --------------------------------------------------------------------------
ALIASES = {
    "flow_duration":      ["Flow Duration"],
    "tot_fwd_pkts":       ["Total Fwd Packets", "Total Fwd Pkts", "Tot Fwd Pkt"],
    "tot_bwd_pkts":       ["Total Backward Packets", "Total Bwd Packets", "Tot Bwd Pkt"],
    "totlen_fwd_pkts":    ["Total Length of Fwd Packets", "TotLen Fwd Pkt",
                           "Total Length of Fwd Packet"],
    "totlen_bwd_pkts":    ["Total Length of Bwd Packets", "TotLen Bwd Pkt",
                           "Total Length of Bwd Packet"],
    "fwd_pkt_len_max":    ["Fwd Packet Length Max"],
    "fwd_pkt_len_min":    ["Fwd Packet Length Min"],
    "fwd_pkt_len_mean":   ["Fwd Packet Length Mean"],
    "fwd_pkt_len_std":    ["Fwd Packet Length Std"],
    "bwd_pkt_len_max":    ["Bwd Packet Length Max"],
    "bwd_pkt_len_min":    ["Bwd Packet Length Min"],
    "bwd_pkt_len_mean":   ["Bwd Packet Length Mean"],
    "bwd_pkt_len_std":    ["Bwd Packet Length Std"],
    "flow_byts_s":        ["Flow Bytes/s", "Flow Byts/sec"],
    "flow_pkts_s":        ["Flow Packets/s", "Flow Pkts/sec"],
    "flow_iat_mean":      ["Flow IAT Mean"],
    "flow_iat_std":       ["Flow IAT Std"],
    "flow_iat_max":       ["Flow IAT Max"],
    "flow_iat_min":       ["Flow IAT Min"],
    "fwd_iat_tot":        ["Fwd IAT Total"],
    "bwd_iat_tot":        ["Bwd IAT Total"],
    "fwd_header_len":     ["Fwd Header Length"],
    "bwd_header_len":     ["Bwd Header Length"],
    "fwd_pkts_s":         ["Fwd Packets/s"],
    "bwd_pkts_s":         ["Bwd Packets/s"],
    "pkt_len_min":        ["Min Packet Length", "Packet Length Min"],
    "pkt_len_max":        ["Max Packet Length", "Packet Length Max"],
    "pkt_len_mean":       ["Packet Length Mean"],
    "pkt_len_std":        ["Packet Length Std"],
    "pkt_len_var":        ["Packet Length Variance", "Pkt Len Variance"],
    "fin_flag_cnt":       ["FIN Flag Count"],
    "syn_flag_cnt":       ["SYN Flag Count"],
    "rst_flag_cnt":       ["RST Flag Count"],
    "psh_flag_cnt":       ["PSH Flag Count"],
    "ack_flag_cnt":       ["ACK Flag Count"],
    "urg_flag_cnt":       ["URG Flag Count"],
    "cwr_flag_count":     ["CWE Flag Cnt", "CWR Flag Count", "CWR Flag Cnt",
                           "CWE Flag Count Count"],
    "ece_flag_cnt":       ["ECE Flag Count"],
    "pkt_size_avg":       ["Average Packet Size", "Avg Packet Size"],
    "fwd_seg_size_avg":   ["Avg Fwd Segment Size", "Fwd Segment Size Avg"],
    "bwd_seg_size_avg":   ["Avg Bwd Segment Size", "Bwd Segment Size Avg"],
    "fwd_byts_b_avg":     ["Fwd Avg Bytes/Bulk", "Fwd Bytes/Bulk Avg"],
    "fwd_pkts_b_avg":     ["Fwd Avg Packets/Bulk", "Fwd Packets/Bulk Avg"],
    "fwd_blk_rate_avg":   ["Fwd Avg Bulk Rate", "Fwd Bulk Rate Avg"],
    "bwd_byts_b_avg":     ["Bwd Avg Bytes/Bulk", "Bwd Bytes/Bulk Avg"],
    "bwd_pkts_b_avg":     ["Bwd Avg Packets/Bulk", "Bwd Packets/Bulk Avg"],
    "bwd_blk_rate_avg":   ["Bwd Avg Bulk Rate", "Bwd Bulk Rate Avg"],
    "subflow_fwd_pkts":   ["Subflow Fwd Packets"],
    "subflow_fwd_byts":   ["Subflow Fwd Bytes"],
    "subflow_bwd_pkts":   ["Subflow Bwd Packets"],
    "subflow_bwd_byts":   ["Subflow Bwd Bytes"],
    "init_fwd_win_byts":  ["Init_Win_bytes_forward", "Init Win bytes forward",
                           "Init Fwd Win Bytes"],
    "init_bwd_win_byts":  ["Init_Win_bytes_backward", "Init Win bytes backward",
                           "Init Bwd Win Bytes"],
    "fwd_act_data_pkts":  ["act_data_pkt_fwd", "Fwd Act Data Packets",
                           "Act Data Pkt Fwd"],
    "fwd_seg_size_min":   ["min_seg_size_forward", "Min Seg Size Forward",
                           "Fwd Seg Size Minimum"],
    "active_mean":        ["Active Mean"],
    "active_std":         ["Active Std"],
    "active_max":         ["Active Max"],
    "active_min":         ["Active Min"],
    "idle_mean":          ["Idle Mean"],
    "idle_std":           ["Idle Std"],
    "idle_max":           ["Idle Max"],
    "idle_min":           ["Idle Min"],
}

# Identifier / label columns that are not features.
IDENTIFIER_ALIASES = {
    "src_ip":    ["Src IP", "Source IP", "Src_IP"],
    "dst_ip":    ["Dst IP", "Destination IP", "Dst_IP"],
    "src_port":  ["Src Port", "Source Port", "Src_Port"],
    "dst_port":  ["Dst Port", "Destination Port", "Dst_Port"],
    "protocol":  ["Protocol"],
    "timestamp": ["Timestamp"],
    "flow_id":   ["Flow ID", "FlowID"],
    "label":     ["Label", "Labels", " Label"],
}


def normalise(name):
    """Canonical form for header matching: lowercase, alphanumerics only.

    Strips surrounding whitespace and quotes first, so ' "Flow Byts/s" '
    and 'Flow Byts/s' and 'flow_byts_s' all collapse together.
    """
    s = str(name).strip().strip('"').strip("'").strip()
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _build_lookup():
    table = {}
    for display, key in CANONICAL_FEATURES:
        table[normalise(display)] = key
        table[normalise(key)] = key
    for key, alts in ALIASES.items():
        for alt in alts:
            table[normalise(alt)] = key
    for key, alts in IDENTIFIER_ALIASES.items():
        for alt in alts:
            table[normalise(alt)] = key
        table[normalise(key)] = key
    return table


NAME_TO_KEY = _build_lookup()

NON_FEATURE_KEYS = set(IDENTIFIER_ALIASES.keys())


def resolve_header(header):
    """Split an original CSV header into feature / identifier / unknown.

    Returns (feature_pairs, identifier_pairs, unknown_names) where
    feature_pairs is [(original_name, internal_key), ...] in the order the
    original file has them.
    """
    features, identifiers, unknown = [], [], []
    for raw in header:
        key = NAME_TO_KEY.get(normalise(raw))
        if key is None:
            unknown.append(raw)
        elif key in NON_FEATURE_KEYS:
            identifiers.append((raw, key))
        else:
            features.append((raw, key))
    return features, identifiers, unknown


# Features whose CICFlowMeter definition is integer-valued.  Used for the
# Part 3 row-matching key and for compact CSV formatting.
INTEGER_KEYS = {
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "pkt_len_max", "pkt_len_min",
    "fwd_header_len", "bwd_header_len", "fwd_seg_size_min",
    "fwd_act_data_pkts", "flow_iat_max", "flow_iat_min", "fwd_iat_tot",
    "fwd_iat_max", "fwd_iat_min", "bwd_iat_tot", "bwd_iat_max",
    "bwd_iat_min", "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags",
    "bwd_urg_flags", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
    "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt",
    "cwr_flag_count", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_max", "active_min", "idle_max", "idle_min",
    "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts", "down_up_ratio",
}
