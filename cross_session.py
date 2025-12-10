#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from collections import defaultdict
import pandas as pd
import csv


SNR_LIMIT = -120
#files to compare ssids
CSV_FILES = [
    "vol1-C..sha_1-01.kismet.csv",
    "vol1-C..Eva_2-01.kismet.csv",
    "vol1-C..Eva_3-01.kismet.csv",
    "vol1-C..HeAt_1-01.kismet.csv",
    "vol1-C..HeAt_2-01.kismet.csv",
    "vol1-C..HeAt_3-01.kismet.csv",
    "vol1-C..SH_22-01.kismet.csv"
]

def extract_valid_essids(file_path):
    try:
        df = pd.read_csv(file_path, delimiter=";", encoding="utf-8", na_filter=False)
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, delimiter=";", encoding="latin1", na_filter=False)

    df["FirstTime"] = pd.to_datetime(df["FirstTime"], errors="coerce")
    df["LastTime"] = pd.to_datetime(df["LastTime"], errors="coerce")
    df["BestQuality"] = pd.to_numeric(df["BestQuality"], errors="coerce")
    df["ESSID"] = df["ESSID"].astype(str)

    df = df.dropna(subset=["FirstTime", "LastTime", "BestQuality"])
    df = df[df["BestQuality"] > SNR_LIMIT]
    df = df[df["ESSID"].str.strip() != ""]

    return set(df["ESSID"].unique())


essid_sessions = defaultdict(set)

for file in CSV_FILES:
    session = Path(file).stem
    essids = extract_valid_essids(file)
    for essid in essids:
        essid_sessions[essid].add(session)


common_essids = {
    essid: sess for essid, sess in essid_sessions.items() if len(sess) >= 2
}

sorted_common_essids = sorted(
    common_essids.items(), key=lambda x: len(x[1]), reverse=True
)


output_path = "common_essids.csv"
with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["ESSID", "Sessions", "Count"])
    for essid, sessions in sorted_common_essids:
        writer.writerow([essid, ", ".join(sorted(sessions)), len(sessions)])

print(f"saved in {output_path}")
