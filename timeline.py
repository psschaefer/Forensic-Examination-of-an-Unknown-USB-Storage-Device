#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Displays ESSIDs among the longest total visibility duration
"""

from pathlib import Path
import sys
import string
from datetime import timedelta

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.colors as mcolors

# Parameters
CSV_FILE  = Path("vol1-C..sha_1-01.kismet.csv")
OUT_PNG   = Path("wifi_timeline_fluid_top.png")
TOP_N     = 50     # Number of networks 
SNR_LIMIT = -60    # BestQuality threshold
SHOW_LABELS = True #



try:
    df = pd.read_csv(CSV_FILE, delimiter=";", encoding="utf-8", na_filter=False)
except UnicodeDecodeError:
    df = pd.read_csv(CSV_FILE, delimiter=";", encoding="latin1", na_filter=False)


df["FirstTime"]   = pd.to_datetime(df["FirstTime"], errors="coerce")
df["LastTime"]    = pd.to_datetime(df["LastTime"],  errors="coerce")
df["BestQuality"] = pd.to_numeric(df["BestQuality"], errors="coerce")


df = df.dropna(subset=["FirstTime", "LastTime", "BestQuality"])
df = df[df["BestQuality"] > SNR_LIMIT]
df["ESSID"] = df["ESSID"].astype(str)
df = df[df["ESSID"].str.strip() != ""]

if df.empty:
    sys.exit("No valid ESSID records found after filtering!")


durations = df.groupby("ESSID").apply(
    lambda g: (g["LastTime"] - g["FirstTime"]).dt.total_seconds().sum()
)

top_essids = set(durations.sort_values(ascending=False).head(TOP_N).index)
df_top = df[df["ESSID"].isin(top_essids)].copy()
first_seen = df_top.groupby("ESSID")["FirstTime"].min()
names_sorted = list(first_seen.sort_values().index) 
rows = len(names_sorted)

name_to_y = {name: idx for idx, name in enumerate(names_sorted)}

all_qualities = df_top["BestQuality"].tolist()
min_q = min(all_qualities)
max_q = max(all_qualities)
norm = mcolors.Normalize(vmin=min_q, vmax=max_q)
cmap = plt.cm.get_cmap("RdYlGn")


fig_height = 0.35 * rows + 2
fig, ax = plt.subplots(figsize=(12, fig_height))


for _, row in df_top.iterrows():
    essid = row["ESSID"]
    y = name_to_y[essid]
    start = row["FirstTime"]
    end = row["LastTime"]
    quality = row["BestQuality"]
    color = cmap(norm(quality))


    ax.hlines(y, start, end, colors="#000000", linewidth=6, linestyles="solid", alpha=0.8)
    ax.hlines(y, start, end, colors=color, linewidth=4, linestyles="solid")


allowed = string.printable + "ÄÖÜäöüß€°–—…“”‘’"
def clean_label(text: str) -> str:
    return "".join(ch for ch in text if ch in allowed)

ax.set_yticks(range(rows))

if SHOW_LABELS:
    ax.set_yticklabels([clean_label(n) for n in names_sorted], fontsize=6)
else:
    ax.set_yticklabels([])
    ax.tick_params(axis="y", length=0)


ax.set_xlabel("Time ")
ax.set_title(
    f"Timeline Top {TOP_N} Total Duration\n"
    f" BestQuality > {SNR_LIMIT} dBm"
)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.grid(axis="x", linestyle="--", alpha=0.3)


global_min = df_top["FirstTime"].min()
global_max = df_top["LastTime"].max()
ax.set_xlim(global_min, global_max)


sm = plt.cm.ScalarMappable(norm=norm, cmap=cmap)
sm.set_array([])
cbar = fig.colorbar(sm, ax=ax, orientation="vertical", pad=0.02)
cbar.set_label("BestQuality (dBm)", rotation=270, labelpad=15)

plt.tight_layout()
fig.savefig(OUT_PNG, dpi=150)
plt.show()

print("PNG saved to:", OUT_PNG.resolve())
