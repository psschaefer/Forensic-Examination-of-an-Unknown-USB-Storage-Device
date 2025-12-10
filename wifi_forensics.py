#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
INPUT  ( any subset)
  --csv     airodump-ng-XX.csv          AP, Station table
  --netxml  kismet.netxml               vendor,channel info
  --logcsv  kismet.log.csv              frame timeline
  --pcap    capture.cap / .pcap         raw packets, handshake count

OUTPUT
  access_points.csv           AP list
  stations.csv                Station list
  client_ap_mapping.csv       Station  AP/ESSID
  ap_clients.csv              AP list of Stations
  station_probes.csv          Station probed ESSIDs
  report.md                   findings
  ap_signal_hist.png          RSSI histogram (all APs)
  channel_distribution.png    bar chart, AP count per channel
  encryption_distribution.png bar chart, split encryption types
  beacon_rate.png             beacon frames per minute       
  station_rssi.png            RSSI vs time for top talkers   
  stations_ch_*.csv           Station lists per channel
  stations_*.csv              Station lists per encryption type

"""

from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

# optional libs
try:
    from lxml import etree as LET
    LXML_OK = True
except ImportError:
    LXML_OK = False

try:
    from scapy.all import PcapReader, Dot11, EAPOL
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(x, **k): return x


def split_airodump_csv(path: Path):
    """Return AP-DF, Station-DF from CSV."""
    raw = path.read_text(encoding="latin1", errors="ignore")
    ap_block, st_block = raw.split("\n\n", 1)
    ap_lines = [ln.strip() for ln in ap_block.splitlines() if ln.strip()]
    header = [h.strip() for h in ap_lines[0].split(",")]
    ap_df = pd.DataFrame(
        [ln.split(",", len(header)-1)[:len(header)] for ln in ap_lines[1:]],
        columns=header
    ).rename(columns=str.lower)
    st_lines = [ln.strip() for ln in st_block.splitlines() if ln.strip()]
    st_hdr = ["station mac","first time seen","last time seen",
              "power","# packets","bssid","probed essids"]
    st_df = pd.DataFrame(
        [ln.split(",", 6) for ln in st_lines[1:] if ln.count(",") >= 6],
        columns=st_hdr
    ).rename(columns=str.lower)
    return ap_df, st_df


def parse_netxml(path: Path):
    """Return maps: BSSID to vendor / channel / encryption"""
    if not LXML_OK:
        print("lxml not installed, skipping NetXML")
        return {}, {}, {}
    root = LET.parse(str(path), LET.XMLParser(recover=True, encoding="utf-8")).getroot()
    vendor, channel, enc = {}, {}, {}
    for net in root.xpath("//wireless-network"):
        b = (net.findtext("BSSID") or "").upper()
        if not b:
            continue
        if (m := net.findtext("manuf")): vendor[b] = m.strip()
        if (c := net.findtext("channel")): channel[b] = c.strip()
        encs = [e.text for e in net.findall("encryption")]
        if encs: enc[b] = ",".join(sorted(set(encs)))
    return vendor, channel, enc


def count_handshakes(pcap: Path):
    """Return (AP, STA): count of EAPOL frames"""
    if not SCAPY_OK:
        print("scapy not installed, skipping handshake scan")
        return {}
    ctr = Counter()
    with PcapReader(str(pcap)) as cap:
        for pkt in tqdm(cap, desc="Scanning pcap for EAPOL"):
            if pkt.haslayer(Dot11) and pkt.haslayer(EAPOL):
                d = pkt[Dot11]
                addr = (d.addr1, d.addr2, d.addr3)
                ds = d.FCfield & 3
                if ds == 0:
                    ap, sta = addr[1], addr[0]
                elif ds == 1:
                    ap, sta = addr[2], addr[1]
                elif ds == 2:
                    ap, sta = addr[0], addr[2]
                else:
                    ap, sta = (None, None)
                if ap and sta:
                    ctr[(ap.upper(), sta.upper())] += 1
    return ctr


def plot_beacon_rate(log_csv: Path, out: Path):
    log = pd.read_csv(log_csv, sep=";", encoding="latin1", on_bad_lines="skip")
    if "Type" not in log.columns:
        return
    bea = log[log["Type"] == "Beacon"]
    if bea.empty:
        return
    bea["ts"] = pd.to_datetime(bea["Timestamp"], unit="s")
    bea.set_index("ts").resample("1T").size().plot(figsize=(7,3))
    plt.xlabel("Time"); plt.ylabel("Beacons/minute")
    plt.title("Beacon traffic over time")
    plt.tight_layout(); plt.savefig(out, dpi=150); plt.close()


def plot_station_rssi(log_csv: Path, stations: pd.DataFrame, out: Path):
    log = pd.read_csv(log_csv, sep=";", encoding="latin1", on_bad_lines="skip")
    if "Signal" not in log.columns:
        return
    stations["# packets"] = pd.to_numeric(stations["# packets"], errors="coerce").fillna(0).astype(int)
    top = stations.nlargest(10, "# packets")
    plt.figure(figsize=(8,4))
    for mac in top["station mac"]:
        seg = log[log["MAC"].str.lower() == mac.lower()]
        if seg.empty:
            continue
        seg["ts"] = pd.to_datetime(seg["Timestamp"], unit="s")
        plt.plot(seg["ts"], seg["Signal"], label=mask_mac(mac))
    if plt.gca().lines:
        plt.legend(fontsize=6, title="Station")
        plt.xlabel("Time"); plt.ylabel("Signal (dBm)")
        plt.title("RSSI over time – top talkers")
        plt.tight_layout(); plt.savefig(out, dpi=150)
    plt.close()


def mask_mac(mac: str) -> str:
    """anonymize mac addresses """
    mac = mac.upper()
    parts = mac.split(":")
    return ":".join(parts[:4]) + ":****" if len(parts) == 6 else mac


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv",     required=True, type=Path)
    p.add_argument("--netxml",  type=Path)
    p.add_argument("--logcsv",  type=Path)
    p.add_argument("--pcap",    type=Path)
    args = p.parse_args()
    OUT = Path.cwd()


    aps, stn = split_airodump_csv(args.csv)
    aps.to_csv(OUT / "access_points.csv", index=False)
    stn.to_csv(OUT / "stations.csv",      index=False)

 
    mapping = stn[stn["bssid"] != "(not associated)"].copy()
    mapping["associated essid"] = mapping["bssid"].map(
        aps.set_index("bssid")["essid"].to_dict())
    mapping.to_csv(OUT / "client_ap_mapping.csv", index=False)
    mapping.groupby("bssid")["station mac"].apply(list).reset_index().to_csv(
        OUT / "ap_clients.csv", index=False)

    probes = stn[stn["probed essids"].str.strip() != ""].copy()
    probes["probe list"] = probes["probed essids"].str.split(",")
    probes[["station mac", "probe list"]].to_csv(
        OUT / "station_probes.csv", index=False)


    if args.netxml and args.netxml.exists():
        try:
            v, ch, en = parse_netxml(args.netxml)
            aps["vendor"] = aps["bssid"].str.upper().map(v)
            aps["channel_xml"] = aps["bssid"].str.upper().map(ch)
            aps["encryption_xml"] = aps["bssid"].str.upper().map(en)
            aps.to_csv(OUT / "access_points.csv", index=False)
        except Exception as e:
            print(f"Fehler beim Parsen von NetXML: {e}")


    handshake = {}
    if args.pcap and args.pcap.exists():
        for (ap, sta), n in count_handshakes(args.pcap).items():
            handshake.setdefault(ap, []).append((sta, n))


    rpt = [f"# Report on {datetime.now():%Y-%m-%d %H:%M}",
           f"Total APs: {len(aps)}  Total Stations: **{len(stn)}**"]

    if handshake:
        rpt.append(f"## WPA Handshake Summary: {len(handshake)} APs with EAPOL frames")
        essid_map = aps.drop_duplicates('bssid').set_index('bssid')['essid']
        for ap_bssid, lst in handshake.items():
            essid = essid_map.get(ap_bssid, '<Unknown>')
            rpt.append(f"- AP {essid} ({ap_bssid}):")
            for sta, count in lst:
                if count >= 4:
                    status = 'full'
                elif count >= 2:
                    status = 'partial'
                else:
                    status = 'incomplete'
                rpt.append(
                    f"    - Station {mask_mac(sta)}: {count} EAPOL frames ({status} handshake)"
                )
    else:
        rpt.append("## WPA Handshake Summary – No EAPOL frames detected")


    dup = aps['essid'].value_counts()
    multi = dup[dup > 1]
    if not multi.empty:
        rpt.append("## Duplicate ESSIDs (>1 BSSID)")
        for essid, n in multi.items():
            rpt.append(f"- {essid or '<Hidden>'}: {n} BSSIDs")


    open_mask = aps.get('privacy','').str.upper() == 'OPN'
    if open_mask.any():
        rpt.append(f"## Open Networks – {open_mask.sum()} APs")
        for _, r in aps[open_mask].sort_values('essid').iterrows():
            ch = r.get('channel') or r.get('channel_xml') or '?'
            rpt.append(f"- {r['essid'] or '<Hidden>'} ({r['bssid']}), Ch {ch}")


    (OUT / "report.md").write_text("\n".join(rpt), encoding="utf-8")
    print("finished report.md")


    aps['power'] = pd.to_numeric(aps.get('power', pd.NA), errors='coerce')
    aps['power'].hist(bins=40, figsize=(6,4))
    plt.xlabel("Signal (dBm)")
    plt.ylabel("Count")
    plt.title("AP RSSI distribution")
    plt.tight_layout(); plt.savefig(OUT / "ap_signal_hist.png", dpi=150); plt.close()

    aps['channel'] = pd.to_numeric(aps.get('channel', pd.NA), errors='coerce')
    ch_dist = aps['channel'].value_counts().sort_index()
    plt.figure(figsize=(7,4)); ch_dist.plot.bar()
    plt.xlabel("Channel"); plt.ylabel("Number of APs")
    plt.title("Channel distribution of APs")
    plt.tight_layout(); plt.savefig(OUT / "channel_distribution.png", dpi=150); plt.close()

    enc_series = aps.get('privacy','').str.upper().str.split(',', expand=True).stack().reset_index(drop=True)
    enc_counts = enc_series.value_counts()
    plt.figure(figsize=(7,4)); enc_counts.plot.bar()
    plt.xlabel("Encryption Type"); plt.ylabel("Number of APs")
    plt.title("Encryption modes in capture (split types)")
    plt.tight_layout(); plt.savefig(OUT / "encryption_distribution.png", dpi=150); plt.close()

    channel_map = aps.drop_duplicates('bssid').set_index('bssid')['channel']
    station_mapping = mapping.copy()
    station_mapping['channel'] = station_mapping['bssid'].map(channel_map)
    for ch, grp in station_mapping.groupby('channel'):
        safe_ch = f"ch_{int(ch)}" if pd.notna(ch) else "ch_unknown"
        grp.to_csv(OUT / f"stations_{safe_ch}.csv", index=False)

    privacy_map = aps.drop_duplicates('bssid').set_index('bssid')['privacy']
    station_enc = station_mapping.copy()
    station_enc['privacy_types'] = station_enc['bssid'].map(privacy_map)
    station_enc = station_enc.assign(
        privacy_types=station_enc['privacy_types'].str.upper().str.split(',')
    ).explode('privacy_types')
    for etype, grp in station_enc.groupby('privacy_types'):
        safe_et = etype.lower().replace('/', '_')
        grp.to_csv(OUT / f"stations_{safe_et}.csv", index=False)

    if args.logcsv and args.logcsv.exists():
        plot_beacon_rate(args.logcsv, OUT / 'beacon_rate.png')
        plot_station_rssi(args.logcsv, stn, OUT / 'station_rssi.png')

    print("finished", OUT.resolve())

if __name__ == '__main__':
    main()
