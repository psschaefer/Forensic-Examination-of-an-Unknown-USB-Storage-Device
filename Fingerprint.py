#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wi-Fi Fingerprinting & MAC Association 
- Fingerprint over stable IEs (45,127,221), but for 221 use only OUI + Subtype (4 bytes)
- Additional fingerprinting using Supported/Extended Rates (1,50)
- Grouping by IE hash
- Heuristic assignment random -> real
    * Time difference
    * RSSI difference
    * Channel consistency
    * Probe SSID match
    * IE stable hash match
    * IE rate hash match
- IE_Sequence: ID(bitlen) in bits
"""
import hashlib
from scapy.all import rdpcap, Dot11Elt, Dot11
from collections import defaultdict
import pandas as pd
import re
from manuf import manuf

# --- Parameters ---
PCAP_FILE  = "vol1-C..HeAt_2-01.cap"
CSV_FILE   = "vol1-C..HeAt_2-01.csv"
OUTPUT_CSV = "fingerprint_with_rate_and_ie_heuristics.csv"

# --- ID-Sets ---
STABLE_IDS = {45, 127, 221}   # HT Capabilities, Extended Caps, Vendor Specific
RATE_IDS   = {1, 50}           # Supported Rates, Extended Rates

parser = manuf.MacParser()

def hash_ies(ies, ids):
    """
    SHA256 nach relevanten IE im paper
    """
    raw = b""
    for i, info in sorted(ies):
        if i not in ids:
            continue

        if i == 221:
            raw += bytes([i])
            raw += info[:4]
        else:
            raw += bytes([i]) + info

    return hashlib.sha256(raw).hexdigest()

# CSV, global vs. random MACs 
real_macs = set()
with open(CSV_FILE, encoding="latin1") as f:

    for line in f:
        if line.startswith("Station MAC"):
            break
    for line in f:
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 1 or len(cols[0]) != 17:
            continue
        mac = cols[0].upper()
        fb  = int(mac.split(":")[0], 16)

        if not (fb & 0x02):
            real_macs.add(mac)

# metrics
fmap = defaultdict(lambda: {
    'ies': [],
    'rate_hashes': set(),
    'times': [],
    'powers': [],
    'channels': [],
    'ssids': set(),
    'reals': set(),
    'randoms': set(),
})

for pkt in rdpcap(PCAP_FILE):
    if not pkt.haslayer(Dot11) or pkt.type != 0 or pkt.subtype != 4:
        continue

    mac = (pkt.addr2 or "").upper()
    if not mac:
        continue

    ies = []
    ssid_tmp = None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        info = getattr(elt, "info", b"")
        ie_id = getattr(elt, "ID", None)

        if ie_id is not None:
            ies.append((ie_id, info or b""))


            if ie_id == 0 and info:
                try:
                    ssid_tmp = info.decode("utf-8", errors="ignore")
                except Exception:
                    ssid_tmp = None


        if hasattr(elt, "payload") and elt.payload:
            elt = elt.payload.getlayer(Dot11Elt)
        else:
            break

    if not ies:
        continue

    fp_stable = hash_ies(ies, STABLE_IDS)
    fp_rate   = hash_ies(ies, RATE_IDS)

    entry = fmap[fp_stable]

    if not entry['ies']:
        entry['ies'] = ies


    entry['rate_hashes'].add(fp_rate)


    entry['times'].append(pkt.time)
    if hasattr(pkt, 'dBm_AntSignal'):
        entry['powers'].append(pkt.dBm_AntSignal)
    if hasattr(pkt, 'Channel'):
        entry['channels'].append(pkt.Channel)

    if ssid_tmp:
        entry['ssids'].add(ssid_tmp)

    if mac in real_macs:
        entry['reals'].add(mac)
    else:
        entry['randoms'].add(mac)

# Heuristic assignment
assign = {}
for fp, data in fmap.items():
    assign[fp] = {'real': '', 'randoms': sorted(data['randoms'])}
    best = (None, 0)
    for rand in data['randoms']:
        for real in data['reals']:
            score = 0

            # Time difference
            if data['times']:
                dt = abs(max(data['times']) - min(data['times']))
                if dt < 60:
                    score += 5
                elif dt < 300:
                    score += 2

            # RSSI Difference
            if data['powers']:
                diff = abs(max(data['powers']) - min(data['powers']))
                if diff < 5:
                    score += 3
                elif diff < 15:
                    score += 1

            # Channel consistency
            if data['channels'] and len(set(data['channels'])) == 1:
                score += 2

            # Probe SSID match
            if data['ssids']:
                score += 10

            # IE stable hash match
            score += 3

            # IE rate hash match
            if len(data['rate_hashes']) == 1:
                score += 2

            if score > best[1]:
                best = (real, score)

    if best[0] and best[1] >= 5:
        assign[fp]['real'] = best[0]


rows = []
for fp, data in fmap.items():
    vendor = parser.get_manuf(assign[fp]['real']) if assign[fp]['real'] else ''
    ie_seq = []
    for i, info in data['ies']:
        if i in STABLE_IDS:
            ie_seq.append(f"{i}({len(info)*8}b)")
    rows.append({
        'Fingerprint':      fp,
        'Random_MACs':      ';'.join(sorted(data['randoms'])),
        'AssignedReal':     assign[fp]['real'],
        'Vendor':           vendor,
        'IE_Sequence':      ','.join(ie_seq),
        'Probed_SSIDs':     ';'.join(sorted(data['ssids']))
    })

df = pd.DataFrame(rows)
df.to_csv(OUTPUT_CSV, index=False, encoding='utf-8')
print(f"[+] Result in {OUTPUT_CSV}")

# Summary
total_fps = len(fmap)
total_random = sum(len(v['randoms']) for v in fmap.values())
total_real = sum(len(v['reals']) for v in fmap.values())
total_ssids = len(set().union(*[v['ssids'] for v in fmap.values()]))
total_packets = sum(len(v['times']) for v in fmap.values())
matched_fps = sum(1 for fp in fmap if assign[fp]['real'])

print("========== SUMMARY ==========")
print("Unique fingerprints:", total_fps)
print("random MACs:", total_random)
print("real MACs:", total_real)
print("probed SSIDs:", total_ssids)
print("processed probes:", total_packets)
print("Total processed packets (Probe Requests):", total_packets)
print("Fingerprints with a real target match:", matched_fps)
print("=============================")
