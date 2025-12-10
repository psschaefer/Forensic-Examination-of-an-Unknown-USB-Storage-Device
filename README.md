# Forensic Examination of an Unknown USB Storage Device

This repository contains the tools and scripts developed for the thesis Forensic Examination of an Unknown USB Storage Device.
It inludes:

- Forensic imaging of a USB mass storage device  
- FAT32 file system reconstruction  
- Cluster-level analysis 
- Recovery of deleted directory entries  
- Wireless capture forensics
- Fingerprinting of Wi-Fi device behavior  
- Timeline reconstruction  
- Cross-session correlation of wireless traces


## Components Overview

### Forensic Imaging 

`forensic_imaging.sh`

### FAT32 File System Analysis

- `fat_analyzis.sh`  
- `similarity_fat_check.sh`  
- `fat_del_scan.sh`  

### Wireless Forensic Analysis

- `wifi_forensics.py`  
- `Fingerprint.py`  
- `timeline.py`  
- `cross_session.py`

## Usage

```
sudo ./forensic_imaging.sh
./fat_analyzis.sh > fat_report.txt
./similarity_fat_check.sh
./fat_del_scan.sh

python3 wifi_forensics.py \
  --csv capture.csv \
  --pcap capture.cap \
  --logcsv capture.log.csv \
  --netxml capture.kismet.netxml

python3 Fingerprint.py
python3 timeline.py
python3 cross_session.py
```
