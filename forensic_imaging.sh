#!/bin/bash

# === Forensic Imaging Tool ===

# Required tools:
REQUIRED_CMDS=("zenity" "lsblk" "grep" "awk" "blockdev" "hdparm" "pv" "dd" "losetup" "udevadm" "fdisk" "blkid" "numfmt" "lsusb" "file" "fsck" "smartctl" "hexdump")

MISSING_CMDS=()

for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_CMDS+=("$cmd")
    fi
done

if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then
    MISSING_LIST=$(printf "%s\n" "${MISSING_CMDS[@]}")
    if zenity --question --width=400 --title="Missing Packages" --text="The following programs are missing:\n\n$MISSING_LIST\n\nWould you like to install them automatically now?\nNote: Program must be run with sudo." 2>/dev/null; then
        sudo apt update
        for pkg in "${MISSING_CMDS[@]}"; do
            sudo apt install -y "$pkg"
            if ! command -v "$pkg" &>/dev/null; then
                zenity --error --width=400 --title="Error" --text="Error installing '$pkg'.\nAborting." 2>/dev/null
                echo "[!] Installation of $pkg failed. Operation aborted." >&2
                exit 1
            fi
        done
        echo "[+] All missing programs were installed successfully."
    else
        zenity --error --width=400 --title="Cancelled" --text="Installation declined. Operation aborted." 2>/dev/null
        echo "[!] Installation declined. Operation aborted."
        exit 1
    fi
fi

if ! command -v dc3dd &>/dev/null && ! command -v dcfldd &>/dev/null; then
    zenity --warning --width=400 --title="Notice" --text="Neither 'dc3dd' nor 'dcfldd' are installed.\nOnly 'dd' is available as imaging tool!" 2>/dev/null
    echo "[!] Only 'dd' available, no alternative imaging tools."
fi

zenity --info --title="Forensic Imaging Tool" --width=400 --text="This tool creates a forensic image file from a USB storage device.\n\nClick 'OK' and then select the destination folder for the image and log file." 2>/dev/null

# Automount check (Kali)
DESKTOP_ENVIRONMENT=$(echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]')
AUTOMOUNT_STATUS="unknown"

case "$DESKTOP_ENVIRONMENT" in
  kde)
    USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6 2>/dev/null || echo "$HOME")
    AUTOMOUNT_STATUS=$(grep -i '\[Module-device_automounter\]' -A1 "$USER_HOME/.config/kded5rc" 2>/dev/null | grep -i 'autoload=' | awk -F'=' '{print tolower($2)}' | tr -d ' ')
    ;;
  xfce)
    AUTOMOUNT_STATUS=$(xfconf-query -c thunar-volman -p /Automount-Drives | tr '[:upper:]' '[:lower:]' 2>/dev/null)
    ;;
  gnome)
    AUTOMOUNT_STATUS=$(gsettings get org.gnome.desktop.media-handling automount | tr '[:upper:]' '[:lower:]' 2>/dev/null)
    ;;
esac

if [[ "$AUTOMOUNT_STATUS" == "true" ]]; then
  zenity --error --text="Automount is ACTIVE! Please disable it first." 2>/dev/null
  echo "[!] Automount is active. Operation aborted." 
  exit 1
elif [[ "$AUTOMOUNT_STATUS" == "false" ]]; then
  echo "[+] Automount is disabled. Safe operation possible." 
else
  if zenity --question --width=400 --title="Automount Status Unknown" --text="Automount status could not be determined.\n\nContinue anyway?\n\n(Warning: Check manually!)" 2>/dev/null; then
    echo "[!] Automount status unknown. User chose to continue." 
  else
    echo "[!] Automount status unknown. User aborted." 
    exit 1
  fi
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR=$(zenity --file-selection --directory --title="Select destination folder for image and log" 2>/dev/null) || exit 1
LOGFILE="$OUTPUT_DIR/forensic_log_$TIMESTAMP.txt"
IMAGENAME="$OUTPUT_DIR/usb_image_$TIMESTAMP.dd"

# Cleanup function (loopback)
cleanup() {
    EXIT_STATUS=$?
    echo ""

    if [[ $EXIT_STATUS -ne 0 ]]; then
        echo "[!] Operation manually aborted or unexpectedly terminated!" | tee -a "$LOGFILE"
        if losetup /dev/loop0 &>/dev/null; then
            echo "[+] Loopback /dev/loop0 detected, removing..." | tee -a "$LOGFILE"
            sudo losetup -d /dev/loop0
            echo "[+] Loopback /dev/loop0 successfully removed." | tee -a "$LOGFILE"
        else
            echo "[!] No active loopback /dev/loop0 found or already removed." | tee -a "$LOGFILE"
        fi

        echo "[!] Imaging ended incompletely." | tee -a "$LOGFILE"
    else
        if losetup /dev/loop0 &>/dev/null; then
            echo "[+] Cleanup: Removing loopback /dev/loop0..." | tee -a "$LOGFILE"
            sudo losetup -d /dev/loop0
            echo "[+] Loopback /dev/loop0 successfully removed." | tee -a "$LOGFILE"
        fi
    fi

    exit $EXIT_STATUS
}
trap cleanup EXIT

# Device detection
zenity --info --title="Unplug USB Device" --text="Please unplug the USB device to be imaged, then click 'Next'." --ok-label="Next" 2>/dev/null
BEFORE=$(lsblk -dpn -o NAME)

zenity --info --title="Plug in USB Device" --text="Now plug in the USB device and click 'Next'." --ok-label="Next" 2>/dev/null
AFTER=$(lsblk -dpn -o NAME)

NEW_DEVICES=$(comm -13 <(echo "$BEFORE" | sort) <(echo "$AFTER" | sort))

if [[ -z "$NEW_DEVICES" ]]; then
  zenity --question --title="No New Device" --text="No new device detected.\n\nDo you want to select an already connected device?" --ok-label="Select device" --cancel-label="Cancel" 2>/dev/null
  
  if [[ $? -eq 0 ]]; then
    ALL_DEVICES=$(lsblk -dpn -o NAME)
    DEV=$(printf "%s\n" "$ALL_DEVICES" | zenity --list --title="Select Existing Device" --column="Device" --height=300 --width=400 2>/dev/null)
  else
    echo "[-] No new device detected, manual abort." | tee -a "$LOGFILE"
    exit 1
  fi
else
  DEV=$(printf "%s\n" "$NEW_DEVICES" | zenity --list --title="Select New Device" --column="Device" --height=300 --width=400 2>/dev/null)
fi

[[ -z "$DEV" ]] && zenity --error --text="No device selected." 2>/dev/null && echo "[-] No device chosen." | tee -a "$LOGFILE" && exit 1

DEVICE="$DEV"
echo "[+] Selected device: $DEVICE" | tee -a "$LOGFILE"


sudo blockdev --setro "$DEVICE"
if [[ "$(sudo blockdev --getro "$DEVICE")" != "1" ]]; then
  zenity --error --text="blockdev write-protection could NOT be activated! Aborting." 2>/dev/null
  echo "[-] Write-protection NOT active. Aborting." | tee -a "$LOGFILE"
  exit 1
fi


# Manufacturer information
USB_SYS_PATH=$(udevadm info -q path -n "$DEVICE" | grep '/usb' | head -n1)

VID=$(udevadm info -a -p "/sys$USB_SYS_PATH" 2>/dev/null | grep "idVendor" | head -1 | awk -F'==' '{print $2}' | tr -d ' "')
PID=$(udevadm info -a -p "/sys$USB_SYS_PATH" 2>/dev/null | grep "idProduct" | head -1 | awk -F'==' '{print $2}' | tr -d ' "')
MANUFACTURER=$(udevadm info -a -p "/sys$USB_SYS_PATH" 2>/dev/null | grep "iManufacturer" | head -1 | awk -F'==' '{print $2}' | tr -d ' "')
PRODUCT=$(udevadm info -a -p "/sys$USB_SYS_PATH" 2>/dev/null | grep "iProduct" | head -1 | awk -F'==' '{print $2}' | tr -d ' "')
SERIAL=$(udevadm info -a -p "/sys$USB_SYS_PATH" 2>/dev/null | grep "iSerial" | head -1 | awk -F'==' '{print $2}' | tr -d ' "')

[[ -z "$VID" ]] && VID="Not found"
[[ -z "$PID" ]] && PID="Not found"
[[ -z "$MANUFACTURER" ]] && MANUFACTURER="Not specified"
[[ -z "$PRODUCT" ]] && PRODUCT="Not specified"
[[ -z "$SERIAL" ]] && SERIAL="Not available"

zenity --info --width=400 --title="Device Information" --text="Detected device: $DEVICE\n\nVendor ID: $VID\nProduct ID: $PID\nManufacturer: $MANUFACTURER\nProduct: $PRODUCT\nSerial number: $SERIAL" 2>/dev/null

{
  echo "===== USB Basic Information ====="
  echo "Device:          $DEVICE"
  echo "USB Vendor ID:   $VID"
  echo "USB Product ID:  $PID"
  echo "Manufacturer:    $MANUFACTURER"
  echo "Product:         $PRODUCT"
  echo "Serial number:   $SERIAL"
  echo

  echo "===== Advanced USB Information ====="
  echo "[+] Output of lsusb -v -d:"
  sudo lsusb -v -d ${VID}:${PID} 2>/dev/null || echo "[!] No detailed USB info found."
  echo
  echo "[+] Output of usb-devices:"
  usb-devices | awk -v vid="$VID" -v pid="$PID" '
    BEGIN { RS="\n\n"; FS="\n" }
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ "Vendor="vid && $i ~ "ProdID="pid) {
          print $0
          next
        }
      }
    }
  ' || echo "[!] No matching information found."
  echo
  echo "[+] USB topology (lsusb -t):"
  lsusb -t || echo "[!] No USB topology found."
  echo

  echo "===== Hardware and Partition Information ====="
  sudo hdparm -I "$DEVICE" 2>/dev/null | grep -E "Model|Serial|Firmware" || echo "[!] hdparm found nothing."
  echo
  lsblk -o NAME,SIZE,MODEL,TRAN,SERIAL 2>/dev/null | grep "$(basename "$DEVICE")"
  echo
  sudo udevadm info --query=all --name="$DEVICE" 2>/dev/null | grep -E "ID_MODEL=|ID_SERIAL=|ID_VENDOR="
  echo
  echo "[+] Partition table (fdisk -l):"
  sudo fdisk -l "$DEVICE" 2>/dev/null || echo "[!] No partition table found."
  echo
  echo "[+] Filesystem information (blkid):"
  sudo blkid "$DEVICE" 2>/dev/null || echo "[!] No filesystem info found."
  echo
  echo "[+] Mountpoints and filesystems:"
  lsblk -o NAME,MOUNTPOINT,LABEL,FSTYPE,UUID 2>/dev/null | grep "$(basename "$DEVICE")"
  echo

  echo "===== Additional Analysis ====="
  echo "[+] Filesystem type (file -sL):"
  sudo file -sL "$DEVICE" 2>/dev/null || echo "[!] Filesystem type not found."
  echo
  echo "[+] Filesystem check (fsck -N):"
  sudo fsck -N "$DEVICE" 2>/dev/null || echo "[!] Filesystem not found."
  echo

  echo "===== S.M.A.R.T. Status ====="
  if command -v smartctl &>/dev/null; then
    sudo smartctl -a "$DEVICE" 2>/dev/null || echo "[!] SMART information not found."
  else
    echo "[!] smartctl not installed."
  fi
  echo

  echo "===== MBR Dump (first 512 bytes) ====="
  sudo dd if="$DEVICE" bs=512 count=1 2>/dev/null | hexdump -C || echo "[!] MBR not found."
  echo "==============================================="

} >> "$LOGFILE"

# Hash and imaging tool selection
HASH_CHOICE=$(zenity --list --radiolist --title="Hash Selection" --text="Choose hash type:" --column="Select" --column="Type" TRUE "MD5" FALSE "SHA256" FALSE "MD5+SHA256" 2>/dev/null) || exit 1
IMAGER=$(zenity --list --radiolist --title="Imager Selection" --text="Choose imaging tool:" --column="Select" --column="Tool" TRUE "dd" FALSE "dc3dd" FALSE "dcfldd" 2>/dev/null) || exit 1

# Optional loopback
if zenity --question --text="Use loopback device?" --ok-label="Yes" --cancel-label="No" --width=400 2>/dev/null; then
    echo "[+] User chose to use loopback." | tee -a "$LOGFILE"
    sudo losetup -d /dev/loop0 2>/dev/null
    sudo losetup -r /dev/loop0 "$DEVICE"
    LOOPDEVICE="/dev/loop0"
    echo "[+] Device mounted as read-only loopback /dev/loop0." | tee -a "$LOGFILE"
else
    LOOPDEVICE="$DEVICE"
    echo "[+] Imaging will be performed directly on the device (no loopback)." | tee -a "$LOGFILE"
fi

# Pre-hashing optional
BYTES=$(sudo blockdev --getsize64 "$LOOPDEVICE")
if zenity --question --text="Generate a pre-hash before imaging?" --ok-label="Yes" --cancel-label="No" 2>/dev/null; then
  echo "[+] Pre-hashing started..." | tee -a "$LOGFILE"

  [[ "$HASH_CHOICE" =~ MD5 ]] && MD5_SOURCE_PRE=$(pv -s "$BYTES" "$LOOPDEVICE" | md5sum | awk '{print $1}')
  [[ "$HASH_CHOICE" =~ SHA256 ]] && SHA256_SOURCE_PRE=$(pv -s "$BYTES" "$LOOPDEVICE" | sha256sum | awk '{print $1}')
fi

# Imaging
STARTTIME=$(date +"%F %T")
ERRORLOG="$OUTPUT_DIR/dd_errors_$TIMESTAMP.log"
echo "[+] Imaging started: $STARTTIME" | tee -a "$LOGFILE"

if [[ "$IMAGER" == "dd" ]]; then
  USED_COMMAND="dd if=$LOOPDEVICE of=$IMAGENAME bs=4M conv=noerror status=progress"
  sudo dd if="$LOOPDEVICE" of="$IMAGENAME" bs=4M conv=noerror status=progress 2> >(tee -a "$ERRORLOG" >&2)
elif [[ "$IMAGER" == "dc3dd" ]]; then
  USED_COMMAND="dc3dd if=$LOOPDEVICE of=$IMAGENAME rec=off"
  sudo dc3dd if="$LOOPDEVICE" of="$IMAGENAME" rec=off | tee -a "$LOGFILE"
elif [[ "$IMAGER" == "dcfldd" ]]; then
  USED_COMMAND="dcfldd if=$LOOPDEVICE of=$IMAGENAME bs=4M conv=noerror"
  sudo dcfldd if="$LOOPDEVICE" of="$IMAGENAME" bs=4M conv=noerror | tee -a "$LOGFILE"
fi

DD_EXIT=$?
ENDTIME=$(date +"%F %T")

IOERRORS=$(grep -c "Input/output error" "$ERRORLOG" 2>/dev/null || echo 0)

# Post-hashing
echo "[+] Post-hashing started: $ENDTIME" | tee -a "$LOGFILE"
[[ "$HASH_CHOICE" =~ MD5 ]] && MD5_SOURCE=$(pv -s "$BYTES" "$LOOPDEVICE" | md5sum | awk '{print $1}') && MD5_IMAGE=$(pv -s "$BYTES" "$IMAGENAME" | md5sum | awk '{print $1}')
[[ "$HASH_CHOICE" =~ SHA256 ]] && SHA256_SOURCE=$(pv -s "$BYTES" "$LOOPDEVICE" | sha256sum | awk '{print $1}') && SHA256_IMAGE=$(pv -s "$BYTES" "$IMAGENAME" | sha256sum | awk '{print $1}')

# Final logging
{
  echo "===== FORENSIC IMAGING LOG ====="
  echo "Start time: $STARTTIME"
  echo "End time:   $ENDTIME"
  echo "Duration:   ${HOURS} hours ${MINUTES} minutes ${SECONDS} seconds"
  echo
  echo "Device:     $DEVICE"
  echo "Read-only:  Yes"
  echo "Size:       $(numfmt --to=iec $BYTES) ($BYTES bytes)"
  echo
  echo "--- HASHES ---"
  printf "%-12s %-64s %-64s %-64s\n" "Type" "Pre-Hash" "Post-Source-Hash" "Image-Hash"

  [[ "$HASH_CHOICE" =~ MD5 ]] && printf "%-12s %-64s %-64s %-64s\n" "MD5" "${MD5_SOURCE_PRE:----}" "${MD5_SOURCE:----}" "${MD5_IMAGE:----}"
  [[ "$HASH_CHOICE" =~ SHA256 ]] && printf "%-12s %-64s %-64s %-64s\n" "SHA256" "${SHA256_SOURCE_PRE:----}" "${SHA256_SOURCE:----}" "${SHA256_IMAGE:----}"

  echo
  echo "--- ERRORS ---"
  echo "Input/Output Errors: $IOERRORS"
  echo
  echo "--- Imaging Command Used ---"
  echo "$USED_COMMAND"
  echo "================================="
} >> "$LOGFILE"

# Summary
DURATION=$(($(date -d "$ENDTIME" +%s) - $(date -d "$STARTTIME" +%s)))
HOURS=$((DURATION / 3600))
MINUTES=$(((DURATION % 3600) / 60))
SECONDS=$((DURATION % 60))

[[ "$LOOPDEVICE" == "/dev/loop0" ]] && sudo losetup -d /dev/loop0

if [[ "$IOERRORS" =~ ^[0-9]+$ ]] && (( IOERRORS > 0 )); then
  SUMMARY_ICON="error"
  ERROR_MESSAGE="$IOERRORS error(s) detected"
else
  SUMMARY_ICON="info"
  ERROR_MESSAGE="No errors detected"
fi

SUMMARY_TEXT="Imaging completed!\n\nDevice: $DEVICE\nImage: $(basename "$IMAGENAME")\nSize: $(numfmt --to=iec $BYTES)\nDuration: ${HOURS}h ${MINUTES}min ${SECONDS}s\nErrors: $ERROR_MESSAGE\nLog file: $(basename "$LOGFILE")"

zenity --$SUMMARY_ICON --width=400 --title="Forensic Imaging Summary" --text="$SUMMARY_TEXT" 2>/dev/null

echo "[+] Imaging completed."
