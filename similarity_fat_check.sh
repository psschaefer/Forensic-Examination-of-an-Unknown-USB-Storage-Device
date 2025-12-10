#!/bin/bash

FILE="fat_report.txt"

# boot sector parameters
BYTES_PER_SECTOR=512
SECTORS_PER_CLUSTER=16
BYTES_PER_CLUSTER=$((BYTES_PER_SECTOR * SECTORS_PER_CLUSTER))
RESERVED_SECTORS=32
FAT_SECTORS=14992
NUM_FATS=2

FIRST_DATA_SECTOR=$((RESERVED_SECTORS + NUM_FATS * FAT_SECTORS))

# FAT1
FAT1=($(awk '/^analyze fat starting sector 32/,/^[-]+$/' "$FILE" \
    | grep '^Cluster' \
    | cut -d':' -f2- \
    | sed 's/^ //'))

# FAT2
FAT2=($(awk '/^analyze fat starting sector 15024/,0' "$FILE" \
    | grep '^Cluster' \
    | cut -d':' -f2- \
    | sed 's/^ //'))

echo "=== Differences between FAT1 and FAT2 ==="
CLUSTER=2
DIFF_FOUND=0
for ((i=0; i<${#FAT1[@]}; i++)); do
    if [[ "${FAT1[$i]}" != "${FAT2[$i]}" ]]; then
        echo "Difference at cluster $CLUSTER:"
        echo "  FAT1: ${FAT1[$i]}"
        echo "  FAT2: ${FAT2[$i]}"
        echo
        DIFF_FOUND=1
    fi
    ((CLUSTER++))
done

if [[ $DIFF_FOUND -eq 0 ]]; then
    echo "Both FAT tables are identical."
fi


# List allocated cluster ranges (FAT1)

echo
echo "=== Allocated cluster ranges ==="

awk -v bytes_per_cluster=$BYTES_PER_CLUSTER \
    -v spc=$SECTORS_PER_CLUSTER \
    -v bps=$BYTES_PER_SECTOR \
    -v first_data_sector=$FIRST_DATA_SECTOR \
'
# Work on FAT1 section of the report
/^analyze fat starting sector 32/,/^[-]+$/ {
    # Look for lines like:
    # Cluster 123: used (link to cluster 456)
    # Cluster 190: used (end)
    if ($0 ~ /^Cluster [0-9]+: used/) {
        match($0, /^Cluster ([0-9]+): used(.*)/, m)
        cluster = m[1]
        status = m[2]

        # "used (link to cluster ...)" : part of a chain
        if (status ~ /link/) {
            if (in_chain == 0) {
                start = cluster
                in_chain = 1
            }
            last = cluster

        # "used (end)" : chain end or single-cluster file
        } else if (status ~ /(Ende|end)/) {
            if (in_chain == 1) {
                print_entry(start, cluster)
                in_chain = 0
            } else {
                print_entry(cluster, cluster)
            }
        }
    }
}
END {
    # If chain remained open at EOF, close it
    if (in_chain == 1) {
        print_entry(start, last)
    }
}

function print_entry(start, end) {
    count = end - start + 1
    bytes = count * bytes_per_cluster
    kb = bytes / 1024
    mb = kb / 1024
    sector = first_data_sector + ((start - 2) * spc)
    offset = sector * bps
    printf("Clusters: %d-%d (end) | Size: %d Bytes (%.1f KB, %.2f MB) | Start sector: %d | Byte offset: %d\n",
        start, end, bytes, kb, mb, sector, offset)
}
' "$FILE"