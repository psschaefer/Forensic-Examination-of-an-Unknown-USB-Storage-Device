#!/bin/bash

# Placeholder
IMAGE="Target.dd"

# paramters from bootsector
BYTES_PER_SECTOR=512
RSVD_SECTORS=32
FAT_SECTORS=14992
SECTORS_PER_CLUSTER=16

# Offset sector 32 for first FAT
FAT1_OFFSET=$((RSVD_SECTORS))
FAT2_OFFSET=$((RSVD_SECTORS + FAT_SECTORS))

# analyzes free/used cluster fore each fat
analyze_fat() {
    local fat_offset=$1
    echo "analyze fat starting sector $fat_offset..."

    dd if="$IMAGE" bs=$BYTES_PER_SECTOR skip=$fat_offset count=$FAT_SECTORS status=none of=fat.tmp

    TOTAL_CLUSTERS=$((FAT_SECTORS * BYTES_PER_SECTOR / 4))
    echo "amount FAT entries (cluster): $TOTAL_CLUSTERS"

    for ((i=2; i<TOTAL_CLUSTERS; i++)); do
        
        entry=$(dd if=fat.tmp bs=4 count=1 skip=$i status=none 2>/dev/null | hexdump -v -e '1/4 "%08x\n"')

        if [[ "$entry" == "00000000" ]]; then
            echo "Cluster $i: free"
        elif [[ "$entry" == "00000001" ]]; then
            echo "Cluster $i: reserved (System)"
        elif [[ "$entry" =~ ^0ffffff[0-6]$ ]]; then
            echo "Cluster $i: reserved (FAT32)"
        elif [[ "$entry" == "0ffffff7" ]]; then
            echo "Cluster $i: defect"
        elif [[ "$entry" =~ ^0ffffff[89aAbBcCdDeEfF]$ ]]; then
            echo "Cluster $i: used (Ende)"
        else
            echo "Cluster $i: used (link to cluster $((0x$entry)))"
        fi
    done

    rm -f fat.tmp
}

analyze_fat $FAT1_OFFSET
echo "----------------------------------------"
analyze_fat $FAT2_OFFSET
