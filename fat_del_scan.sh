#!/bin/bash

IMAGE="Target.dd"

# bootsector parameters
BYTES_PER_SECTOR=512
SECTORS_PER_CLUSTER=16
BYTES_PER_CLUSTER=$((BYTES_PER_SECTOR * SECTORS_PER_CLUSTER))
RESERVED_SECTORS=32
FAT_SECTORS=14992
NUM_FATS=2

# data area after 2 fats
FIRST_DATA_SECTOR=$((RESERVED_SECTORS + NUM_FATS * FAT_SECTORS))

# Sector addres to Cluster n
cluster_to_sector() {
    local cluster=$1
    echo $((FIRST_DATA_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER))
}

echo "looking for deletetd data in root:"

# root cluster
ROOT_CLUSTER=2
ROOT_SECTOR=$(cluster_to_sector $ROOT_CLUSTER)
dd if="$IMAGE" bs=$BYTES_PER_SECTOR skip=$ROOT_SECTOR count=$SECTORS_PER_CLUSTER status=none of=rootdir.tmp

# directory entries are 32 bytes
ENTRIES=$((BYTES_PER_CLUSTER / 32))

for ((i=0; i<ENTRIES; i++)); do
    offset=$((i * 32))
    hex=$(xxd -p -c 32 -s $offset -l 32 rootdir.tmp)
    first_byte=${hex:0:2}

    if [[ "$first_byte" == "e5" ]]; then
        
        name_hex=${hex:0:22}
        cluster_hex="${hex:26:2}${hex:20:2}"  # !high and low
        cluster=$((0x$cluster_hex))
        echo "deletetd data found:"
        echo "  - name (hex): $name_hex"
        echo "  - Start-cluster: $cluster"
        echo
    fi
done

rm -f rootdir.tmp
