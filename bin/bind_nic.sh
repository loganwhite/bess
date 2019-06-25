#! /bin/bash
set -e

DPDK_HOME=$1

DEVICE_ID=$2
echo $DEVICE_ID

# Install drivers
if ! lsmod | grep -q '^uio'; then
        sudo modprobe uio
fi


if ! lsmod | grep -q '^igb_uio'; then
        sudo insmod $DPDK_HOME/build/kmod/igb_uio.ko
fi

# Bind NIC to driver
sudo ./dpdk-devbind.py --bind=igb_uio $DEVICE_ID

#Print current NIC binding status
./dpdk-devbind.py --status
