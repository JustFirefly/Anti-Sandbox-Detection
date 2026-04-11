#!/bin/bash

# Configuration - Change these if your backup path is different
KERNEL_VER=$(uname -r)
CUSTOM_DIR="/home/firefly/backups"
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)."
   exit 1
fi

echo "------------------------------------------------"
echo "  KVM MODULE SWITCHER (Original vs. Custom) "
echo "------------------------------------------------"

# 1. Stop all virtualization services to unlock modules
echo "[*] Stopping virtualization services..."
systemctl stop libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket libvirtd.service 2>/dev/null
systemctl stop virtqemud.socket virtqemud.service 2>/dev/null
pkill -9 qemu 2>/dev/null

# 2. Unload current modules
echo "[*] Unloading active KVM modules..."
rmmod kvm_intel 2>/dev/null
rmmod kvm 2>/dev/null

# 3. Ask user for choice
echo ""
echo "Select the mode you want to activate:"
echo "1) ORIGINAL (Official Ubuntu Modules - Best for Installs)"
echo "2) CUSTOM   (Your Patched Modules - Best for Malware Testing)"
read -p "Selection [1 or 2]: " choice

case $choice in
    1)
        echo "[+] Loading ORIGINAL KVM modules via modprobe..."
        modprobe kvm
        modprobe kvm_intel
        ;;
    2)
        echo "[+] Loading CUSTOM KVM modules via insmod..."
        if [ -f "$CUSTOM_DIR/kvm.ko" ] && [ -f "$CUSTOM_DIR/kvm-intel.ko" ]; then
            # Order matters: kvm must load before kvm_intel
            insmod "$CUSTOM_DIR/kvm.ko"
            insmod "$CUSTOM_DIR/kvm-intel.ko"
        else
            echo "Error: Custom modules not found in $CUSTOM_DIR"
            exit 1
        fi
        ;;
    *)
        echo "Invalid selection. Exiting."
        exit 1
        ;;
esac

# 4. Restart services
echo "[*] Restarting virtualization services..."
systemctl start virtqemud.socket 2>/dev/null || systemctl start libvirtd.socket

echo ""
echo "[SUCCESS] KVM State Updated."
lsmod | grep kvm
