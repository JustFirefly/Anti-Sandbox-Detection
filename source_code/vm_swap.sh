#!/bin/bash
VM_NAME="TargetVM_W11"

if [ "$1" == "clean" ]; then
    echo "[*] Swapping $VM_NAME to CLEAN profile..."
    virsh define ./default_profile.xml
    echo "[+] Done. Ready to launch in virt-manager."
elif [ "$1" == "hook" ]; then
    echo "[*] Swapping $VM_NAME to HOOKED profile..."
    virsh define ./hooked_profile.xml
    echo "[+] Done. Ready to launch in virt-manager."
elif [ "$1" == "edid" ]; then
    echo "[*] Swapping $VM_NAME to FALSE EDID profile..."
    virsh define ./false_edid_profile.xml
    echo "[+] Done. Ready to launch in virt-manager."
else
    echo "Usage: ./vm_swap.sh [clean | hook | edid]"
fi
