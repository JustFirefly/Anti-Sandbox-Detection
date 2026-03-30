#!/bin/bash
VM_NAME="TargetVM_W11"

# Define profile paths based on project structure
DEFAULT_XML="./main/default_profile.xml"
HOOK_XML="./T01/hooked_profile.xml"
MAC_XML="./T02/mac_spoof_profile.xml"
AUDIO_XML="./T07/audio_device_spoof.xml"
EDID_XML="./T08/false_edid_profile.xml"

case "$1" in
    "clean")
        echo "[*] Swapping $VM_NAME to CLEAN profile..."
        virsh define "$DEFAULT_XML"
        ;;
    "hook")
        echo "[*] Swapping $VM_NAME to HOOKED profile (KVM Hook)..."
        virsh define "$HOOK_XML"
        ;;
    "mac")
        echo "[*] Swapping $VM_NAME to MAC Spoof profile..."
        virsh define "$MAC_XML"
        ;;
    "audio")
        echo "[*] Swapping $VM_NAME to Audio Device Spoof profile..."
        virsh define "$AUDIO_XML"
        ;;
    "edid")
        echo "[*] Swapping $VM_NAME to FALSE EDID profile..."
        virsh define "$EDID_XML"
        ;;
    *)
        echo "Usage: ./vm_swap.sh [clean | hook | mac | audio | edid]"
        exit 1
        ;;
esac

echo "[+] Done. Ready to launch in virt-manager."
