#!/bin/bash

echo "[*] Forcibly stopping all QEMU/KVM processes..."
sudo pkill -9 -f qemu-system
sudo pkill -9 -f qemu

echo "[*] Forcibly stopping all VirtualBox processes..."
sudo pkill -9 -f VirtualBoxVM
sudo pkill -9 -f VBoxHeadless
sudo pkill -9 -f VBoxSVC

echo "[+] All VM processes have been terminated."
