
***

# Hypervisor Detection Evasion & VM Spoofing

## Overview
This repository contains the source code, build scripts, and execution environments for evading hypervisor detection and spoofing virtual machine hardware characteristics. The project utilizes QEMU/KVM hooks, libvirt XML profile modifications, and DLL injection to mask the presence of a virtual machine from guest operating systems.

## Prerequisites & Setup
To compile and run this project, you will need:
* A Linux host environment (e.g., Ubuntu)
* QEMU/KVM and libvirt installed
* `gcc` and `g++` compilers
* A Windows Virtual Machine (for testing the `.bat` and `.ps1` countermeasures)
* The MinGW-w64 cross-compiler toolchain (e.g., `mingw-w64` package on Ubuntu) required for compiling the Windows-targeted binaries/DLLs.

# File Structure


```markdown
source_code/
|-- main/                     (Core injector logic and default profiles)
|   |-- dll_injector.cpp
|   |-- main.cpp 
|   |-- main_v2.cpp
|   |-- default_profile.xml
|   |-- compile.sh
|   `-- compile_inj.sh
|
|-- T01/                      (KVM Hooking and Hardware ID Spoofing)
|   |-- kvm_hook.c            (Hooking logic, compiled to shared object)
|   |-- spoof_hwid.cpp        (Hardware ID modification)
|   |-- hooked_profile.xml
|   |-- compile_so.sh
|   |-- compile_t01_t06.sh
|   `-- run_QEmu.sh
|
|-- T02/                      (MAC Address Spoofing)
|   `-- mac_spoof_profile.xml
|
|-- T03/                      (Guest Countermeasure - PowerShell)
|   `-- T03_countermeasure.ps1
|
|-- T04/                      (Guest Countermeasure - Batch)
|   `-- T04_countermeasure.bat
|
|-- T05/                      (Guest Countermeasure - Batch)
|   `-- T05_countermeasure.bat
|
|-- T06/                      (VMX Hypervisor Modification)
|   `-- vmx.c                 (Modified KVM source file)
|
|-- T07/                      (Audio Device Spoofing)
|   `-- audio_device_spoof.xml
|
|-- T08/                      (Display and EDID Spoofing)
|   |-- spoof_display.cpp
|   |-- real_monitor_edid.bin
|   |-- false_edid_profile.xml
|   `-- compile_t08.sh
|
|-- T09/                      (Isolated Network Configuration)
|   |-- isolated_network.xml
|   `-- T09_profile.xml
|
|-- T10/                      (Guest Countermeasure - PowerShell)
|   `-- T10_countermeasure.ps1
|
|-- capture.sh                (Utility: Standard log capture)
|-- read_log.sh               (Utility: Read standard logs)
|-- vmexit_capture.sh         (Utility: Capture KVM VM Exits)
|-- vmexit_read.sh            (Utility: Read VM Exits)
|-- vm_swap.sh                (Utility: Swap VM states)
|-- swap_kernel.sh            (Utility: Swap hypervisor kernels)
`-- kill_vms.sh               (Utility: Terminate running VMs)
```

### ⚠️ Important Initial Setup
Before running the compile scripts, you **must** configure your file paths and shared directories:

1. **Create the Shared Folder:** The compilation scripts automatically output Windows binaries (`sandbox_tester.exe`, `injector.exe`, `spoof_hw.dll`) to a shared folder. You must create this folder before compiling:
   ```bash
   mkdir -p ~/vbox_share/
   ```
   *Note: Ensure this folder is configured as a shared directory with your Windows VM so you can easily transfer the compiled payloads.*
2. **Update VM Names and Paths:** Open the following scripts and update the hardcoded paths to match your local environment:
   * **`T01/run_QEmu.sh`**: Change `-hda /media/firefly/VMs/TargetVM-W11-QEMU.qcow2` to point to your actual Windows VM `.qcow2` file.
   * **`vm_swap.sh`**: Change `VM_NAME="TargetVM_W11"` to the name of your VM in libvirt.
   * **`swap_kernel.sh`**: Change `CUSTOM_DIR="/home/firefly/backups"` to the directory where you plan to store your custom compiled `kvm.ko` and `kvm-intel.ko` modules.

## Detailed Usage Guide by Technique

The project is structured into specific techniques (T01-T10) targeting different hypervisor detection vectors.

### Core Modules
* **`main/` (DLL Injector & Core Logic):** Contains the primary injection mechanisms (`dll_injector.cpp`, `main.cpp`). 
  **Usage:** Run `./compile.sh` or `./compile_inj.sh` to build the injector binaries. The output will be automatically placed in `~/vbox_share/`.

### Evasion Techniques (Host-Side)
* **T01 - KVM Hooking & HWID Spoofing:** Intercepts CPUID and other KVM exits to spoof hardware IDs.
  **Usage:** Navigate to `T01/`. Run `./compile_so.sh` followed by `./compile_t01_t06.sh` (this places the DLL in `~/vbox_share/`). Launch the VM with the hooks applied using `./run_QEmu.sh` (ensure you updated the image path first). 
* **T02 - MAC Address Spoofing:** Modifies the virtual network interface to hide typical QEMU/OUI MAC addresses.
  **Usage:** Apply `mac_spoof_profile.xml` to your libvirt/QEMU configuration before boot.
* **T06 - VMX Hypervisor Modification:** Deep-level evasion modifying the Intel VMX kernel module.
  **Usage:** The `vmx.c` file must be used to replace the standard `arch/x86/kvm/vmx/vmx.c` in the Linux kernel source tree, followed by recompiling the KVM module. Place the resulting `kvm.ko` and `kvm-intel.ko` files into your custom backup directory (default: `/home/firefly/backups`) so `swap_kernel.sh` can load them.
* **T07 - Audio Device Spoofing:** Masks the default virtual audio controllers (e.g., AC97).
  **Usage:** Apply `audio_device_spoof.xml` to the VM's libvirt configuration.
* **T08 - Display & EDID Spoofing:** Feeds a real monitor's EDID (`real_monitor_edid.bin`) to the guest instead of the QEMU default.
  **Usage:** Compile the spoofing binary using `./compile_t08.sh`. Apply `false_edid_profile.xml` to load the realistic display configuration.
* **T09 - Isolated Network Configuration:** Prevents the guest from probing the host network for virtualization artifacts.
  **Usage:** Apply `isolated_network.xml` or `T09_profile.xml` to the VM's libvirt configuration.

### Countermeasure Scripts (Guest-Side)
These scripts are designed to be executed inside the Windows Guest OS to test or implement further evasion.
* **T03 (PowerShell):** Transfer `T03_countermeasure.ps1` to the guest and run as Administrator.
* **T04 (Batch):** Transfer `T04_countermeasure.bat` to the guest and run as Administrator.
* **T05 (Batch):** Transfer `T05_countermeasure.bat` to the guest and run as Administrator.
* **T10 (PowerShell):** Transfer `T10_countermeasure.ps1` to the guest and run as Administrator.

### Root Management Scripts
* **Profile Swapping:** Use `./vm_swap.sh` to transition between hooked and standard hypervisor states. **Note:** This script relies on relative file paths and *must* be executed from the root of the repository (do not run it from inside a subfolder).
* **Kernel Swapping:** Use `sudo ./swap_kernel.sh` to unload standard KVM modules and inject your modified ones. Ensure your custom modules are placed in the configured `CUSTOM_DIR`.
* **Logging:** Use `./capture.sh`, `./read_log.sh`, `./vmexit_capture.sh`, and `./vmexit_read.sh` to monitor evasion success and KVM exits.