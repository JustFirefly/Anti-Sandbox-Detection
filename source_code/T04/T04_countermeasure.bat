@echo off
:: Rename analysis tools to look like benign system processes
rename "C:\Tools\wireshark.exe" "svchost_net.exe"
rename "C:\Tools\procmon.exe" "lsass_debug.exe"

:: Uninstall QEMU Guest Agent (if present) to remove qemu-ga.exe from process list
MsiExec.exe /X{REPLACE-WITH-QEMU-GA-GUID} /qn
echo Analysis tools masked and Guest Agent removed.
