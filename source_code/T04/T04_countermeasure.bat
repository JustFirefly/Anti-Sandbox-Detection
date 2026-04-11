@echo off
echo [*] Initiating T04 Full Process Cloaking...

:: 1. Kill all 7 targeted processes to release file locks
taskkill /F /IM vboxservice.exe /T >nul 2>&1
taskkill /F /IM vboxtray.exe /T >nul 2>&1
taskkill /F /IM vmtoolsd.exe /T >nul 2>&1
taskkill /F /IM wireshark.exe /T >nul 2>&1
taskkill /F /IM procmon.exe /T >nul 2>&1
taskkill /F /IM qemu-ga.exe /T >nul 2>&1
taskkill /F /IM spice-vdagent.exe /T >nul 2>&1

:: 2. Create a hidden staging directory for your tools
mkdir "C:\Windows\Temp\SystemHost" >nul 2>&1

:: 3. Copy and rename the analysis tools to benign Windows names
:: (Only doing this for tools you might actually run)
copy "C:\Tools\wireshark.exe" "C:\Windows\Temp\SystemHost\spoolsv_net.exe" /Y >nul 2>&1
copy "C:\Tools\procmon.exe" "C:\Windows\Temp\SystemHost\taskhostw_ext.exe" /Y >nul 2>&1

:: 4. Rename the SPICE Guest Agent (Crucial for QEMU)
:: You must also update the vdservice registry key for this to persist across reboots
copy "C:\Program Files\SPICE Guest Tools\spice-vdagent.exe" "C:\Program Files\SPICE Guest Tools\win_disp_helper.exe" /Y >nul 2>&1

:: 5. Launch the disguised tools
start "" "C:\Windows\Temp\SystemHost\spoolsv_net.exe"
start "" "C:\Windows\Temp\SystemHost\taskhostw_ext.exe"
start "" "C:\Program Files\SPICE Guest Tools\win_disp_helper.exe"

echo [+] All 7 processes neutralized. Analysis tools are now cloaked.
