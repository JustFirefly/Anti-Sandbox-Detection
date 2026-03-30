# Run as Administrator inside the Guest
$drivers = @("viostar", "vmmouse", "balloon")

foreach ($name in $drivers) {
    $originalPath = "C:\Windows\System32\drivers\$name.sys"
    $newName = "stornvme_ext_$name.sys" # Benign looking name
    $newPath = "C:\Windows\System32\drivers\$newName"

    if (Test-Path $originalPath) {
        # 1. Rename the driver file
        Move-Item -Path $originalPath -Destination $newPath -Force
        
        # 2. Update the Registry ImagePath for the service
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "ImagePath" -Value "system32\drivers\$newName"
            Write-Host "Successfully spoofed $name.sys to $newName"
        }
    }
}
