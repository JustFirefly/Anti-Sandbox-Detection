# T10_countermeasure.ps1
# Run this script during VM provisioning BEFORE taking the clean snapshot

Write-Host "[+] Generating human-like system state..."

# 1. Generate Fake Recent Documents
$tempDocs = "$env:USERPROFILE\Documents"
$shell = New-Object -ComObject WScript.Shell

for ($i = 1; $i -le 10; $i++) {
    $filePath = "$tempDocs\Financial_Report_Q$i.txt"
    Set-Content -Path $filePath -Value "Confidential financial data."
    
    # Opening the file via the Shell registers it in Windows "Recent" items
    $shell.Run("notepad.exe $filePath")
    Start-Sleep -Milliseconds 500
    
    # Kill notepad silently
    Stop-Process -Name notepad -Force
}

# 2. Generate Fake Browser History (Edge/Chrome)
# Opens legitimate high-traffic sites to populate DNS cache and browser SQLite DBs
$urls = @("https://www.google.com", "https://www.youtube.com", "https://www.amazon.com", "https://www.wikipedia.org")

foreach ($url in $urls) {
    Start-Process "microsoft-edge:$url"
    Start-Sleep -Seconds 2
}
Stop-Process -Name msedge -Force

Write-Host "[+] System aged successfully. Environment is ready for snapshot."