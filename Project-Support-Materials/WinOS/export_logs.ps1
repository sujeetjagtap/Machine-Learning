# Set output path
$outputPath = "C:\CTI_Pipeline\logs\sysmon_events.csv"
New-Item -ItemType Directory -Force -Path "C:\CTI_Pipeline\logs"

# Export all Sysmon events (adjust MaxEvents for production)
Write-Host "Exporting Sysmon events..." -ForegroundColor Yellow
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50000 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, Message, @{Name='XML';Expression={$_.ToXml()}} |
    Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported to: $outputPath" -ForegroundColor Green
Write-Host "Total events exported: $((Import-Csv $outputPath).Count)" -ForegroundColor Cyan
