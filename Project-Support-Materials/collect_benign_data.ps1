# Collect benign data during normal operations
Write-Host "Starting benign data collection (30 minutes)..." -ForegroundColor Yellow
Write-Host "Perform normal system activities: browse web, open applications, edit documents" -ForegroundColor Cyan

# Capture start time
$startTime = Get-Date
$duration = 30  # minutes

# Wait for data collection
Start-Sleep -Seconds ($duration * 60)

# Export benign events
$outputPath = "C:\CTI_Pipeline\logs\benign_events.csv"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 | 
    Where-Object { $_.TimeCreated -gt $startTime } |
    Select-Object TimeCreated, Id, Message, @{Name='XML';Expression={$_.ToXml()}} |
    Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "Collected benign events" -ForegroundColor Green
