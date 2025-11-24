# Check if Sysmon is running
$service = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($service.Status -eq "Running") {
    Write-Host "✓ Sysmon is running" -ForegroundColor Green
} else {
    Write-Host "✗ Sysmon is not running" -ForegroundColor Red
}

# Count events by type
$eventCounts = @{
    "Process Creation (ID 1)" = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1000 -ErrorAction SilentlyContinue).Count
    "Network Connection (ID 3)" = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 1000 -ErrorAction SilentlyContinue).Count
    "File Creation (ID 11)" = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -MaxEvents 1000 -ErrorAction SilentlyContinue).Count
    "Registry Events (ID 12-14)" = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=12,13,14} -MaxEvents 1000 -ErrorAction SilentlyContinue).Count
}

$eventCounts.GetEnumerator() | ForEach-Object {
    Write-Host "$($_.Key): $($_.Value) events" -ForegroundColor Cyan
}
