# This simulates MITRE ATT&CK techniques

Write-Host "Simulating malicious activities..." -ForegroundColor Red

# T1059.003: Command and Scripting Interpreter: Windows Command Shell
cmd.exe /c "whoami && ipconfig && net user"

# T1082: System Information Discovery
systeminfo
wmic computersystem get domain

# T1083: File and Directory Discovery
dir C:\Users /s /b

# T1016: System Network Configuration Discovery
nslookup google.com
netstat -ano

# T1033: System Owner/User Discovery
query user

# T1046: Network Service Scanning (simulated)
Test-NetConnection -ComputerName "127.0.0.1" -Port 445

# Export malicious events
$outputPath = "C:\CTI_Pipeline\logs\malicious_events.csv"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 | 
    Select-Object -First 500 TimeCreated, Id, Message, @{Name='XML';Expression={$_.ToXml()}} |
    Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "Collected simulated malicious events" -ForegroundColor Green
