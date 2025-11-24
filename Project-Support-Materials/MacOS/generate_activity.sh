#!/bin/bash

echo "Generating system activity for CTI data collection..."
echo "Duration: 30 minutes"
echo ""

# Function to generate benign activity
generate_benign_activity() {
    echo "[BENIGN] Generating normal system activity..."
    
    # File operations
    for i in {1..100}; do
        touch ~/CTI_Pipeline/temp/file_$i.txt
        echo "test data $i" > ~/CTI_Pipeline/temp/file_$i.txt
        cat ~/CTI_Pipeline/temp/file_$i.txt > /dev/null
        rm ~/CTI_Pipeline/temp/file_$i.txt
        sleep 0.1
    done
    
    # Process spawning
    for i in {1..50}; do
        ls -la / > /dev/null &
        sleep 0.5
    done
    
    # Network activity (safe)
    for i in {1..20}; do
        curl -s https://www.google.com > /dev/null
        sleep 2
    done
    
    echo "✓ Benign activity completed"
}

# Function to simulate malicious activity (SAFE SIMULATION)
generate_malicious_activity() {
    echo "[MALICIOUS] Simulating MITRE ATT&CK techniques..."
    
    # T1059.004: Command and Scripting Interpreter: Unix Shell
    /bin/bash -c "whoami; id; uname -a"
    
    # T1082: System Information Discovery
    system_profiler SPSoftwareDataType
    sw_vers
    
    # T1083: File and Directory Discovery
    find ~/Documents -type f -name "*.pdf" 2>/dev/null | head -20
    ls -la ~/.ssh 2>/dev/null
    
    # T1033: System Owner/User Discovery
    who
    last | head -10
    dscl . list /Users
    
    # T1016: System Network Configuration Discovery
    ifconfig
    netstat -an | head -20
    arp -a
    
    # T1057: Process Discovery
    ps aux | head -20
    top -l 1 -n 10
    
    # T1046: Network Service Scanning (simulated, safe)
    nc -zv 127.0.0.1 22 2>&1
    nc -zv 127.0.0.1 80 2>&1
    
    echo "✓ Malicious simulation completed"
}

# Create temp directory
mkdir -p ~/CTI_Pipeline/temp

# Run activities
generate_benign_activity
sleep 5
generate_malicious_activity

# Cleanup
rm -rf ~/CTI_Pipeline/temp

echo ""
echo "✓ Activity generation completed"
echo "Now export logs using: ./export_logs.sh"
