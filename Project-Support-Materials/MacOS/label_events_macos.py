import pandas as pd

# macOS-specific MITRE ATT&CK patterns
ATTACK_PATTERNS_MACOS = {
    'T1059.004': {
        'name': 'Command and Scripting Interpreter: Unix Shell',
        'patterns': ['bash', 'zsh', 'sh', '/bin/bash', '/bin/zsh'],
        'keywords': ['whoami', 'id', 'uname', 'sudo', 'su']
    },
    'T1082': {
        'name': 'System Information Discovery',
        'patterns': ['system_profiler', 'sw_vers', 'sysctl'],
        'keywords': ['spsoftware', 'sphardware', 'kern.']
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'patterns': ['find', 'mdfind', 'ls'],
        'keywords': ['-name', '-type', '-la', 'spotlight']
    },
    'T1016': {
        'name': 'System Network Configuration Discovery',
        'patterns': ['ifconfig', 'netstat', 'arp', 'networksetup'],
        'keywords': ['an', 'inet', 'ether']
    },
    'T1033': {
        'name': 'System Owner/User Discovery',
        'patterns': ['who', 'last', 'dscl', 'id'],
        'keywords': ['users', 'list']
    },
    'T1057': {
        'name': 'Process Discovery',
        'patterns': ['ps', 'top', 'lsof'],
        'keywords': ['aux', '-l']
    },
    'T1046': {
        'name': 'Network Service Scanning',
        'patterns': ['nc', 'nmap', 'telnet'],
        'keywords': ['-zv', '-sS', '-p']
    },
    'T1552.001': {
        'name': 'Credentials from Files',
        'patterns': ['cat', 'grep', 'find'],
        'keywords': ['.ssh', 'id_rsa', 'credentials', 'password']
    }
}

def detect_attack_technique_macos(command_line, process_path, process_name):
    """Detect MITRE ATT&CK technique for macOS"""
    if not isinstance(command_line, str):
        command_line = ''
    if not isinstance(process_name, str):
        process_name = ''
    
    command_lower = command_line.lower()
    process_lower = process_name.lower()
    
    for technique_id, technique_info in ATTACK_PATTERNS_MACOS.items():
        # Check if process matches known patterns
        for pattern in technique_info['patterns']:
            if pattern in process_lower or pattern in command_lower:
                # Check for specific keywords
                if technique_info['keywords']:
                    if any(keyword in command_lower for keyword in technique_info['keywords']):
                        return technique_id, technique_info['name']
                else:
                    return technique_id, technique_info['name']
    
    return None, None

def label_dataset_macos(input_csv, output_csv):
    """Label macOS events with MITRE ATT&CK"""
    print("Loading dataset...")
    df = pd.read_csv(input_csv)
    
    # Initialize labels
    df['label'] = 'benign'
    df['mitre_technique'] = ''
    df['mitre_tactic'] = ''
    
    # Detect and label malicious patterns
    print("Detecting malicious patterns...")
    for idx, row in df.iterrows():
        technique_id, technique_name = detect_attack_technique_macos(
            row.get('command_line', ''),
            row.get('process_path', ''),
            row.get('process_name_extracted', '')
        )
        
        if technique_id:
            df.at[idx, 'label'] = 'malicious'
            df.at[idx, 'mitre_technique'] = technique_id
            df.at[idx, 'mitre_tactic'] = technique_name
    
    # Statistics
    label_counts = df['label'].value_counts()
    print(f"\nLabeling Summary:")
    print(f"  Benign: {label_counts.get('benign', 0)}")
    print(f"  Malicious: {label_counts.get('malicious', 0)}")
    
    if 'malicious' in label_counts:
        print(f"\nMITRE ATT&CK Techniques Detected:")
        technique_counts = df[df['label'] == 'malicious']['mitre_technique'].value_counts()
        for tech, count in technique_counts.items():
            print(f"  {tech}: {count} events")
    
    # Save
    df.to_csv(output_csv, index=False)
    print(f"\n✓ Saved labeled dataset to: {output_csv}")
    
    return df

if __name__ == "__main__":
    import os
    
    input_file = os.path.expanduser("~/CTI_Pipeline/logs/preprocessed_events.csv")
    output_file = os.path.expanduser("~/CTI_Pipeline/logs/labeled_events.csv")
    
    labeled_df = label_dataset_macos(input_file, output_file)
