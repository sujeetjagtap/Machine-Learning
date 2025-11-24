import pandas as pd
import chromadb
from chromadb.config import Settings
import json

# MITRE ATT&CK technique mapping
ATTACK_PATTERNS = {
    'T1059.003': {
        'name': 'Command and Scripting Interpreter: Windows Command Shell',
        'patterns': ['cmd.exe', 'powershell.exe'],
        'keywords': ['whoami', 'ipconfig', 'net user', 'net group']
    },
    'T1082': {
        'name': 'System Information Discovery',
        'patterns': ['systeminfo', 'wmic'],
        'keywords': ['computersystem', 'os get']
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'patterns': ['dir', 'tree'],
        'keywords': ['/s', '/b', 'recurse']
    },
    'T1016': {
        'name': 'System Network Configuration Discovery',
        'patterns': ['ipconfig', 'nslookup', 'netstat'],
        'keywords': ['all', 'ano']
    },
    'T1033': {
        'name': 'System Owner/User Discovery',
        'patterns': ['whoami', 'query user', 'quser'],
        'keywords': []
    }
}

def detect_attack_technique(command_line, image_name):
    """Detect MITRE ATT&CK technique based on command"""
    if not isinstance(command_line, str):
        return None, None
    
    command_lower = command_line.lower()
    image_lower = image_name.lower() if isinstance(image_name, str) else ''
    
    for technique_id, technique_info in ATTACK_PATTERNS.items():
        # Check if image matches known patterns
        for pattern in technique_info['patterns']:
            if pattern in image_lower or pattern in command_lower:
                # Check for specific keywords
                if technique_info['keywords']:
                    if any(keyword in command_lower for keyword in technique_info['keywords']):
                        return technique_id, technique_info['name']
                else:
                    return technique_id, technique_info['name']
    
    return None, None

def label_dataset(benign_csv, malicious_csv, output_csv):
    """Label benign and malicious events"""
    print("Loading datasets...")
    
    # Load and parse both datasets
    benign_df = pd.read_csv(benign_csv)
    malicious_df = pd.read_csv(malicious_csv)
    
    # Parse if needed (assuming already parsed)
    # For this example, we'll use the preprocessed data
    
    # Load preprocessed events
    all_events = pd.read_csv(r"C:\CTI_Pipeline\logs\preprocessed_events.csv")
    
    # Label all as benign initially
    all_events['label'] = 'benign'
    all_events['mitre_technique'] = ''
    all_events['mitre_tactic'] = ''
    
    # Detect and label malicious patterns
    print("Detecting malicious patterns...")
    for idx, row in all_events.iterrows():
        technique_id, technique_name = detect_attack_technique(
            row['command_line_cleaned'],
            row['image_name']
        )
        
        if technique_id:
            all_events.at[idx, 'label'] = 'malicious'
            all_events.at[idx, 'mitre_technique'] = technique_id
            all_events.at[idx, 'mitre_tactic'] = technique_name
    
    # Statistics
    label_counts = all_events['label'].value_counts()
    print(f"\nLabeling Summary:")
    print(f"  Benign: {label_counts.get('benign', 0)}")
    print(f"  Malicious: {label_counts.get('malicious', 0)}")
    
    if 'malicious' in label_counts:
        print(f"\nMITRE ATT&CK Techniques Detected:")
        technique_counts = all_events[all_events['label'] == 'malicious']['mitre_technique'].value_counts()
        for tech, count in technique_counts.items():
            print(f"  {tech}: {count} events")
    
    # Save labeled dataset
    all_events.to_csv(output_csv, index=False)
    print(f"\n Saved labeled dataset to: {output_csv}")
    
    return all_events

def update_vectordb_labels(labeled_df):
    """Update ChromaDB with labels"""
    print("\nUpdating vector database with labels...")
    
    client = chromadb.PersistentClient(
        path=r"C:\CTI_Pipeline\vectordb",
        settings=Settings(anonymized_telemetry=False)
    )
    
    collection = client.get_collection("sysmon_events")
    
    # Update in batches
    batch_size = 1000
    for i in range(0, len(labeled_df), batch_size):
        batch = labeled_df.iloc[i:i+batch_size]
        
        ids = [f"event_{i+j}" for j in range(len(batch))]
        
        # Update metadata
        for j, (idx, row) in enumerate(batch.iterrows()):
            try:
                collection.update(
                    ids=[ids[j]],
                    metadatas=[{
                        'event_id': str(row['event_id']),
                        'timestamp': str(row['timestamp']),
                        'image_name': str(row['image_name']) if pd.notna(row['image_name']) else '',
                        'label': row['label'],
                        'mitre_technique': row['mitre_technique'] if pd.notna(row['mitre_technique']) else '',
                        'mitre_tactic': row['mitre_tactic'] if pd.notna(row['mitre_tactic']) else ''
                    }]
                )
            except Exception as e:
                pass  # Skip if event doesn't exist
    
    print("Updated vector database with labels")

if __name__ == "__main__":
    # Label events
    labeled_df = label_dataset(
        benign_csv=r"C:\CTI_Pipeline\logs\benign_events.csv",
        malicious_csv=r"C:\CTI_Pipeline\logs\malicious_events.csv",
        output_csv=r"C:\CTI_Pipeline\logs\labeled_events.csv"
    )
    
    # Update vector database
    update_vectordb_labels(labeled_df)
