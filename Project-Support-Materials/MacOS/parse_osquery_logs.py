import json
import pandas as pd
import os
from datetime import datetime
from pathlib import Path

def parse_process_events(json_file):
    """Parse process events from osquery"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    parsed = []
    for event in data:
        parsed.append({
            'event_type': 'process',
            'event_id': 1,  # Map to SYSMON-like ID
            'timestamp': datetime.fromtimestamp(int(event.get('time', 0))),
            'pid': event.get('pid', ''),
            'process_name': event.get('path', '').split('/')[-1],
            'process_path': event.get('path', ''),
            'command_line': event.get('cmdline', ''),
            'parent_pid': event.get('parent', ''),
            'uid': event.get('uid', ''),
            'gid': event.get('gid', ''),
            'action': event.get('action', '')
        })
    
    return parsed

def parse_socket_events(json_file):
    """Parse network socket events"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    parsed = []
    for event in data:
        parsed.append({
            'event_type': 'network',
            'event_id': 3,  # Map to SYSMON-like ID
            'timestamp': datetime.fromtimestamp(int(event.get('time', 0))),
            'pid': event.get('pid', ''),
            'process_name': event.get('path', '').split('/')[-1] if event.get('path') else '',
            'process_path': event.get('path', ''),
            'protocol': event.get('protocol', ''),
            'local_address': event.get('local_address', ''),
            'local_port': event.get('local_port', ''),
            'remote_address': event.get('remote_address', ''),
            'remote_port': event.get('remote_port', ''),
            'action': event.get('action', '')
        })
    
    return parsed

def parse_file_events(json_file):
    """Parse file system events"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    parsed = []
    for event in data:
        parsed.append({
            'event_type': 'file',
            'event_id': 11,  # Map to SYSMON-like ID
            'timestamp': datetime.fromtimestamp(int(event.get('time', 0))),
            'target_path': event.get('target_path', ''),
            'action': event.get('action', ''),
            'uid': event.get('uid', ''),
            'gid': event.get('gid', ''),
            'mode': event.get('mode', '')
        })
    
    return parsed

def parse_all_logs(log_dir):
    """Parse all osquery logs and combine"""
    print("Parsing osquery logs...")
    
    all_events = []
    
    # Parse process events
    process_file = os.path.join(log_dir, 'process_events.json')
    if os.path.exists(process_file):
        print(f"Parsing {process_file}...")
        all_events.extend(parse_process_events(process_file))
    
    # Parse socket events
    socket_file = os.path.join(log_dir, 'socket_events.json')
    if os.path.exists(socket_file):
        print(f"Parsing {socket_file}...")
        all_events.extend(parse_socket_events(socket_file))
    
    # Parse file events
    file_file = os.path.join(log_dir, 'file_events.json')
    if os.path.exists(file_file):
        print(f"Parsing {file_file}...")
        all_events.extend(parse_file_events(file_file))
    
    # Create dataframe
    df = pd.DataFrame(all_events)
    
    # Sort by timestamp
    if len(df) > 0 and 'timestamp' in df.columns:
        df = df.sort_values('timestamp')
    
    print(f"\n✓ Parsed {len(df)} total events")
    print(f"Event distribution:\n{df['event_type'].value_counts()}")
    
    return df

if __name__ == "__main__":
    # Parse logs
    log_dir = os.path.expanduser("~/CTI_Pipeline/logs/collected")
    output_file = os.path.expanduser("~/CTI_Pipeline/logs/structured_events.csv")
    
    df = parse_all_logs(log_dir)
    
    # Save structured dataset
    df.to_csv(output_file, index=False)
    print(f"\n✓ Saved structured dataset to: {output_file}")
    
    # Display sample
    print("\n=== Sample Events ===")
    print(df.head(10))
