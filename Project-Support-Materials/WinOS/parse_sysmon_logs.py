import pandas as pd
import xml.etree.ElementTree as ET
import re
from datetime import datetime
import json

def parse_sysmon_xml(xml_string):
    """Parse Sysmon event XML and extract key fields"""
    try:
        root = ET.fromstring(xml_string)
        
        # Define namespace
        ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Extract system data
        system = root.find('.//event:System', ns)
        event_id = system.find('.//event:EventID', ns).text if system.find('.//event:EventID', ns) is not None else None
        time_created = system.find('.//event:TimeCreated', ns).get('SystemTime') if system.find('.//event:TimeCreated', ns) is not None else None
        
        # Extract event data
        event_data = {}
        data_elements = root.findall('.//event:EventData/event:Data', ns)
        
        for data in data_elements:
            name = data.get('Name')
            value = data.text if data.text else ''
            event_data[name] = value
        
        return {
            'event_id': event_id,
            'timestamp': time_created,
            'process_id': event_data.get('ProcessId', ''),
            'command_line': event_data.get('CommandLine', ''),
            'image': event_data.get('Image', ''),
            'parent_image': event_data.get('ParentImage', ''),
            'user': event_data.get('User', ''),
            'network_destination': event_data.get('DestinationIp', '') + ':' + event_data.get('DestinationPort', ''),
            'hash': event_data.get('Hashes', ''),
            'target_filename': event_data.get('TargetFilename', ''),
            'registry_target': event_data.get('TargetObject', ''),
            'raw_data': json.dumps(event_data)
        }
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return None

def process_sysmon_logs(csv_path):
    """Process exported Sysmon CSV and create structured dataset"""
    print("Loading CSV file...")
    df = pd.read_csv(csv_path)
    
    print(f"Total events loaded: {len(df)}")
    
    # Parse XML for each event
    parsed_events = []
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"Processing event {idx}/{len(df)}...")
        
        parsed = parse_sysmon_xml(row['XML'])
        if parsed:
            parsed_events.append(parsed)
    
    # Create structured dataframe
    structured_df = pd.DataFrame(parsed_events)
    
    # Clean timestamp
    structured_df['timestamp'] = pd.to_datetime(structured_df['timestamp'])
    
    # Remove duplicate events
    structured_df = structured_df.drop_duplicates(subset=['timestamp', 'process_id', 'command_line'])
    
    print(f"\n Parsed {len(structured_df)} unique events")
    print(f"Event distribution:\n{structured_df['event_id'].value_counts()}")
    
    return structured_df

if __name__ == "__main__":
    # Process logs
    csv_path = r"C:\CTI_Pipeline\logs\sysmon_events.csv"
    output_path = r"C:\CTI_Pipeline\logs\structured_events.csv"
    
    df = process_sysmon_logs(csv_path)
    
    # Save structured dataset
    df.to_csv(output_path, index=False)
    print(f"\n Saved structured dataset to: {output_path}")
    
    # Display sample
    print("\n=== Sample Events ===")
    print(df[['event_id', 'timestamp', 'image', 'command_line']].head(10))
