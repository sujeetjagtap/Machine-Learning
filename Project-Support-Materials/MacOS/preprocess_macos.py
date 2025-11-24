import re
import pandas as pd
from pathlib import Path

def clean_command_line_macos(cmd):
    """Clean and normalize command line text for macOS"""
    if not isinstance(cmd, str) or cmd == '':
        return ''
    
    # Convert to lowercase
    cmd = cmd.lower()
    
    # Remove macOS specific paths but keep structure
    cmd = re.sub(r'/users/[^/]+/', '/users/<user>/', cmd)
    cmd = re.sub(r'/applications/[^/]+\.app', '/applications/<app>.app', cmd)
    cmd = re.sub(r'/library/[^/]+/', '/library/<dir>/', cmd)
    cmd = re.sub(r'/tmp/[^/\s]+', '/tmp/<file>', cmd)
    
    # Remove UUIDs
    cmd = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<uuid>', cmd)
    
    # Remove long hex strings
    cmd = re.sub(r'\b[0-9a-f]{32,}\b', '<hash>', cmd)
    
    # Normalize whitespace
    cmd = ' '.join(cmd.split())
    
    return cmd

def extract_executable_name_macos(path):
    """Extract executable name from full macOS path"""
    if not isinstance(path, str) or path == '':
        return ''
    
    # Handle .app bundles
    if '.app/' in path:
        match = re.search(r'/([^/]+\.app)/', path)
        if match:
            return match.group(1).lower()
    
    return Path(path).name.lower()

def preprocess_dataset_macos(df):
    """Preprocess macOS dataset"""
    print("Preprocessing macOS events...")
    
    # Clean command lines
    if 'command_line' in df.columns:
        df['command_line_cleaned'] = df['command_line'].apply(clean_command_line_macos)
    else:
        df['command_line_cleaned'] = ''
    
    # Extract executable names
    if 'process_path' in df.columns:
        df['process_name_extracted'] = df['process_path'].apply(extract_executable_name_macos)
    else:
        df['process_name_extracted'] = df.get('process_name', '')
    
    # Create combined text for embedding
    df['combined_text'] = (
        df['process_name_extracted'].fillna('') + ' ' +
        df['command_line_cleaned'].fillna('')
    ).str.strip()
    
    # Remove empty combined text
    df = df[df['combined_text'] != '']
    
    print(f"✓ Preprocessed {len(df)} events")
    
    return df

if __name__ == "__main__":
    import os
    
    # Load structured events
    input_file = os.path.expanduser("~/CTI_Pipeline/logs/structured_events.csv")
    output_file = os.path.expanduser("~/CTI_Pipeline/logs/preprocessed_events.csv")
    
    df = pd.read_csv(input_file)
    
    # Preprocess
    df_processed = preprocess_dataset_macos(df)
    
    # Save
    df_processed.to_csv(output_file, index=False)
    print(f"\n✓ Saved to: {output_file}")
    print("\n=== Sample Preprocessed Events ===")
    print(df_processed[['event_type', 'process_name_extracted', 'command_line_cleaned']].head())
