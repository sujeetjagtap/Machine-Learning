import re
import pandas as pd
from pathlib import Path

def clean_command_line(cmd):
    """Clean and normalize command line text"""
    if not isinstance(cmd, str) or cmd == '':
        return ''
    
    # Convert to lowercase
    cmd = cmd.lower()
    
    # Remove paths, keep only executable names
    cmd = re.sub(r'[c-z]:\\[^\s]*\\([^\\]+\.exe)', r'\1', cmd)
    
    # Remove specific file paths but keep general structure
    cmd = re.sub(r'\\users\\[^\\]+\\', r'\\users\\<user>\\', cmd)
    cmd = re.sub(r'\\temp\\[^\\]+', r'\\temp\\<file>', cmd)
    
    # Remove UUIDs and GUIDs
    cmd = re.sub(r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}', '<guid>', cmd)
    
    # Remove long hex strings
    cmd = re.sub(r'\b[0-9a-f]{32,}\b', '<hash>', cmd)
    
    # Normalize whitespace
    cmd = ' '.join(cmd.split())
    
    return cmd

def extract_executable_name(path):
    """Extract executable name from full path"""
    if not isinstance(path, str) or path == '':
        return ''
    
    return Path(path).name.lower()

def preprocess_dataset(df):
    """Preprocess entire dataset"""
    print("Preprocessing text fields...")
    
    # Clean command lines
    df['command_line_cleaned'] = df['command_line'].apply(clean_command_line)
    
    # Extract executable names
    df['image_name'] = df['image'].apply(extract_executable_name)
    df['parent_image_name'] = df['parent_image'].apply(extract_executable_name)
    
    # Create combined text for embedding
    df['combined_text'] = (
        df['image_name'] + ' ' + 
        df['command_line_cleaned'] + ' ' + 
        df['parent_image_name']
    )
    
    # Remove empty combined text
    df = df[df['combined_text'].str.strip() != '']
    
    print(f"Preprocessed {len(df)} events")
    
    return df

if __name__ == "__main__":
    # Load structured events
    df = pd.read_csv(r"C:\CTI_Pipeline\logs\structured_events.csv")
    
    # Preprocess
    df_processed = preprocess_dataset(df)
    
    # Save
    df_processed.to_csv(r"C:\CTI_Pipeline\logs\preprocessed_events.csv", index=False)
    print("\n=== Sample Preprocessed Events ===")
    print(df_processed[['event_id', 'image_name', 'command_line_cleaned']].head())
