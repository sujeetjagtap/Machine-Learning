import chromadb
from chromadb.config import Settings
import pandas as pd
import numpy as np
from datetime import datetime
import json

def initialize_chromadb(persist_directory="C:\\CTI_Pipeline\\vectordb"):
    """Initialize ChromaDB client"""
    print("Initializing ChromaDB...")
    
    client = chromadb.PersistentClient(
        path=persist_directory,
        settings=Settings(
            anonymized_telemetry=False,
            allow_reset=True
        )
    )
    
    return client

def create_collection(client, collection_name="sysmon_events"):
    """Create or get collection"""
    print(f"Creating collection: {collection_name}")
    
    # Delete if exists (for fresh start)
    try:
        client.delete_collection(name=collection_name)
    except:
        pass
    
    collection = client.create_collection(
        name=collection_name,
        metadata={"description": "SYSMON events with embeddings"}
    )
    
    return collection

def batch_insert_vectors(collection, embeddings, metadata_df, batch_size=1000):
    """Insert vectors in batches"""
    print(f"Inserting {len(embeddings)} vectors in batches of {batch_size}...")
    
    total_batches = (len(embeddings) + batch_size - 1) // batch_size
    
    for i in range(0, len(embeddings), batch_size):
        batch_end = min(i + batch_size, len(embeddings))
        batch_num = i // batch_size + 1
        
        print(f"Processing batch {batch_num}/{total_batches}...")
        
        # Prepare batch data
        batch_embeddings = embeddings[i:batch_end].tolist()
        batch_metadata = metadata_df.iloc[i:batch_end]
        
        # Create IDs
        ids = [f"event_{i+j}" for j in range(len(batch_embeddings))]
        
        # Create metadata dicts
        metadatas = []
        for idx, row in batch_metadata.iterrows():
            meta = {
                'event_id': str(row['event_id']),
                'timestamp': str(row['timestamp']),
                'image_name': str(row['image_name']) if pd.notna(row['image_name']) else '',
                'label': 'unlabeled'  # Will be updated in labeling phase
            }
            metadatas.append(meta)
        
        # Create documents (text representation for search)
        documents = [
            f"{row['image_name']} {row['command_line_cleaned']}"
            for _, row in batch_metadata.iterrows()
        ]
        
        # Insert batch
        collection.add(
            ids=ids,
            embeddings=batch_embeddings,
            metadatas=metadatas,
            documents=documents
        )
    
    print(f"Inserted {len(embeddings)} vectors successfully")

def create_index(collection):
    """ChromaDB automatically indexes, but we can verify"""
    count = collection.count()
    print(f"Collection contains {count} vectors")
    print(f"Index ready for similarity search")

if __name__ == "__main__":
    # Load embeddings and metadata
    embeddings = np.load(r"C:\CTI_Pipeline\embeddings\event_embeddings.npy")
    metadata_df = pd.read_csv(r"C:\CTI_Pipeline\embeddings\event_metadata.csv")
    
    print(f"Loaded {len(embeddings)} embeddings")
    
    # Initialize ChromaDB
    client = initialize_chromadb()
    
    # Create collection
    collection = create_collection(client)
    
    # Insert vectors
    batch_insert_vectors(collection, embeddings, metadata_df)
    
    # Verify index
    create_index(collection)
    
    # Test query
    print("\n=== Testing Similarity Search ===")
    results = collection.query(
        query_embeddings=[embeddings[0].tolist()],
        n_results=5
    )
    
    print("Top 5 similar events:")
    for i, (doc, meta) in enumerate(zip(results['documents'][0], results['metadatas'][0])):
        print(f"{i+1}. Event ID: {meta['event_id']}, Image: {meta['image_name']}")
