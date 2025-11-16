import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import OneHotEncoder
import pickle
from tqdm import tqdm

def load_embedding_model(model_name='sentence-transformers/all-MiniLM-L6-v2'):
    """Load pre-trained embedding model"""
    print(f"Loading embedding model: {model_name}")
    model = SentenceTransformer(model_name)
    return model

def generate_text_embeddings(texts, model, batch_size=32):
    """Generate embeddings for text data"""
    print(f"Generating embeddings for {len(texts)} texts...")
    
    # Convert to list and handle empty strings
    text_list = [str(t) if t else "unknown" for t in texts]
    
    # Generate embeddings in batches
    embeddings = model.encode(
        text_list,
        batch_size=batch_size,
        show_progress_bar=True,
        convert_to_numpy=True
    )
    
    return embeddings

def encode_categorical_features(df):
    """One-hot encode categorical features"""
    print("Encoding categorical features...")
    
    # Encode event_id
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    event_id_encoded = encoder.fit_transform(df[['event_id']])
    
    # Save encoder for later use
    with open(r"C:\CTI_Pipeline\models\event_id_encoder.pkl", 'wb') as f:
        pickle.dump(encoder, f)
    
    return event_id_encoded, encoder

def create_combined_vectors(text_embeddings, categorical_features):
    """Combine text embeddings with categorical features"""
    print("Combining feature vectors...")
    
    combined = np.hstack([text_embeddings, categorical_features])
    
    print(f"Created combined vectors of shape: {combined.shape}")
    return combined

if __name__ == "__main__":
    import os
    os.makedirs(r"C:\CTI_Pipeline\models", exist_ok=True)
    os.makedirs(r"C:\CTI_Pipeline\embeddings", exist_ok=True)
    
    # Load preprocessed data
    df = pd.read_csv(r"C:\CTI_Pipeline\logs\preprocessed_events.csv")
    
    print(f"Loaded {len(df)} events")
    
    # Load embedding model
    model = load_embedding_model()
    
    # Generate text embeddings
    text_embeddings = generate_text_embeddings(df['combined_text'].tolist(), model)
    
    # Encode categorical features
    categorical_encoded, encoder = encode_categorical_features(df)
    
    # Combine vectors
    final_vectors = create_combined_vectors(text_embeddings, categorical_encoded)
    
    # Save embeddings
    np.save(r"C:\CTI_Pipeline\embeddings\event_embeddings.npy", final_vectors)
    
    # Save metadata
    df[['event_id', 'timestamp', 'image_name', 'command_line_cleaned']].to_csv(
        r"C:\CTI_Pipeline\embeddings\event_metadata.csv", 
        index=False
    )
    
    print(f"\n Saved embeddings: {final_vectors.shape}")
    print(f"Embedding dimension: {final_vectors.shape[1]}")
