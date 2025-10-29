import numpy as np
import os
from pathlib import Path


def normalize_vectors(vectors):
    """
    Unit-normalize vectors (L2 normalization).
    
    Args:
        vectors: numpy array of shape (n, d) where n is number of vectors, d is dimension
    
    Returns:
        Unit-normalized vectors
    """
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    # Avoid division by zero
    norms = np.where(norms == 0, 1, norms)
    return vectors / norms


def generate_dataset(dataset_path, num_storage_vectors=10, dimension=512):
    """
    Generate a single dataset with storage vectors and query vector.
    
    Args:
        dataset_path: Path where the dataset will be saved
        num_storage_vectors: Number of storage vectors to generate (default: 1000)
        dimension: Dimension of vectors (default: 512)
    """
    # Create dataset directory if it doesn't exist
    os.makedirs(dataset_path, exist_ok=True)
    
    # Generate storage vectors: 1000 vectors of 512 dimensions
    storage_vectors = np.random.randn(num_storage_vectors, dimension).astype(np.float32)
    
    # Unit-normalize storage vectors
    storage_vectors = normalize_vectors(storage_vectors)
    
    # Generate query vector: single 512D vector
    query_vector = np.random.randn(dimension).astype(np.float32)
    
    # Unit-normalize query vector (required for cosine similarity via dot product)
    query_vector = query_vector / np.linalg.norm(query_vector)
    
    # Save as numpy files
    np.save(os.path.join(dataset_path, 'storage_vectors.npy'), storage_vectors)
    np.save(os.path.join(dataset_path, 'query_vector.npy'), query_vector)
    
    print(f"Generated dataset at {dataset_path}")
    print(f"  - Storage vectors shape: {storage_vectors.shape}, dtype: {storage_vectors.dtype}")
    print(f"  - Query vector shape: {query_vector.shape}, dtype: {query_vector.dtype}")
    print(f"  - Storage vectors normalized: {np.allclose(np.linalg.norm(storage_vectors, axis=1), 1.0)}")


def generate_all_datasets(num_datasets=10, base_path='datasets'):
    """
    Generate multiple datasets.
    
    Args:
        num_datasets: Number of datasets to generate (default: 10)
        base_path: Base directory where datasets will be stored (default: 'datasets')
    """
    print(f"Generating {num_datasets} datasets...")
    print("=" * 60)
    
    for i in range(1, num_datasets + 1):
        dataset_path = os.path.join(base_path, f'dataset_{i}')
        generate_dataset(dataset_path)
        print()
    
    print("=" * 60)
    print(f"Successfully generated {num_datasets} datasets in '{base_path}' folder")


if __name__ == '__main__':
    # Generate 10 datasets
    generate_all_datasets(num_datasets=10)
