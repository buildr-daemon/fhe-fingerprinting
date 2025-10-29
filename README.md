# Homomorphic Maximum Similarity Search

A C++ implementation of secure maximum cosine similarity search using OpenFHE and the CKKS homomorphic encryption scheme.

## Overview

This project implements an **interactive protocol** for finding the maximum cosine similarity between an encrypted query vector and a set of encrypted storage vectors, without revealing the actual similarity scores or data to the server.

The solution uses a **double-blind comparison protocol** where:
- The compute server performs homomorphic operations
- An oracle (key holder) provides masked comparisons without seeing the actual values
- Both vectors remain encrypted throughout the process

---

## Key Components

### `final_main.cpp`

Implements a **parallel tournament-based maximum finding algorithm**:

1. **Key Generation**: Generates CKKS keys with rotation capabilities for efficient operations
2. **Vector Encryption**: Encrypts normalized query and storage vectors
3. **Similarity Computation**: Computes cosine similarities homomorphically via dot products
4. **Maximum Finding**: Uses a parallel tournament tree where:
   - Candidates compete in pairs using masked comparisons
   - Winner advances to the next round
   - Maintains both encrypted value and index
5. **Verification**: Compares results against plaintext computation

**CKKS Parameters**:
- Multiplicative depth: 20
- Scale mod size: 50
- Batch size: 1024
- Security level: 128-bit

### `data_synthesis.py`

Generates test datasets with unit-normalized vectors for cosine similarity.

**Default Configuration**:
- Storage vectors: `100 vectors × 512 dimensions`
- Query vector: `1 vector × 512 dimensions`
- Format: NumPy `.npy` files

**Customization**: Edit `generate_dataset()` to modify:
- `num_storage_vectors`: Number of storage vectors (default: 100)
- `dimension`: Vector dimensions (default: 512)

---

## Setup Instructions

### Prerequisites

- C++ compiler with C++17 support
- CMake (3.10+)
- OpenFHE 1.42.0 (bundled in `dependencies/openfhe-development/`)

### Build

```bash
# 1. Generate test data
python data_synthesis.py

# 2. Build the project
./build_main.sh

# Or manually:
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

**Note**: Update `CMakeLists.txt` with your OpenFHE library path if needed.

---

## Running

```bash
./final-main
```

The program will:
1. Generate CKKS keys
2. Load and encrypt vectors from `datasets/dataset_1/`
3. Compute cosine similarities homomorphically
4. Find maximum using parallel tournament
5. Decrypt and verify results

### Test Results

```
❯ ./final-main
╔════════════════════════════════════════╗
║    Interactive Max via Sequential      ║
║       Double-Blind Comparison          ║
╚════════════════════════════════════════╝

========================================
Generating CKKS Keys
========================================
✓ CryptoContext initialized
✓ Key pair generated
✓ Rotation keys generated (for EvalSum)

========================================
Loading and Encrypting Vectors
========================================
✓ All vectors loaded and encrypted

========================================
Computing Cosine Similarities
========================================
✓ All similarities computed

========================================
Finding Max via Parallel Tournament
========================================
  Tournament Round 1 | 100 candidates -> 50 winners
  Tournament Round 2 | 50 candidates -> 25 winners
  Tournament Round 3 | 25 candidates -> 13 winners
  Tournament Round 4 | 13 candidates -> 7 winners
  Tournament Round 5 | 7 candidates -> 4 winners
  Tournament Round 6 | 4 candidates -> 2 winners
  Tournament Round 7 | 2 candidates -> 1 winners
✓ Tournament finished.

========================================
Decrypting Results
========================================
✓ Decrypted maximum similarity: 0.0819815
✓ Decrypted maximum index: 53

========================================
Verification (Plaintext)
========================================
✓ Plaintext maximum similarity: 0.0819815
✓ Plaintext maximum index: 53

========================================
Result Comparison
========================================
Index match: ✓ YES
Value match: ✓ YES (diff: 4.08619e-12)

✓✓✓ ALL TESTS PASSED ✓✓✓
```

---

## Project Structure

```
├── final_main.cpp          # Main program with tournament-based max search
├── data_synthesis.py       # Dataset generation script
├── datasets/               # Generated test datasets
├── dependencies/           # OpenFHE library
├── build/                  # Build artifacts
└── CMakeLists.txt         # Build configuration
```

---

## Design Documentation

[Design Notes](https://www.notion.so/Mercle-Assignment-Design-notes-29644d413d1a801cba3bf7229fb322f5)

---

## Disclaimer

This was my first full C++ project, so the codebase may have rough edges. OpenFHE was chosen over the Python library due to API availability concerns.
