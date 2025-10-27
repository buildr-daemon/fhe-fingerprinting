<!-- f5c1f578-1915-42e6-a646-afb75215d40b 24e178d8-bed5-4cf3-94ff-f5d03c98362b -->
# Encrypted Vector Similarity Test with Ranking

## Overview

Transform the existing 3D vector test into a comprehensive 512-dimensional vector similarity test with 100 storage vectors, using homomorphic encryption to find the maximum similarity.

## Implementation Steps

### 1. Update Vector Generation (Lines 68-80, 106-119)

- Change `generateRandomVectors()` to generate 100 vectors with 512 dimensions
- Update `Vector3D` struct to support 512D vectors or replace with `std::vector<double>`
- Keep normalized plaintext copies alongside encrypted versions

### 2. Compute Plaintext Similarities (Lines 121-158)

- Calculate dot product between query and each of 100 storage vectors
- Find and store the maximum similarity and its index for comparison

### 3. Setup CKKS Parameters (Lines 160-202)

- Update `vectorLength = 100` (number of similarities)
- Increase `numSlots` to at least `100 * 100 = 10000` (use 16384, next power of 2)
- Adjust `multiplicativeDepth` based on operations needed:
- Dot product computation: ~log2(512) = 9 levels
- Ranking operations: 3-5 levels
- Indicator function: 2-3 levels
- Total: ~25-30 depth recommended
- Keep `compareDepth = 3` for ranking
- Generate crypto context and keys

### 4. Encrypt Vectors

- Encrypt all 100 storage vectors (512D each)
- Encrypt query vector (512D)
- Keep plaintext copies for verification

### 5. Compute Encrypted Cosine Similarities

Using manual dot product (not `EvalInnerProduct`):

- For each storage vector:
- Element-wise multiply with query: `EvalMult(storage[i], query)`
- Sum all 512 elements: use `EvalSum()` with rotation keys
- Result: ciphertext with 100 similarity values

### 6. Find Maximum Using Ranking (Lines 216-232)

- Apply `rankWithCorrection()` to encrypted similarities
- Use `indicator()` function to create mask for maximum (rank = 100)
- `indicator(ranks, 99.5, 100.5, 0.5, 100.5, degreeI)`
- Multiply mask with similarities: `EvalMult(mask, similarities)`
- Sum to extract single maximum value: `EvalSum(masked_similarities)`

### 7. Decrypt and Compare (Lines 240-320)

- Decrypt only the extracted maximum value
- Compare with plaintext maximum
- Calculate and report error

## Key Files

- `/Users/theholygrail/job-search/merkel-assignment/ranking_test/ranking_test.cpp`

## Key Functions to Use

- `rankWithCorrection()` from `ranking.h`
- `indicator()` from `utils-eval.h` 
- `EvalMult()`, `EvalSum()` from OpenFHE
- Manual dot product implementation with rotation-based sum

### To-dos

- [ ] Replace Vector3D with 512D vector structure and update generation functions
- [ ] Generate 100 storage vectors (512D) and 1 query vector, all unit-normalized
- [ ] Compute plaintext cosine similarities and find maximum
- [ ] Update CKKS parameters for 512D vectors and 100 similarities
- [ ] Encrypt all 100 storage vectors and query vector
- [ ] Implement encrypted dot product computation for all 100 pairs
- [ ] Use rankWithCorrection + indicator to extract maximum similarity in encrypted form
- [ ] Decrypt only the maximum value and compare with plaintext result