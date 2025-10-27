# Ranking Test for 3D Vector Cosine Similarity

This standalone test demonstrates encrypted ranking of cosine similarities using OpenFHE CKKS and the ranking functions from `openfhe-statistics`.

## Overview

The test:
1. Generates 10 random 3D storage vectors and 1 query vector
2. Normalizes all vectors to unit length
3. Computes cosine similarities in plaintext
4. Encrypts the similarities using CKKS
5. Uses `rankWithCorrection()` to rank the encrypted similarities
6. Decrypts and compares the results with plaintext

## Requirements

- OpenFHE library (must be built in `../dependencies/openfhe-development/build`)
- CMake 3.10 or higher
- C++ compiler with C++17 support
- Make
- OpenMP (for parallel processing in ranking functions)

## Building

From the `ranking_test/` directory:

```bash
./build_test.sh
```

This will:
1. Create a `build/` directory
2. Run CMake to configure the project
3. Build the `ranking_test` executable
4. Run the test

Alternatively, build manually:

```bash
mkdir -p build
cd build
cmake ..
make
cd ..
./ranking_test
```

## Troubleshooting

### CMake Not Found

If you get "cmake: command not found", try:

1. Install cmake via Homebrew (if on macOS):
   ```bash
   brew install cmake
   ```

2. Or update the path in `build_test.sh` to point to your cmake installation

3. Or use the full path to cmake when building:
   ```bash
   /usr/local/bin/cmake ..  # or wherever cmake is installed
   ```

### OpenMP Not Found

The ranking functions require OpenMP. If you get OpenMP errors:

1. Install OpenMP via Homebrew (if on macOS):
   ```bash
   brew install libomp
   ```

2. The CMakeLists.txt is configured to find OpenMP automatically

### Clean Build

If you encounter build issues, try a clean build:

```bash
cd ranking_test
rm -rf build
./build_test.sh
```

## Output

The test produces detailed output including:
- All generated vectors and their normalizations
- Plaintext cosine similarities and their ranks
- Encrypted similarities and their decrypted ranks
- Comparison showing which vector has maximum similarity
- Error analysis comparing plaintext vs encrypted results

## Files

- `ranking_test.cpp` - Main test implementation
- `CMakeLists.txt` - Build configuration
- `build_test.sh` - Automated build and run script
- `README.md` - This file

## Dependencies

The test uses utilities from `../resources/openfhe-statistics/src/`:
- `ranking.cpp` - Ranking functions
- `utils-basics.cpp` - Crypto context and key generation
- `utils-eval.cpp` - Evaluation utilities (depth2degree)
- `utils-matrices.cpp` - Matrix operations for ranking
- `utils-ptxt.cpp` - Plaintext utilities

## Notes

- Uses fixed random seeds (42 for storage vectors, 123 for query) for reproducibility
- Performs fractional ranking with tie correction
- The test is completely isolated from the main project
