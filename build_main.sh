#!/bin/bash

# Build and run script for multiparty key generation

echo "=========================================="
echo "Building Multiparty CKKS System"
echo "=========================================="

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Run CMake
echo ""
echo "Running CMake..."
cmake ..

if [ $? -ne 0 ]; then
    echo "CMake configuration failed!"
    exit 1
fi

# Build the project
echo ""
echo "Building project..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

cd ..

echo ""
echo "=========================================="
echo "Build completed successfully!"
echo "=========================================="
echo ""
echo "Available executables:"
echo "  ./main              - Main entry point (runs keygen by default)"
echo "  ./main keygen       - Generate multiparty keys"
echo "  ./main plaintext    - Compute plaintext similarity for comparison"
echo "  ./harness/create_key - Standalone key generator"
echo "  ./harness/plaintext_similarity - Standalone plaintext similarity"
echo ""
echo "To generate keys, run:"
echo "  ./main"
echo ""


