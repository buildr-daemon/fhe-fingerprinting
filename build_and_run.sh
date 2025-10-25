#!/bin/bash

# Build and run the understanding_ckks program

echo "========================================="
echo "Building understanding_ckks program..."
echo "========================================="

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

# Run CMake
echo "Running CMake..."
cmake ..

# Build the project
echo "Building project..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

cd ..

# Check if build was successful
if [ -f "understanding_ckks" ]; then
    echo ""
    echo "========================================="
    echo "Build successful! Running program..."
    echo "========================================="
    echo ""
    ./understanding_ckks
else
    echo ""
    echo "Build failed! Please check the error messages above."
    exit 1
fi


