#!/bin/bash

# Build and run the ranking_test program

echo "========================================="
echo "Building ranking_test program..."
echo "========================================="

# Check if we're in the right directory
if [ ! -f "ranking_test.cpp" ]; then
    echo "Error: ranking_test.cpp not found. Please run from ranking_test/ directory"
    exit 1
fi

# Find cmake
CMAKE=""
if command -v cmake &> /dev/null; then
    CMAKE=cmake
elif [ -f "/usr/local/bin/cmake" ]; then
    CMAKE="/usr/local/bin/cmake"
elif [ -f "/opt/homebrew/bin/cmake" ]; then
    CMAKE="/opt/homebrew/bin/cmake"
else
    echo "Error: cmake not found. Please install cmake or update the path in this script."
    exit 1
fi

echo "Using cmake: $CMAKE"

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

# Run CMake
echo "Running CMake..."
$CMAKE ..

# Check if CMake succeeded
if [ $? -ne 0 ]; then
    echo "CMake failed! Please check the error messages above."
    exit 1
fi

# Build the project
echo "Building project..."
make -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4)

cd ..

# Check if build was successful
if [ -f "ranking_test" ]; then
    echo ""
    echo "========================================="
    echo "Build successful! Running program..."
    echo "========================================="
    echo ""
    ./ranking_test
else
    echo ""
    echo "Build failed! Please check the error messages above."
    exit 1
fi
