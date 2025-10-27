//==================================================================================
// Ranking Test for 512D Vector Cosine Similarity
// 
// This program demonstrates:
// 1. Generation and normalization of 100 512D storage vectors and 1 query vector
// 2. Cosine similarity computation in plaintext
// 3. Cosine similarity computation using homomorphic encryption (OpenFHE CKKS)
// 4. Finding maximum similarity using encrypted ranking
// 5. Comparison of plaintext vs encrypted results
//==================================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <iomanip>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <iterator>
#ifdef _OPENMP
#include <omp.h>
#endif

// OpenFHE includes
#include "openfhe.h"

// openfhe-statistics includes
#include "ranking.h"
#include "utils-basics.h"
#include "utils-eval.h"
#include "utils-matrices.h"
#include "utils-ptxt.h"

using namespace lbcrypto;

// Generate random N-dimensional vectors
std::vector<double> generateRandomVector(size_t dim, unsigned int seed) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<double> dis(-10.0, 10.0);
    
    std::vector<double> vec(dim);
    for (size_t i = 0; i < dim; ++i) {
        vec[i] = dis(gen);
    }
    
    // Normalize to unit length
    double magnitude = 0.0;
    for (size_t i = 0; i < dim; ++i) {
        magnitude += vec[i] * vec[i];
    }
    magnitude = std::sqrt(magnitude);
    
    if (magnitude > 1e-10) {
        for (size_t i = 0; i < dim; ++i) {
            vec[i] /= magnitude;
        }
    }
    
    return vec;
}

// Compute dot product (cosine similarity for unit vectors)
double dotProduct(const std::vector<double>& a, const std::vector<double>& b) {
    assert(a.size() == b.size());
    double result = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

// Print header
void printHeader() {
    std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   512D Vector Cosine Similarity with Encrypted Ranking   ║" << std::endl;
    std::cout << "║   Using rankWithCorrection with OpenFHE CKKS              ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
}

int main() {
    printHeader();
    
    const size_t numStorageVectors = 100;
    const size_t vectorDim = 512;
    
    // Step 1: Generate storage vectors and query vector
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 1: Generate and Normalize Vectors" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<std::vector<double>> storageVectors;
    for (size_t i = 0; i < numStorageVectors; ++i) {
        storageVectors.push_back(generateRandomVector(vectorDim, 42 + i));
    }
    
    std::vector<double> queryVector = generateRandomVector(vectorDim, 123);
    
    std::cout << "✓ Generated " << numStorageVectors << " storage vectors (" << vectorDim << "D each)" << std::endl;
    std::cout << "✓ Generated 1 query vector (" << vectorDim << "D)" << std::endl;
    
    // Step 2: Compute plaintext cosine similarities
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 2: Plaintext Cosine Similarity" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<double> plaintextSimilarities;
    for (size_t i = 0; i < storageVectors.size(); ++i) {
        double sim = dotProduct(queryVector, storageVectors[i]);
        plaintextSimilarities.push_back(sim);
    }
    
    // Find plaintext maximum
    size_t plaintextMaxIdx = std::distance(plaintextSimilarities.begin(),
                                           std::max_element(plaintextSimilarities.begin(),
                                                           plaintextSimilarities.end()));
    double plaintextMax = plaintextSimilarities[plaintextMaxIdx];
    
    std::cout << "\nPlaintext Maximum:" << std::endl;
    std::cout << "  Vector index: " << plaintextMaxIdx << std::endl;
    std::cout << "  Similarity: " << std::fixed << std::setprecision(6) << plaintextMax << std::endl;
    
    // Show top 5 similarities
    std::cout << "\nTop 5 Similarities:" << std::endl;
    std::vector<size_t> sortedIndices(plaintextSimilarities.size());
    for (size_t i = 0; i < sortedIndices.size(); ++i) sortedIndices[i] = i;
    std::sort(sortedIndices.begin(), sortedIndices.end(), 
              [&](size_t a, size_t b) { return plaintextSimilarities[a] > plaintextSimilarities[b]; });
    for (size_t i = 0; i < std::min(5UL, sortedIndices.size()); ++i) {
        std::cout << "  " << i+1 << ". Vector " << sortedIndices[i] << ": " 
                  << std::fixed << std::setprecision(6) << plaintextSimilarities[sortedIndices[i]] << std::endl;
    }
    
    // Step 3: Setup CKKS and encrypt
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 3: CKKS Encryption Setup" << std::endl;
    std::cout << "========================================" << std::endl;
    
    const size_t similarityVectorLength = numStorageVectors;  // Number of similarity values
    const usint compareDepth = 5;
    const usint integralPrecision = 1;
    const usint decimalPrecision = 50;  // Higher precision for 512D vectors
    const usint multiplicativeDepth = 20;  // Increased for dot product + ranking
    // numSlots needs to be >= similarityVectorLength^2 for matrix operations
    // For 100 similarities, we need at least 10000, use 16384
    const usint numSlots = 16384;
    const bool enableBootstrap = false;
    const usint ringDim = 0;
    const bool verbose = true;
    
    std::cout << "\nCryptoContext Parameters:" << std::endl;
    std::cout << "  Similarity vector length: " << similarityVectorLength << std::endl;
    std::cout << "  Comparison depth: " << compareDepth << std::endl;
    std::cout << "  Multiplicative depth: " << multiplicativeDepth << std::endl;
    std::cout << "  Num slots: " << numSlots << std::endl;
    
    // Generate rotation indices for the dot product (need shifts up to vectorDim for 512D vectors)
    std::cout << "\nGenerating rotation indices..." << std::endl;
    std::vector<int32_t> indices;
    
    // Add all rotations needed for packing (0 to similarityVectorLength-1)
    for (size_t i = 0; i < similarityVectorLength; ++i) {
        indices.push_back(static_cast<int32_t>(i));
        indices.push_back(-static_cast<int32_t>(i));  // Both directions
    }
    
    // Add log2 shifts for dot product summation (1, 2, 4, 8, 16, 32, 64, 128, 256)
    for (int shift = 1; shift < vectorDim; shift *= 2) {
        indices.push_back(shift);
        indices.push_back(-shift);
    }
    
    // Also add rotation indices for ranking operations
    std::vector<int32_t> rankingIndices = getRotationIndices(similarityVectorLength);
    for (int32_t idx : rankingIndices) {
        if (std::find(indices.begin(), indices.end(), idx) == indices.end()) {
            indices.push_back(idx);
        }
    }
    
    std::cout << "  Generated " << indices.size() << " rotation indices" << std::endl;
    
    CryptoContext<DCRTPoly> cryptoContext = generateCryptoContext(
        integralPrecision,
        decimalPrecision,
        multiplicativeDepth,
        numSlots,
        enableBootstrap,
        ringDim,
        verbose
    );
    
    KeyPair<DCRTPoly> keyPair = keyGeneration(
        cryptoContext,
        indices,
        numSlots,
        enableBootstrap,
        verbose
    );
    
    // Step 4: Encrypt storage vectors and query vector
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 4: Encrypt Vectors" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<Ciphertext<DCRTPoly>> encryptedStorageVectors;
    for (size_t i = 0; i < storageVectors.size(); ++i) {
        // Pad vector to numSlots size
        std::vector<double> padded = storageVectors[i];
        padded.resize(numSlots, 0.0);
        Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(padded);
        Ciphertext<DCRTPoly> ct = cryptoContext->Encrypt(keyPair.publicKey, pt);
        encryptedStorageVectors.push_back(ct);
    }
    
    // Encrypt query vector
    std::vector<double> paddedQuery = queryVector;
    paddedQuery.resize(numSlots, 0.0);
    Plaintext queryPlaintext = cryptoContext->MakeCKKSPackedPlaintext(paddedQuery);
    Ciphertext<DCRTPoly> encryptedQuery = cryptoContext->Encrypt(keyPair.publicKey, queryPlaintext);
    
    std::cout << "✓ Encrypted " << numStorageVectors << " storage vectors" << std::endl;
    std::cout << "✓ Encrypted query vector" << std::endl;
    
    // Step 5: Compute encrypted cosine similarities (dot products)
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 5: Compute Encrypted Dot Products" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<Ciphertext<DCRTPoly>> encryptedSimilarities;
    
    std::cout << "Computing encrypted dot products for " << encryptedStorageVectors.size() << " vectors..." << std::endl;
    
    for (size_t i = 0; i < encryptedStorageVectors.size(); ++i) {
        // Element-wise multiply storage vector with query
        Ciphertext<DCRTPoly> product = cryptoContext->EvalMult(encryptedStorageVectors[i], encryptedQuery);
        
        // Sum all 512 elements using rotation
        // Rotate and add: sum = x0 + x1 + x2 + ... + x511
        Ciphertext<DCRTPoly> sum = product;
        for (size_t shift = 1; shift < vectorDim; shift *= 2) {
            auto rotated = cryptoContext->EvalRotate(sum, shift);
            sum = cryptoContext->EvalAdd(sum, rotated);
        }
        
        encryptedSimilarities.push_back(sum);
        
        if ((i + 1) % 10 == 0 || i == 0) {
            std::cout << "  Processed " << (i + 1) << "/" << encryptedStorageVectors.size() << " vectors" << std::endl;
        }
    }
    
    std::cout << "✓ Computed encrypted similarities" << std::endl;
    
    // Now we need to pack all individual similarities (from slot 0 of each ciphertext) 
    // into a single ciphertext for ranking. Since each similarity is in slot 0 and others are zeros,
    // we'll combine them by rotating and adding
    std::cout << "Packing similarities into single ciphertext..." << std::endl;
    
    Ciphertext<DCRTPoly> packedSimilarities;
    for (size_t i = 0; i < encryptedSimilarities.size(); ++i) {
        // Rotate similarity from slot 0 to slot i
        Ciphertext<DCRTPoly> rotated = cryptoContext->EvalRotate(encryptedSimilarities[i], static_cast<int32_t>(i));
        
        if (i == 0) {
            packedSimilarities = rotated;
        } else {
            packedSimilarities = cryptoContext->EvalAdd(packedSimilarities, rotated);
        }
    }
    
    std::cout << "✓ Packed similarities into single ciphertext" << std::endl;
    
    // Step 6: Perform encrypted ranking and find maximum
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 6: Encrypted Ranking and Maximum Extraction" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << "\n[Algorithm] rankWithCorrection + indicator for maximum" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Compute ranks
    Ciphertext<DCRTPoly> encryptedRanks = rankWithCorrection(
        packedSimilarities,
        similarityVectorLength,
        -1.0, 1.0,  // Bounds for cosine similarity range
        depth2degree(compareDepth),
        false  // Not using parallel mode
    );
    
    std::cout << "  ✓ Ranked similarities" << std::endl;
    
    // Create indicator mask for maximum (rank should be highest = similarityVectorLength)
    const double indicatorDegree =9;
    Ciphertext<DCRTPoly> maxMask = indicator(
        encryptedRanks,
        0.5, similarityVectorLength + 0.5,
        similarityVectorLength - 10.0, similarityVectorLength + 10.0,
        static_cast<uint32_t>(indicatorDegree)
    );
    
    std::cout << "  ✓ Created maximum indicator mask" << std::endl;
    
    // Multiply similarity vector by mask to extract maximum
    Ciphertext<DCRTPoly> maskedSimilarities = cryptoContext->EvalMult(maxMask, packedSimilarities);
    
    // Sum to get single maximum value (all non-maximum slots become zero)
    Ciphertext<DCRTPoly> encryptedMax = cryptoContext->EvalSum(maskedSimilarities, similarityVectorLength);
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    
    std::cout << "✓ Encrypted maximum extraction completed" << std::endl;
    std::cout << "  Runtime: " << elapsed_seconds.count() << " seconds" << std::endl;
    
    // Step 7: Decrypt results
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 7: Decrypt and Compare" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Decrypt packed similarities for verification
    Plaintext decryptedPacked;
    cryptoContext->Decrypt(keyPair.secretKey, packedSimilarities, &decryptedPacked);
    decryptedPacked->SetLength(similarityVectorLength);
    std::vector<double> decryptedSimilarities = decryptedPacked->GetRealPackedValue();
    
    // Decrypt ranks for verification
    Plaintext decryptedRanksPT;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedRanks, &decryptedRanksPT);
    decryptedRanksPT->SetLength(similarityVectorLength);
    std::vector<double> decryptedRanks = decryptedRanksPT->GetRealPackedValue();
    
    std::cout << "\nEncrypted Similarities (decrypted, top 10):" << std::endl;
    std::cout << std::fixed << std::setprecision(6);
    for (size_t i = 0; i < std::min(10UL, decryptedSimilarities.size()); ++i) {
        std::cout << "  Vector " << i << ": " << decryptedSimilarities[i] 
                  << " (rank: " << std::setprecision(2) << decryptedRanks[i] << ")" << std::endl;
    }
    
    // Decrypt only the extracted maximum value
    Plaintext decryptedMaxPT;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedMax, &decryptedMaxPT);
    decryptedMaxPT->SetLength(1);
    std::vector<double> decryptedMaxVec = decryptedMaxPT->GetRealPackedValue();
    double encryptedMaxValue = decryptedMaxVec[0];
    
    std::cout << "\nEncrypted Maximum (decrypted):" << std::endl;
    std::cout << "  Similarity: " << std::setprecision(6) << encryptedMaxValue << std::endl;
    
    // Step 8: Final comparison
    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 8: Final Comparison" << std::endl;
    std::cout << "========================================" << std::endl;
    
    double error = std::abs(plaintextMax - encryptedMaxValue);
    
    std::cout << "\nMaximum Similarity Comparison:" << std::endl;
    std::cout << "  Plaintext Max (Vector " << plaintextMaxIdx << "): " 
              << std::setprecision(6) << plaintextMax << std::endl;
    std::cout << "  Encrypted Max (decrypted): " << encryptedMaxValue << std::endl;
    std::cout << "  Absolute Error: " << error << std::endl;
    std::cout << "  Relative Error: " << std::setprecision(4) 
              << (error / std::max(std::abs(plaintextMax), 1e-10)) * 100 << "%" << std::endl;
    
    // Verify similarity accuracy
    bool match = (error < 1e-4);  // Small tolerance for floating point
    std::cout << "  Match within tolerance: " << (match ? "✓ YES" : "✗ NO") << std::endl;
    
    // Print error summary for similarities
    std::cout << "\nSimilarity Error Summary (first 10 vectors):" << std::endl;
    double maxError = 0.0;
    double avgError = 0.0;
    for (size_t i = 0; i < std::min(10UL, plaintextSimilarities.size()); ++i) {
        double simError = std::abs(plaintextSimilarities[i] - decryptedSimilarities[i]);
        maxError = std::max(maxError, simError);
        avgError += simError;
        std::cout << "  Vector " << i << ": error=" << std::setprecision(8) << simError << std::endl;
    }
    avgError /= std::min(10UL, plaintextSimilarities.size());
    
    std::cout << "\nOverall Statistics:" << std::endl;
    std::cout << "  Max similarity error (first 10): " << std::setprecision(8) << maxError << std::endl;
    std::cout << "  Average similarity error (first 10): " << avgError << std::endl;
    
    if (match) {
        std::cout << "\n✓ SUCCESS: Encrypted result matches plaintext within tolerance!" << std::endl;
    } else {
        std::cout << "\n✗ WARNING: Significant error detected between plaintext and encrypted results" << std::endl;
    }
    
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                    Test Complete!                           ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    return 0;
}

