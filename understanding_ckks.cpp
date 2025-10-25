//==================================================================================
// Cosine Similarity Computation: Plaintext vs Encrypted (CKKS)
// 
// This program demonstrates:
// 1. Generation and normalization of 3D vectors
// 2. Cosine similarity computation in plaintext
// 3. Cosine similarity computation using homomorphic encryption (OpenFHE CKKS)
//==================================================================================

#include <iostream>
#include <vector>
#include <fstream>
#include <cmath>
#include <random>
#include <iomanip>
#include "openfhe.h"

using namespace lbcrypto;

// Structure to hold a 3D vector
struct Vector3D {
    float x, y, z;
    
    Vector3D(float x = 0, float y = 0, float z = 0) : x(x), y(y), z(z) {}
    
    // Compute magnitude
    float magnitude() const {
        return std::sqrt(x*x + y*y + z*z);
    }
    
    // Unit normalize the vector
    void normalize() {
        float mag = magnitude();
        if (mag > 0.0f) {
            x /= mag;
            y /= mag;
            z /= mag;
        }
    }
    
    // Convert to std::vector<double> for CKKS
    std::vector<double> toVector() const {
        return {static_cast<double>(x), static_cast<double>(y), static_cast<double>(z)};
    }
    
    // Compute dot product (which equals cosine similarity for normalized vectors)
    float dot(const Vector3D& other) const {
        return x * other.x + y * other.y + z * other.z;
    }
};

// Generate random 3D vectors
std::vector<Vector3D> generateRandomVectors(int count, unsigned int seed = 42) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<float> dis(-10.0f, 10.0f);
    
    std::vector<Vector3D> vectors;
    for (int i = 0; i < count; ++i) {
        Vector3D vec(dis(gen), dis(gen), dis(gen));
        vec.normalize();  // Unit normalize
        vectors.push_back(vec);
    }
    
    return vectors;
}

// Save vectors to CSV file
void saveVectorsToCSV(const std::vector<Vector3D>& vectors, const std::string& filename) {
    std::ofstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return;
    }
    
    // Write header
    file << "x,y,z,magnitude\n";
    
    // Write vectors with high precision
    file << std::fixed << std::setprecision(8);
    for (const auto& vec : vectors) {
        file << vec.x << "," << vec.y << "," << vec.z << "," << vec.magnitude() << "\n";
    }
    
    file.close();
    std::cout << "Vectors saved to " << filename << std::endl;
}

// Plaintext cosine similarity computation
void plaintextCosineSimilarity(const Vector3D& query, const std::vector<Vector3D>& dataset) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "PLAINTEXT COSINE SIMILARITY" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "\nQuery Vector (normalized): [" << query.x << ", " << query.y << ", " << query.z << "]" << std::endl;
    std::cout << "Query magnitude: " << query.magnitude() << std::endl;
    
    std::cout << "\nCosine Similarities:" << std::endl;
    for (size_t i = 0; i < dataset.size(); ++i) {
        float similarity = query.dot(dataset[i]);
        std::cout << "Vector " << i << ": " << similarity << std::endl;
    }
}

// Encrypted cosine similarity computation using OpenFHE CKKS
void encryptedCosineSimilarity(const Vector3D& query, const std::vector<Vector3D>& dataset) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "ENCRYPTED COSINE SIMILARITY (CKKS)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Step 1: Setup CryptoContext
    uint32_t multDepth = 3;  // We need depth for multiplication
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 8;  // We only need 3 elements, but minimum batch size helps
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    
    // Enable features
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    
    std::cout << "\nCKKS scheme using ring dimension: " << cryptoContext->GetRingDimension() << std::endl;
    
    // Step 2: Key Generation
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);  // For inner product
    
    std::cout << "Keys generated successfully" << std::endl;
    
    // Step 3: Encode and encrypt query vector
    std::vector<double> queryVec = query.toVector();
    Plaintext queryPlaintext = cryptoContext->MakeCKKSPackedPlaintext(queryVec);
    auto queryEncrypted = cryptoContext->Encrypt(keyPair.publicKey, queryPlaintext);
    
    std::cout << "Query vector encrypted" << std::endl;
    
    // Step 4: Compute cosine similarities (dot products for normalized vectors)
    std::cout << "\nComputing encrypted cosine similarities..." << std::endl;
    std::cout << std::fixed << std::setprecision(6);
    
    for (size_t i = 0; i < dataset.size(); ++i) {
        // Encrypt the dataset vector
        std::vector<double> dataVec = dataset[i].toVector();
        Plaintext dataPlaintext = cryptoContext->MakeCKKSPackedPlaintext(dataVec);
        auto dataEncrypted = cryptoContext->Encrypt(keyPair.publicKey, dataPlaintext);
        
        // Compute encrypted inner product (cosine similarity for normalized vectors)
        // For dot product: multiply element-wise, then sum
        auto product = cryptoContext->EvalMult(queryEncrypted, dataEncrypted);
        
        // Sum the elements to get the dot product
        auto dotProductEncrypted = cryptoContext->EvalSum(product, batchSize);
        
        // Decrypt the result
        Plaintext resultPlaintext;
        cryptoContext->Decrypt(keyPair.secretKey, dotProductEncrypted, &resultPlaintext);
        resultPlaintext->SetLength(1);
        
        // Extract the similarity value
        auto resultVec = resultPlaintext->GetCKKSPackedValue();
        double encryptedSimilarity = resultVec[0].real();
        
        // Also compute plaintext for comparison
        double plaintextSimilarity = query.dot(dataset[i]);
        double error = std::abs(encryptedSimilarity - plaintextSimilarity);
        
        std::cout << "Vector " << i << ": " 
                  << encryptedSimilarity 
                  << " (plaintext: " << plaintextSimilarity 
                  << ", error: " << error << ")" << std::endl;
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Cosine Similarity: Plaintext vs Encrypted" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Step 1: Generate 10 random 3D vectors and normalize them
    std::cout << "\nGenerating 10 random 3D vectors..." << std::endl;
    std::vector<Vector3D> dataset = generateRandomVectors(10);
    
    // Save to CSV
    saveVectorsToCSV(dataset, "normalized_vectors.csv");
    
    // Step 2: Generate a query vector and normalize it
    std::cout << "\nGenerating query vector..." << std::endl;
    std::mt19937 gen(123);  // Different seed for query
    std::uniform_real_distribution<float> dis(-10.0f, 10.0f);
    Vector3D query(dis(gen), dis(gen), dis(gen));
    
    std::cout << "Query Vector (before normalization): [" 
              << query.x << ", " << query.y << ", " << query.z << "]" << std::endl;
    
    query.normalize();
    
    std::cout << "Query Vector (after normalization): [" 
              << query.x << ", " << query.y << ", " << query.z << "]" 
              << " (magnitude: " << query.magnitude() << ")" << std::endl;
    
    // Save query to CSV
    std::vector<Vector3D> queryVec = {query};
    saveVectorsToCSV(queryVec, "query_vector.csv");
    
    // Step 3: Compute cosine similarity in plaintext
    plaintextCosineSimilarity(query, dataset);
    
    // Step 4: Compute cosine similarity with encryption
    encryptedCosineSimilarity(query, dataset);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Computation Complete!" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}

