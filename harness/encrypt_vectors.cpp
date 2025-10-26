//==================================================================================
// Vector Encryption Module
// 
// This program:
// 1. Loads the joint public key
// 2. Reads numpy arrays (storage + query vectors)
// 3. Encrypts each 512-D vector into a CKKS ciphertext
// 4. Saves encrypted vectors to disk
//==================================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cstring>
#include <numeric>
#include <cmath>
#include "openfhe.h"

// Serialization includes
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

// Simple NPY file reader for float32 arrays
class NPYReader {
public:
    static std::vector<float> readNPY(const std::string& filename, size_t& numVectors, size_t& dimension) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }
        
        // Read magic string (6 bytes)
        char magic[6];
        file.read(magic, 6);
        
        // Read version (2 bytes)
        uint8_t major, minor;
        file.read(reinterpret_cast<char*>(&major), 1);
        file.read(reinterpret_cast<char*>(&minor), 1);
        
        // Read header length (2 or 4 bytes depending on version)
        uint16_t headerLen = 0;
        if (major == 1) {
            file.read(reinterpret_cast<char*>(&headerLen), 2);
        } else if (major >= 2) {
            uint32_t headerLen32;
            file.read(reinterpret_cast<char*>(&headerLen32), 4);
            headerLen = static_cast<uint16_t>(headerLen32);
        }
        
        // Read header (Python dict as string)
        std::vector<char> headerBuf(headerLen);
        file.read(headerBuf.data(), headerLen);
        std::string header(headerBuf.begin(), headerBuf.end());
        
        // Parse shape from header
        // Header format: "{'descr': '<f4', 'fortran_order': False, 'shape': (1000, 512), }"
        size_t shapePos = header.find("'shape': (");
        if (shapePos == std::string::npos) {
            shapePos = header.find("\"shape\": (");
        }
        
        if (shapePos != std::string::npos) {
            size_t start = shapePos + 10;
            size_t end = header.find(")", start);
            std::string shapeStr = header.substr(start, end - start);
            
            // Remove whitespace
            shapeStr.erase(std::remove_if(shapeStr.begin(), shapeStr.end(), ::isspace), shapeStr.end());
            
            // Parse shape tuple
            size_t comma = shapeStr.find(",");
            if (comma != std::string::npos) {
                std::string firstDim = shapeStr.substr(0, comma);
                std::string secondDim = shapeStr.substr(comma + 1);
                
                // Remove any trailing commas or other non-numeric characters
                secondDim.erase(std::remove_if(secondDim.begin(), secondDim.end(), 
                    [](char c) { return !std::isdigit(c); }), secondDim.end());
                
                if (secondDim.empty()) {
                    // 1D array: (dimension,)
                    numVectors = 1;
                    dimension = std::stoull(firstDim);
                } else {
                    // 2D array: (numVectors, dimension)
                    numVectors = std::stoull(firstDim);
                    dimension = std::stoull(secondDim);
                }
            } else {
                // 1D array without trailing comma: (dimension)
                numVectors = 1;
                dimension = std::stoull(shapeStr);
            }
        }
        
        // Read data
        size_t numElements = numVectors * dimension;
        std::vector<float> data(numElements);
        file.read(reinterpret_cast<char*>(data.data()), numElements * sizeof(float));
        
        return data;
    }
};

class VectorEncryptor {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    PublicKey<DCRTPoly> jointPublicKey;
    std::string encryptedDataPath;
    
public:
    VectorEncryptor(const std::string& outputPath = "encrypted_data") 
        : encryptedDataPath(outputPath) {
        fs::create_directories(encryptedDataPath);
    }
    
    // Load crypto context and joint public key
    void loadKeys(const std::string& userPath = "users/user1") {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Loading Crypto Context and Keys" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Load crypto context
        std::string ccPath = userPath + "/cryptocontext.txt";
        if (!Serial::DeserializeFromFile(ccPath, cryptoContext, SerType::BINARY)) {
            throw std::runtime_error("Failed to load crypto context from: " + ccPath);
        }
        std::cout << "✓ Crypto context loaded" << std::endl;
        std::cout << "  Ring Dimension: " << cryptoContext->GetRingDimension() << std::endl;
        std::cout << "  Batch Size: " << cryptoContext->GetEncodingParams()->GetBatchSize() << std::endl;
        
        // Load joint public key
        std::string pkPath = userPath + "/joint_public_key.txt";
        if (!Serial::DeserializeFromFile(pkPath, jointPublicKey, SerType::BINARY)) {
            throw std::runtime_error("Failed to load joint public key from: " + pkPath);
        }
        std::cout << "✓ Joint public key loaded" << std::endl;
    }
    
    // Encrypt a single vector
    Ciphertext<DCRTPoly> encryptVector(const std::vector<double>& vector) {
        Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vector);
        return cryptoContext->Encrypt(jointPublicKey, plaintext);
    }
    
    // Encrypt storage vectors from numpy file
    void encryptStorageVectors(const std::string& datasetPath) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Encrypting Storage Vectors" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::string npyPath = datasetPath + "/storage_vectors.npy";
        
        // Read numpy array
        size_t numVectors, dimension;
        std::vector<float> data = NPYReader::readNPY(npyPath, numVectors, dimension);
        
        std::cout << "\n[Dataset] Loaded storage vectors" << std::endl;
        std::cout << "  Number of vectors: " << numVectors << std::endl;
        std::cout << "  Dimension: " << dimension << std::endl;
        std::cout << "  Total elements: " << data.size() << std::endl;
        
        // Encrypt each vector
        std::cout << "\n[Encryption] Processing vectors..." << std::endl;
        for (size_t i = 0; i < numVectors; ++i) {
            // Extract vector i
            std::vector<double> vec(dimension);
            for (size_t j = 0; j < dimension; ++j) {
                vec[j] = static_cast<double>(data[i * dimension + j]);
            }
            
            // Encrypt
            auto ciphertext = encryptVector(vec);
            
            // Save to disk
            std::string filename = encryptedDataPath + "/storage_" + std::to_string(i) + ".bin";
            if (!Serial::SerializeToFile(filename, ciphertext, SerType::BINARY)) {
                throw std::runtime_error("Failed to save ciphertext: " + filename);
            }
            
            if ((i + 1) % 100 == 0 || i == 0 || i == numVectors - 1) {
                std::cout << "  Encrypted " << (i + 1) << "/" << numVectors << " vectors" << std::endl;
            }
        }
        
        std::cout << "✓ All storage vectors encrypted and saved" << std::endl;
    }
    
    // Normalize vector to unit length
    std::vector<double> normalizeVector(const std::vector<double>& vec) {
        double norm = 0.0;
        for (double val : vec) {
            norm += val * val;
        }
        norm = std::sqrt(norm);
        
        if (norm == 0.0) {
            throw std::runtime_error("Cannot normalize zero vector");
        }
        
        std::vector<double> normalized(vec.size());
        for (size_t i = 0; i < vec.size(); ++i) {
            normalized[i] = vec[i] / norm;
        }
        
        return normalized;
    }
    
    // Encrypt query vector from numpy file
    void encryptQueryVector(const std::string& datasetPath) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Encrypting Query Vector" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::string npyPath = datasetPath + "/query_vector.npy";
        
        // Read numpy array
        size_t numVectors, dimension;
        std::vector<float> data = NPYReader::readNPY(npyPath, numVectors, dimension);
        
        std::cout << "\n[Dataset] Loaded query vector" << std::endl;
        std::cout << "  Dimension: " << dimension << std::endl;
        
        // Convert to double
        std::vector<double> query(dimension);
        for (size_t i = 0; i < dimension; ++i) {
            query[i] = static_cast<double>(data[i]);
        }
        
        // Normalize query vector to unit length
        std::cout << "\n[Normalization] Computing unit normalization..." << std::endl;
        auto normalizedQuery = normalizeVector(query);
        
        // Verify normalization
        double norm = 0.0;
        for (double val : normalizedQuery) {
            norm += val * val;
        }
        norm = std::sqrt(norm);
        std::cout << "  Original norm: " << std::sqrt(std::inner_product(query.begin(), query.end(), query.begin(), 0.0)) << std::endl;
        std::cout << "  Normalized norm: " << norm << std::endl;
        std::cout << "✓ Query vector normalized to unit length" << std::endl;
        
        // Encrypt
        auto ciphertext = encryptVector(normalizedQuery);
        
        // Save to disk
        std::string filename = encryptedDataPath + "/query.bin";
        if (!Serial::SerializeToFile(filename, ciphertext, SerType::BINARY)) {
            throw std::runtime_error("Failed to save query ciphertext");
        }
        
        std::cout << "✓ Query vector encrypted and saved" << std::endl;
    }
    
    // Save metadata about the encryption
    void saveMetadata(size_t numVectors, size_t dimension) {
        std::string metadataPath = encryptedDataPath + "/metadata.txt";
        std::ofstream file(metadataPath);
        file << "num_vectors=" << numVectors << "\n";
        file << "dimension=" << dimension << "\n";
        file << "batch_size=" << cryptoContext->GetEncodingParams()->GetBatchSize() << "\n";
        file << "ring_dimension=" << cryptoContext->GetRingDimension() << "\n";
        file.close();
        std::cout << "✓ Metadata saved to: " << metadataPath << std::endl;
    }
    
    void printSummary() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Encryption Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "\n✓ Encryption completed successfully" << std::endl;
        std::cout << "✓ Encrypted data saved to: " << encryptedDataPath << "/" << std::endl;
        std::cout << "\nFiles created:" << std::endl;
        std::cout << "  - storage_0.bin to storage_999.bin (1000 vectors)" << std::endl;
        std::cout << "  - query.bin (query vector)" << std::endl;
        std::cout << "  - metadata.txt (encryption metadata)" << std::endl;
        std::cout << "========================================" << std::endl;
    }
};

// Main function
int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Vector Encryption Module             ║" << std::endl;
    std::cout << "║   Multiparty CKKS System               ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    // Parse arguments
    std::string datasetPath = "datasets/dataset_1";
    if (argc >= 2) {
        std::string datasetId = argv[1];
        datasetPath = "datasets/dataset_" + datasetId;
    }
    
    try {
        VectorEncryptor encryptor;
        
        // Load keys
        encryptor.loadKeys("users/user1");
        
        // Encrypt storage vectors
        encryptor.encryptStorageVectors(datasetPath);
        
        // Encrypt query vector
        encryptor.encryptQueryVector(datasetPath);
        
        // Save metadata
        encryptor.saveMetadata(1000, 512);
        
        // Print summary
        encryptor.printSummary();
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Encryption failed: " << e.what() << std::endl;
        return 1;
    }
}

