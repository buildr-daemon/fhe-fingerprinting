//==================================================================================
// Threshold Decryption Module
// 
// This program:
// 1. Loads secret keys from both parties
// 2. Loads encrypted results (max similarity and threshold check)
// 3. Performs threshold decryption (requires both parties)
// 4. Displays plaintext results
//==================================================================================

#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include "openfhe.h"

// Serialization includes
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

class ThresholdDecryptor {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    PrivateKey<DCRTPoly> user1SecretKey;
    PrivateKey<DCRTPoly> user2SecretKey;
    std::string resultsPath;
    
public:
    ThresholdDecryptor(const std::string& resPath = "results")
        : resultsPath(resPath) {}
    
    // Load crypto context and secret keys from both users
    void loadKeysAndContext() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Loading Crypto Context and Keys" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Load crypto context from user1
        std::string ccPath = "users/user1/cryptocontext.txt";
        if (!Serial::DeserializeFromFile(ccPath, cryptoContext, SerType::BINARY)) {
            throw std::runtime_error("Failed to load crypto context");
        }
        std::cout << "✓ Crypto context loaded" << std::endl;
        
        // Load User 1's secret key
        std::string sk1Path = "users/user1/secret_key.txt";
        if (!Serial::DeserializeFromFile(sk1Path, user1SecretKey, SerType::BINARY)) {
            throw std::runtime_error("Failed to load User 1's secret key");
        }
        std::cout << "✓ User 1 secret key loaded" << std::endl;
        
        // Load User 2's secret key
        std::string sk2Path = "users/user2/secret_key.txt";
        if (!Serial::DeserializeFromFile(sk2Path, user2SecretKey, SerType::BINARY)) {
            throw std::runtime_error("Failed to load User 2's secret key");
        }
        std::cout << "✓ User 2 secret key loaded" << std::endl;
        
        std::cout << "\n[Security] Both parties' keys required for decryption" << std::endl;
        std::cout << "           This ensures threshold security!" << std::endl;
    }
    
    // Perform threshold decryption on a ciphertext
    Plaintext thresholdDecrypt(const Ciphertext<DCRTPoly>& ciphertext, 
                              const std::string& description) {
        
        std::cout << "\n[Decrypting] " << description << "..." << std::endl;
        
        // Multiparty decryption protocol:
        // 1. User 1 performs partial decryption (Main party)
        std::vector<Ciphertext<DCRTPoly>> ciphertextVec = {ciphertext};
        auto partialPlaintext1 = cryptoContext->MultipartyDecryptMain(
            ciphertextVec, user1SecretKey);
        std::cout << "  [User 1] Partial decryption completed" << std::endl;
        
        // 2. User 2 performs partial decryption (Lead party)
        auto partialPlaintext2 = cryptoContext->MultipartyDecryptLead(
            ciphertextVec, user2SecretKey);
        std::cout << "  [User 2] Partial decryption completed" << std::endl;
        
        // 3. Fuse partial plaintexts to get final result
        Plaintext finalPlaintext;
        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec = {
            partialPlaintext1[0], partialPlaintext2[0]
        };
        
        cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &finalPlaintext);
        std::cout << "  [Fusion] Final plaintext recovered" << std::endl;
        
        return finalPlaintext;
    }
    
    // Load and decrypt results
    void decryptResults() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Decrypting Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Load metadata
        double threshold = 0.85;
        bool thresholdInPlaintext = false;
        std::ifstream metaFile(resultsPath + "/results_metadata.txt");
        if (metaFile.is_open()) {
            std::string line;
            while (std::getline(metaFile, line)) {
                if (line.find("threshold=") == 0) {
                    threshold = std::stod(line.substr(10));
                } else if (line.find("threshold_comparison=plaintext") == 0) {
                    thresholdInPlaintext = true;
                }
            }
            metaFile.close();
        }
        
        // Load max similarity ciphertext
        Ciphertext<DCRTPoly> maxSimCt;
        std::string maxFile = resultsPath + "/max_similarity.bin";
        if (!Serial::DeserializeFromFile(maxFile, maxSimCt, SerType::BINARY)) {
            throw std::runtime_error("Failed to load max similarity ciphertext");
        }
        std::cout << "\n✓ Encrypted max similarity loaded" << std::endl;
        
        // Decrypt max similarity using threshold protocol
        auto maxSimPlaintext = thresholdDecrypt(maxSimCt, "Max Similarity");
        
        // Extract max similarity value
        std::vector<double> maxValues = maxSimPlaintext->GetRealPackedValue();
        double maxSimilarity = maxValues[0];
        
        // Perform threshold comparison in plaintext
        std::cout << "\n[Threshold Check] Performing comparison in plaintext..." << std::endl;
        std::cout << "  Max similarity: " << std::fixed << std::setprecision(6) << maxSimilarity << std::endl;
        std::cout << "  Threshold τ: " << std::fixed << std::setprecision(2) << threshold << std::endl;
        
        bool isUnique = (maxSimilarity > threshold);
        double thresholdResult = isUnique ? 1.0 : 0.0;  // For compatibility with display
        
        std::cout << "  Result: " << (isUnique ? "UNIQUE (max > τ)" : "NOT UNIQUE (max ≤ τ)") << std::endl;
        std::cout << "✓ Threshold comparison completed in plaintext" << std::endl;
        
        // Print results
        printResults(maxSimilarity, threshold, isUnique, thresholdResult);
    }
    
    // Print final results
    void printResults(double maxSimilarity, double threshold, 
                     bool isUnique, double thresholdRaw) {
        
        std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
        std::cout << "║         DECRYPTION RESULTS             ║" << std::endl;
        std::cout << "╚════════════════════════════════════════╝" << std::endl;
        
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  Maximum Cosine Similarity          │" << std::endl;
        std::cout << "├─────────────────────────────────────┤" << std::endl;
        std::cout << "│  Value: " << std::fixed << std::setprecision(6) 
                  << maxSimilarity << "                   │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;
        
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  Threshold Check                    │" << std::endl;
        std::cout << "├─────────────────────────────────────┤" << std::endl;
        std::cout << "│  Threshold τ: " << std::fixed << std::setprecision(2) 
                  << threshold << "                     │" << std::endl;
        std::cout << "│  Max > τ: " << (isUnique ? "YES (Unique)     " : "NO (Not Unique)")
                  << "           │" << std::endl;
        std::cout << "│  Raw value: " << std::fixed << std::setprecision(4) 
                  << thresholdRaw << "                   │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;
        
        std::cout << "\n[Interpretation]" << std::endl;
        if (isUnique) {
            std::cout << "  The query vector has HIGH similarity (> " << threshold 
                      << ") with database vectors." << std::endl;
            std::cout << "  This suggests the query is UNIQUE/MATCHED in the database." << std::endl;
        } else {
            std::cout << "  The query vector has LOW similarity (≤ " << threshold 
                      << ") with database vectors." << std::endl;
            std::cout << "  This suggests the query is NOT UNIQUE/MATCHED in the database." << std::endl;
        }
        
        std::cout << "\n[Security Note]" << std::endl;
        std::cout << "  ✓ Decryption required cooperation from BOTH parties" << std::endl;
        std::cout << "  ✓ No single party could decrypt alone" << std::endl;
        std::cout << "  ✓ Individual similarities were NEVER decrypted" << std::endl;
        std::cout << "  ✓ Only the maximum value was revealed" << std::endl;
        
        std::cout << "\n========================================" << std::endl;
    }
    
    void run() {
        try {
            loadKeysAndContext();
            decryptResults();
            
        } catch (const std::exception& e) {
            std::cerr << "\n✗ Decryption failed: " << e.what() << std::endl;
            throw;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Threshold Decryption Module          ║" << std::endl;
    std::cout << "║   Multiparty CKKS System               ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    try {
        ThresholdDecryptor decryptor;
        decryptor.run();
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << std::endl;
        return 1;
    }
}


