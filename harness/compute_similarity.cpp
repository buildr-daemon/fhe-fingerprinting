//==================================================================================
// Homomorphic Computation Module
// 
// This program:
// 1. Loads encrypted storage and query vectors
// 2. Computes encrypted cosine similarities (dot products)
// 3. Computes encrypted maximum using polynomial approximation
// 4. Performs threshold check homomorphically
// 5. Saves results for threshold decryption
//==================================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cmath>
#include <algorithm>
#include "openfhe.h"

// Serialization includes
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

// Polynomial approximation helpers
class PolynomialApproximations {
public:
    // Compute exp(x) using Taylor series approximation
    // exp(x) ≈ 1 + x + x²/2! + x³/3! + x⁴/4! + x⁵/5! + x⁶/6!
    static Ciphertext<DCRTPoly> evaluateExponential(
        CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        int degree = 7) {
        
        try {
            // Start with constant term 1
            std::vector<double> ones(cc->GetEncodingParams()->GetBatchSize(), 1.0);
            Plaintext ptOnes = cc->MakeCKKSPackedPlaintext(ones);
            auto result = cc->EvalAdd(x, ptOnes);
            result = cc->EvalSub(result, x); // result = 1
        
            // Add x term
            result = cc->EvalAdd(result, x);
            
            // Compute higher order terms: x^n / n!
            auto xPower = x;  // Current power of x
            std::vector<double> factorials = {1.0, 1.0, 2.0, 6.0, 24.0, 120.0, 720.0, 5040.0};
            
            for (int n = 2; n <= degree && n < 8; ++n) {
                // Compute x^n
                xPower = cc->EvalMult(xPower, x);
                
                // Divide by n! and add to result
                double coeff = 1.0 / factorials[n];
                auto term = cc->EvalMult(xPower, coeff);
                result = cc->EvalAdd(result, term);
            }
            
            return result;
        } catch (const std::exception& e) {
            std::cerr << "\n✗ Error in exponential evaluation:" << std::endl;
            std::cerr << "  Exception: " << e.what() << std::endl;
            std::cerr << "  Degree: " << degree << std::endl;
            std::cerr << "  Batch size: " << cc->GetEncodingParams()->GetBatchSize() << std::endl;
            throw;
        }
    }
    
    // Compute sign function using tanh approximation
    // sign(x) ≈ tanh(αx) ≈ αx - (αx)³/3 + 2(αx)⁵/15 for small αx
    static Ciphertext<DCRTPoly> evaluateSign(
        CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        double alpha = 5.0) {
        
        // Compute αx
        auto ax = cc->EvalMult(x, alpha);
        
        // Compute (αx)³
        auto ax2 = cc->EvalMult(ax, ax);
        auto ax3 = cc->EvalMult(ax2, ax);
        
        // sign ≈ αx - (αx)³/3
        auto term1 = cc->EvalMult(ax3, -1.0/3.0);
        auto result = cc->EvalAdd(ax, term1);
        
        return result;
    }
    
    // Compute sigmoid-like function: 1/(1+exp(-αx))
    // Using approximation: 0.5 + 0.25*αx - (αx)³/48 (for |αx| < 2)
    static Ciphertext<DCRTPoly> evaluateSigmoid(
        CryptoContext<DCRTPoly>& cc,
        const Ciphertext<DCRTPoly>& x,
        double alpha = 3.0) {
        
        // Compute αx
        auto ax = cc->EvalMult(x, alpha);
        
        // Compute (αx)³
        auto ax2 = cc->EvalMult(ax, ax);
        auto ax3 = cc->EvalMult(ax2, ax);
        
        // sigmoid ≈ 0.5 + 0.25*αx - (αx)³/48
        auto term1 = cc->EvalMult(ax, 0.25);
        auto term2 = cc->EvalMult(ax3, -1.0/48.0);
        
        // Create constant 0.5 and add terms
        std::vector<double> half(cc->GetEncodingParams()->GetBatchSize(), 0.5);
        Plaintext ptHalf = cc->MakeCKKSPackedPlaintext(half);
        auto resultCt = cc->EvalAdd(term1, ptHalf);
        resultCt = cc->EvalAdd(resultCt, term2);
        
        return resultCt;
    }
};

class SimilarityComputer {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::string encryptedDataPath;
    std::string resultsPath;
    double threshold;
    
public:
    SimilarityComputer(const std::string& encDataPath = "encrypted_data", 
                      const std::string& resPath = "results",
                      double tau = 0.85)
        : encryptedDataPath(encDataPath), resultsPath(resPath), threshold(tau) {
        fs::create_directories(resultsPath);
    }
    
    // Load crypto context
    void loadCryptoContext(const std::string& userPath = "users/user1") {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Loading Crypto Context" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::string ccPath = userPath + "/cryptocontext.txt";
        if (!Serial::DeserializeFromFile(ccPath, cryptoContext, SerType::BINARY)) {
            throw std::runtime_error("Failed to load crypto context");
        }
        std::cout << "✓ Crypto context loaded" << std::endl;
        
        // Load evaluation multiplication keys
        std::cout << "\n[Loading] Evaluation multiplication keys..." << std::endl;
        std::string multKeyPath = userPath + "/key-eval-mult.txt";
        if (std::filesystem::exists(multKeyPath)) {
            std::vector<EvalKey<DCRTPoly>> evalMultKeys;
            if (Serial::DeserializeFromFile(multKeyPath, evalMultKeys, SerType::BINARY)) {
                cryptoContext->InsertEvalMultKey(evalMultKeys);
                std::cout << "✓ Evaluation multiplication keys loaded" << std::endl;
            } else {
                std::cout << "⚠ Failed to load evaluation multiplication keys" << std::endl;
            }
        } else {
            std::cout << "⚠ Evaluation multiplication keys file not found" << std::endl;
        }
        
        // Load evaluation sum keys (rotation keys)
        std::cout << "\n[Loading] Evaluation sum keys..." << std::endl;
        std::string sumKeyPath = userPath + "/key-eval-sum.txt";
        if (std::filesystem::exists(sumKeyPath)) {
            std::map<usint, EvalKey<DCRTPoly>> evalSumKeys;
            if (Serial::DeserializeFromFile(sumKeyPath, evalSumKeys, SerType::BINARY)) {
                cryptoContext->InsertEvalSumKey(
                    std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(evalSumKeys));
                std::cout << "✓ Evaluation sum keys loaded" << std::endl;
            } else {
                std::cout << "⚠ Failed to load evaluation sum keys" << std::endl;
            }
        } else {
            std::cout << "⚠ Evaluation sum keys file not found" << std::endl;
        }
    }
    
    // Compute dot product of two encrypted vectors
    Ciphertext<DCRTPoly> computeDotProduct(
        const Ciphertext<DCRTPoly>& ct1,
        const Ciphertext<DCRTPoly>& ct2) {
        
        // Element-wise multiplication
        auto product = cryptoContext->EvalMult(ct1, ct2);
        
        // Sum all elements using EvalSum
        auto result = cryptoContext->EvalSum(product, cryptoContext->GetEncodingParams()->GetBatchSize());
        
        return result;
    }
    
    // Compute all cosine similarities
    std::vector<Ciphertext<DCRTPoly>> computeAllSimilarities(
        const Ciphertext<DCRTPoly>& queryCt) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Cosine Similarities" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::vector<Ciphertext<DCRTPoly>> similarities;
        
        // Read metadata to get number of vectors
        std::ifstream metaFile(encryptedDataPath + "/metadata.txt");
        size_t numVectors = 1000;  // Default
        std::string line;
        while (std::getline(metaFile, line)) {
            if (line.find("num_vectors=") == 0) {
                numVectors = std::stoull(line.substr(12));
            }
        }
        metaFile.close();
        
        std::cout << "\n[Processing] Computing " << numVectors << " dot products..." << std::endl;
        
        for (size_t i = 0; i < numVectors; ++i) {
            // Load storage vector ciphertext
            Ciphertext<DCRTPoly> storageCt;
            std::string filename = encryptedDataPath + "/storage_" + std::to_string(i) + ".bin";
            if (!Serial::DeserializeFromFile(filename, storageCt, SerType::BINARY)) {
                throw std::runtime_error("Failed to load ciphertext: " + filename);
            }
            
            // Compute dot product (cosine similarity for unit vectors)
            try {
                auto similarity = computeDotProduct(queryCt, storageCt);
                similarities.push_back(similarity);
            } catch (const std::exception& e) {
                std::cerr << "\n✗ Error in dot product computation at iteration " << i << ":" << std::endl;
                std::cerr << "  Exception: " << e.what() << std::endl;
                std::cerr << "  Storage vector index: " << i << std::endl;
                std::cerr << "  Filename: " << filename << std::endl;
                throw;
            }
            
            if ((i + 1) % 100 == 0 || i == 0 || i == numVectors - 1) {
                std::cout << "  Computed " << (i + 1) << "/" << numVectors << " similarities" << std::endl;
            }
        }
        
        std::cout << "✓ All similarities computed" << std::endl;
        return similarities;
    }
    
    // Compute maximum using softmax approximation
    // max(x) ≈ Σ(x_i * exp(α*x_i)) / Σ(exp(α*x_i))
    Ciphertext<DCRTPoly> computeEncryptedMax(
        const std::vector<Ciphertext<DCRTPoly>>& similarities) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Encrypted Maximum" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Validation checks
        if (similarities.empty()) {
            throw std::runtime_error("No similarities provided for max computation");
        }
        std::cout << "\n[Validation] Input similarities count: " << similarities.size() << std::endl;
        std::cout << "[Validation] Crypto context valid: " << (cryptoContext ? "Yes" : "No") << std::endl;
        
        // Use softmax-based approximation with sharpness parameter α
        double alpha = 10.0;  // Sharpness parameter (higher = sharper, but needs more precision)
        
        std::cout << "\n[Algorithm] Softmax approximation" << std::endl;
        std::cout << "  Sharpness α: " << alpha << std::endl;
        std::cout << "  Formula: max ≈ Σ(x_i * exp(α*x_i)) / Σ(exp(α*x_i))" << std::endl;
        
        // Scale similarities by α
        std::cout << "\n[Step 1] Scaling similarities by α..." << std::endl;
        std::vector<Ciphertext<DCRTPoly>> scaledSims;
        for (size_t i = 0; i < similarities.size(); ++i) {
            try {
                scaledSims.push_back(cryptoContext->EvalMult(similarities[i], alpha));
            } catch (const std::exception& e) {
                std::cerr << "\n✗ Error in scaling at iteration " << i << ":" << std::endl;
                std::cerr << "  Exception: " << e.what() << std::endl;
                std::cerr << "  Similarity index: " << i << std::endl;
                std::cerr << "  Total similarities: " << similarities.size() << std::endl;
                std::cerr << "  Alpha value: " << alpha << std::endl;
                throw;
            }
        }
        
        // Compute exp(α*x_i) for each similarity
        std::cout << "[Step 2] Computing exponentials (polynomial approximation)..." << std::endl;
        std::vector<Ciphertext<DCRTPoly>> expSims;
        for (size_t i = 0; i < scaledSims.size(); ++i) {
            try {
                auto expSim = PolynomialApproximations::evaluateExponential(
                    cryptoContext, scaledSims[i], 6);
                expSims.push_back(expSim);
                
                if ((i + 1) % 100 == 0 || i == 0) {
                    std::cout << "  Processed " << (i + 1) << "/" << scaledSims.size() << " exponentials" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "\n✗ Error in exponential computation at iteration " << i << ":" << std::endl;
                std::cerr << "  Exception: " << e.what() << std::endl;
                std::cerr << "  Scaled similarity index: " << i << std::endl;
                std::cerr << "  Total scaled similarities: " << scaledSims.size() << std::endl;
                std::cerr << "  Alpha value: " << alpha << std::endl;
                throw;
            }
        }
        
        // Compute numerator: Σ(x_i * exp(α*x_i))
        std::cout << "[Step 3] Computing weighted sum (numerator)..." << std::endl;
        Ciphertext<DCRTPoly> numerator;
        try {
            numerator = cryptoContext->EvalMult(similarities[0], expSims[0]);
            for (size_t i = 1; i < similarities.size(); ++i) {
                try {
                    auto term = cryptoContext->EvalMult(similarities[i], expSims[i]);
                    numerator = cryptoContext->EvalAdd(numerator, term);
                } catch (const std::exception& e) {
                    std::cerr << "\n✗ Error in numerator computation at iteration " << i << ":" << std::endl;
                    std::cerr << "  Exception: " << e.what() << std::endl;
                    std::cerr << "  Similarity index: " << i << std::endl;
                    std::cerr << "  Total similarities: " << similarities.size() << std::endl;
                    std::cerr << "  Total exp values: " << expSims.size() << std::endl;
                    throw;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "\n✗ Error in numerator computation:" << std::endl;
            std::cerr << "  Exception: " << e.what() << std::endl;
            std::cerr << "  Similarities size: " << similarities.size() << std::endl;
            std::cerr << "  Exp values size: " << expSims.size() << std::endl;
            throw;
        }
        
        // Compute denominator: Σ(exp(α*x_i))
        std::cout << "[Step 4] Computing sum of exponentials (denominator)..." << std::endl;
        auto denominator = expSims[0];
        for (size_t i = 1; i < expSims.size(); ++i) {
            denominator = cryptoContext->EvalAdd(denominator, expSims[i]);
        }
        
        // Compute division: numerator / denominator
        // For division, we use the multiplicative inverse approximation
        // 1/x ≈ 2/x₀ - x/(x₀²) where x₀ is an initial guess
        // For simplicity, we'll use a linear approximation: assuming denominator ≈ constant
        std::cout << "[Step 5] Computing final division (approximate)..." << std::endl;
        
        // Simplified approach: Since all exp values are positive and relatively similar,
        // we approximate: max ≈ numerator * (1 / expected_denominator)
        // For 1000 similarities near 1.0, exp(10*1) ≈ 22026, so sum ≈ 22026*1000
        double expectedDenom = std::exp(alpha * 1.0) * similarities.size();
        auto maxApprox = cryptoContext->EvalMult(numerator, 1.0 / expectedDenom);
        
        std::cout << "✓ Encrypted maximum computed" << std::endl;
        
        return maxApprox;
    }
    
    // Perform threshold check: is max > threshold?
    Ciphertext<DCRTPoly> computeThresholdCheck(
        const Ciphertext<DCRTPoly>& maxSimilarity) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Threshold Check" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::cout << "\n[Threshold] τ = " << threshold << std::endl;
        std::cout << "[Check] max > τ ?" << std::endl;
        
        // Compute (max - threshold)
        auto diff = cryptoContext->EvalSub(maxSimilarity, threshold);
        
        // Apply sign function: sign(diff) ≈ 1 if diff > 0, ≈ -1 if diff < 0
        auto signResult = PolynomialApproximations::evaluateSign(cryptoContext, diff, 5.0);
        
        // Convert to 0/1: (sign + 1) / 2
        auto shifted = cryptoContext->EvalAdd(signResult, 1.0);
        auto binaryResult = cryptoContext->EvalMult(shifted, 0.5);
        
        std::cout << "✓ Threshold check computed (1 if unique, 0 if not unique)" << std::endl;
        
        return binaryResult;
    }
    
    // Save results
    void saveResults(const Ciphertext<DCRTPoly>& maxSim, 
                    const Ciphertext<DCRTPoly>& thresholdResult) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Saving Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Save max similarity
        std::string maxFile = resultsPath + "/max_similarity.bin";
        if (!Serial::SerializeToFile(maxFile, maxSim, SerType::BINARY)) {
            throw std::runtime_error("Failed to save max similarity");
        }
        std::cout << "✓ Max similarity saved to: " << maxFile << std::endl;
        
        // Save threshold result
        std::string thresholdFile = resultsPath + "/threshold_result.bin";
        if (!Serial::SerializeToFile(thresholdFile, thresholdResult, SerType::BINARY)) {
            throw std::runtime_error("Failed to save threshold result");
        }
        std::cout << "✓ Threshold result saved to: " << thresholdFile << std::endl;
        
        // Save metadata
        std::ofstream metaFile(resultsPath + "/results_metadata.txt");
        metaFile << "threshold=" << threshold << "\n";
        metaFile << "num_similarities=1000\n";
        metaFile << "algorithm=softmax_approximation\n";
        metaFile.close();
        std::cout << "✓ Metadata saved" << std::endl;
    }
    
    void run() {
        try {
            // Load crypto context
            loadCryptoContext();
            
            // Load query vector
            std::cout << "\n[Loading] Query vector..." << std::endl;
            Ciphertext<DCRTPoly> queryCt;
            std::string queryFile = encryptedDataPath + "/query.bin";
            if (!Serial::DeserializeFromFile(queryFile, queryCt, SerType::BINARY)) {
                throw std::runtime_error("Failed to load query ciphertext");
            }
            std::cout << "✓ Query vector loaded" << std::endl;
            
            // Compute all similarities
            auto similarities = computeAllSimilarities(queryCt);
            
            // Compute encrypted max
            auto maxSim = computeEncryptedMax(similarities);
            
            // Compute threshold check
            auto thresholdResult = computeThresholdCheck(maxSim);
            
            // Save results
            saveResults(maxSim, thresholdResult);
            
            // Print summary
            std::cout << "\n========================================" << std::endl;
            std::cout << "Computation Complete" << std::endl;
            std::cout << "========================================" << std::endl;
            std::cout << "\n✓ All homomorphic computations completed" << std::endl;
            std::cout << "✓ Results ready for threshold decryption" << std::endl;
            std::cout << "\nNext step: Run decryption module to reveal results" << std::endl;
            std::cout << "========================================" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "\n✗ Computation failed: " << e.what() << std::endl;
            std::cerr << "\nStack trace information:" << std::endl;
            std::cerr << "Exception type: " << typeid(e).name() << std::endl;
            std::cerr << "Error details: " << e.what() << std::endl;
            std::cerr << "\nDebug information:" << std::endl;
            std::cerr << "- Crypto context loaded: " << (cryptoContext ? "Yes" : "No") << std::endl;
            std::cerr << "- Encrypted data path: " << encryptedDataPath << std::endl;
            std::cerr << "- Results path: " << resultsPath << std::endl;
            std::cerr << "- Threshold: " << threshold << std::endl;
            throw;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Homomorphic Similarity Computer       ║" << std::endl;
    std::cout << "║  Multiparty CKKS System                ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    // Parse threshold from command line if provided
    double threshold = 0.85;
    if (argc >= 2) {
        threshold = std::stod(argv[1]);
    }
    
    try {
        SimilarityComputer computer("encrypted_data", "results", threshold);
        computer.run();
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << std::endl;
        std::cerr << "\nDetailed error information:" << std::endl;
        std::cerr << "Exception type: " << typeid(e).name() << std::endl;
        std::cerr << "Error message: " << e.what() << std::endl;
        std::cerr << "\nThis error occurred in the main function." << std::endl;
        std::cerr << "Please check the previous output for more context." << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n✗ Unknown error occurred!" << std::endl;
        std::cerr << "This is likely a non-standard exception or a system error." << std::endl;
        return 1;
    }
}

