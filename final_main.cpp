#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <cmath>
#include <cstdio>
#include <vector>
#include <random>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <future> // Required for std::async and std::future
#include <mutex> // Required for thread-safe random number generation
#include "openfhe.h"

using namespace lbcrypto;

// NPYReader Class (unchanged)
class NPYReader {
public:
    static std::vector<float> readNPY(const std::string& filename, size_t& numVectors, size_t& dimension) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }
        
        char magic[6];
        file.read(magic, 6);
        uint8_t major, minor;
        file.read(reinterpret_cast<char*>(&major), 1);
        file.read(reinterpret_cast<char*>(&minor), 1);
        uint16_t headerLen = 0;
        if (major == 1) {
            file.read(reinterpret_cast<char*>(&headerLen), 2);
        } else if (major >= 2) {
            uint32_t headerLen32;
            file.read(reinterpret_cast<char*>(&headerLen32), 4);
            headerLen = static_cast<uint16_t>(headerLen32);
        }
        
        std::vector<char> headerBuf(headerLen);
        file.read(headerBuf.data(), headerLen);
        std::string header(headerBuf.begin(), headerBuf.end());
        
        size_t shapePos = header.find("'shape': (");
        if (shapePos == std::string::npos) {
            shapePos = header.find("\"shape\": (");
        }
        
        if (shapePos != std::string::npos) {
            size_t start = shapePos + 10;
            size_t end = header.find(")", start);
            std::string shapeStr = header.substr(start, end - start);
            
            shapeStr.erase(std::remove_if(shapeStr.begin(), shapeStr.end(), ::isspace), shapeStr.end());
            
            size_t comma = shapeStr.find(",");
            if (comma != std::string::npos) {
                std::string firstDim = shapeStr.substr(0, comma);
                std::string secondDim = shapeStr.substr(comma + 1);
                
                secondDim.erase(std::remove_if(secondDim.begin(), secondDim.end(), 
                    [](char c) { return !std::isdigit(c); }), secondDim.end());
                
                if (secondDim.empty()) {
                    numVectors = 1;
                    dimension = std::stoull(firstDim);
                } else {
                    numVectors = std::stoull(firstDim);
                    dimension = std::stoull(secondDim);
                }
            } else {
                numVectors = 1;
                dimension = std::stoull(shapeStr);
            }
        }
        
        size_t numElements = numVectors * dimension;
        std::vector<float> data(numElements);
        file.read(reinterpret_cast<char*>(data.data()), numElements * sizeof(float));
        
        return data;
    }
};


// generateCKKSKeys (unchanged, EvalMerge keys are no longer needed)
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> generateCKKSKeys() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Generating CKKS Keys" << std::endl;
    std::cout << "========================================" << std::endl;
    
    uint32_t multDepth = 20; 
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 1024;
    SecurityLevel securityLevel = HEStd_128_classic;
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    std::cout << "✓ CryptoContext initialized" << std::endl;
    
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    std::cout << "✓ Key pair generated" << std::endl;
    
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    
    std::vector<int32_t> rotation_indices;
    for (int i = 1; i < batchSize; i *= 2) {
        rotation_indices.push_back(i);
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indices);
    std::cout << "✓ Rotation keys generated (for EvalSum)" << std::endl;
    
    return std::make_tuple(cryptoContext, keyPair);
}


// normalizeVector and loadAndEncryptVectors (unchanged)
std::vector<double> normalizeVector(const std::vector<double>& vec) {
    double norm = std::sqrt(std::inner_product(vec.begin(), vec.end(), vec.begin(), 0.0));
    if (norm == 0.0) return vec;
    std::vector<double> normalized(vec.size());
    std::transform(vec.begin(), vec.end(), normalized.begin(), 
                   [norm](double val) { return val / norm; });
    return normalized;
}

std::tuple<Ciphertext<DCRTPoly>, std::vector<Ciphertext<DCRTPoly>>, std::vector<double>, std::vector<std::vector<double>>>
loadAndEncryptVectors(CryptoContext<DCRTPoly> cryptoContext, PublicKey<DCRTPoly> publicKey) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Loading and Encrypting Vectors" << std::endl;
    std::cout << "========================================" << std::endl;
    
    size_t numVectorsQ, dimQ;
    std::vector<float> queryData = NPYReader::readNPY("datasets/dataset_1/query_vector.npy", numVectorsQ, dimQ);
    std::vector<double> queryVec(dimQ);
    std::transform(queryData.begin(), queryData.end(), queryVec.begin(), [](float f) { return static_cast<double>(f); });
    
    size_t numVectors, dimension;
    std::vector<float> storageData = NPYReader::readNPY("datasets/dataset_1/storage_vectors.npy", numVectors, dimension);
    
    std::vector<double> normalizedQuery = normalizeVector(queryVec);
    
    std::vector<std::vector<double>> storageVecs(numVectors, std::vector<double>(dimension));
    for (size_t i = 0; i < numVectors; ++i) {
        for (size_t j = 0; j < dimension; ++j) {
            storageVecs[i][j] = static_cast<double>(storageData[i * dimension + j]);
        }
    }
    
    Plaintext queryPt = cryptoContext->MakeCKKSPackedPlaintext(normalizedQuery);
    Ciphertext<DCRTPoly> queryCt = cryptoContext->Encrypt(publicKey, queryPt);
    
    std::vector<Ciphertext<DCRTPoly>> encryptedStorage;
    for (size_t i = 0; i < numVectors; ++i) {
        Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(storageVecs[i]);
        Ciphertext<DCRTPoly> ct = cryptoContext->Encrypt(publicKey, pt);
        encryptedStorage.push_back(ct);
    }
    std::cout << "✓ All vectors loaded and encrypted" << std::endl;
    return std::make_tuple(queryCt, encryptedStorage, normalizedQuery, storageVecs);
}

// computeCosineSimilarities (unchanged)
std::vector<Ciphertext<DCRTPoly>> computeCosineSimilarities(
    CryptoContext<DCRTPoly> cryptoContext,
    Ciphertext<DCRTPoly> queryCt,
    const std::vector<Ciphertext<DCRTPoly>>& storageVecs) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Computing Cosine Similarities" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<Ciphertext<DCRTPoly>> similarities;
    for (const auto& vec : storageVecs) {
        auto product = cryptoContext->EvalMult(queryCt, vec);
        auto similarity = cryptoContext->EvalSum(product, cryptoContext->GetEncodingParams()->GetBatchSize());
        similarities.push_back(similarity);
    }
    std::cout << "✓ All similarities computed" << std::endl;
    return similarities;
}


//================================================================================
// KeyHolder (Oracle) Class - MODIFIED
//================================================================================
class KeyHolder {
public:
    KeyHolder(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, PublicKey<DCRTPoly> pk)
        : m_cc(cc), m_sk(sk), m_pk(pk) {}

    /**
     * @brief Securely determines if a challenger value is greater than a champion.
     * Receives Enc(challenger - champion + r) and returns Enc(1) if it's a new max,
     * otherwise returns Enc(0).
     * @param ct_masked_diff Ciphertext containing the masked difference.
     * @param r The plaintext random mask 'r' used by the server.
     * @return An encrypted bit: Enc(1) for new max, Enc(0) otherwise.
     */
    Ciphertext<DCRTPoly> IsNewMax(Ciphertext<DCRTPoly> ct_masked_diff, double r) {
        Plaintext pt_masked_diff;
        m_cc->Decrypt(m_sk, ct_masked_diff, &pt_masked_diff);
        double v = pt_masked_diff->GetRealPackedValue()[0];

        // Comparison: (challenger - champion + r) > r  <=>  challenger > champion
        double bit = (v > r) ? 1.0 : 0.0;
        
        std::vector<double> bit_vec = {bit};
        Plaintext pt_bit = m_cc->MakeCKKSPackedPlaintext(bit_vec);
        return m_cc->Encrypt(m_pk, pt_bit);
    }

private:
    CryptoContext<DCRTPoly> m_cc;
    PrivateKey<DCRTPoly> m_sk;
    PublicKey<DCRTPoly> m_pk;
};

//================================================================================
// ComputeServer Class - CORRECTED
//================================================================================
// class ComputeServer {
//     public:
//         ComputeServer(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk) : m_cc(cc), m_pk(pk) {}
    
        // std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> findMaxSequential(
        //     const std::vector<Ciphertext<DCRTPoly>>& similarities, KeyHolder& oracle) {
            
        //     if (similarities.size() < 1) {
        //         throw std::runtime_error("Similarities vector cannot be empty.");
        //     }
        //     size_t k = similarities.size();
        //     std::cout << "\n========================================" << std::endl;
        //     std::cout << "Finding Max via Sequential Comparison" << std::endl;
        //     std::cout << "========================================" << std::endl;
    
        //     // --- 1. Initialization ---
        //     auto encrypted_max = similarities[0];
        //     // **FIX 1**: Explicitly create the vector
        //     Plaintext pt_idx_0 = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{0.0});
        //     auto encrypted_idx = m_cc->Encrypt(m_pk, pt_idx_0);
    
        //     std::random_device rd;
        //     std::mt19937 gen(rd());
        //     std::uniform_real_distribution<> distrib(-10000.0, 10000.0);
            
        //     // --- 2. Iteration ---
        //     for (size_t i = 1; i < k; ++i) {
        //         auto& challenger_val = similarities[i];
                
        //         auto ct_diff = m_cc->EvalSub(challenger_val, encrypted_max);
                
        //         double r = distrib(gen);
        //         auto ct_masked_diff = m_cc->EvalAdd(ct_diff, r);
        //         auto encrypted_bit = oracle.IsNewMax(ct_masked_diff, r);
    
        //         // Homomorphically update the max and index
        //         auto diff_for_update = m_cc->EvalSub(challenger_val, encrypted_max);
        //         auto term_to_add_val = m_cc->EvalMult(encrypted_bit, diff_for_update);
        //         encrypted_max = m_cc->EvalAdd(encrypted_max, term_to_add_val);
                
        //         // **FIX 2**: Explicitly create the vector for the index 'i'
        //         Plaintext pt_i = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{(double)i});
        //         auto diff_idx = m_cc->EvalSub(pt_i, encrypted_idx);
        //         auto term_to_add_idx = m_cc->EvalMult(encrypted_bit, diff_idx);
        //         encrypted_idx = m_cc->EvalAdd(encrypted_idx, term_to_add_idx);
    
        //         std::cout << "  Round " << i << "/" << k-1 << " completed." << std::endl;
        //     }
    
        //     std::cout << "✓ Sequential comparison finished." << std::endl;
        //     return {encrypted_max, encrypted_idx};
        // }
    
    //     std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> findMaxSequential(
    //         const std::vector<Ciphertext<DCRTPoly>>& similarities, KeyHolder& oracle) {
            
    //         if (similarities.size() < 1) {
    //             throw std::runtime_error("Similarities vector cannot be empty.");
    //         }
    //         size_t k = similarities.size();
    //         std::cout << "\n========================================" << std::endl;
    //         std::cout << "Finding Max via Sequential Comparison" << std::endl;
    //         std::cout << "========================================" << std::endl;
    
    //         auto encrypted_max = similarities[0];
    //         Plaintext pt_idx_0 = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{0.0});
    //         auto encrypted_idx = m_cc->Encrypt(m_pk, pt_idx_0);
    
    //         std::random_device rd;
    //         std::mt19937 gen(rd());
    //         std::uniform_real_distribution<> distrib(-10000.0, 10000.0);
            
    //         for (size_t i = 1; i < k; ++i) {
    //             auto& challenger_val = similarities[i];
                
    //             auto ct_diff = m_cc->EvalSub(challenger_val, encrypted_max);
                
    //             double r = distrib(gen);
    //             auto ct_masked_diff = m_cc->EvalAdd(ct_diff, r);
    //             auto encrypted_bit = oracle.IsNewMax(ct_masked_diff, r);
    
    //             // Update max value (this part was correct)
    //             auto diff_for_update = m_cc->EvalSub(challenger_val, encrypted_max);
    //             auto term_to_add_val = m_cc->EvalMult(encrypted_bit, diff_for_update);
    //             encrypted_max = m_cc->EvalAdd(encrypted_max, term_to_add_val);
                
    //             // **FIX 2: STABLE INDEX UPDATE LOGIC**
    //             // The old way `EvalSub(Plaintext, Ciphertext)` is unstable in a deep loop
    //             // as the ciphertext's parameters change.
    //             // The robust way is to make both operands proper ciphertexts.
    //             Plaintext pt_i = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{(double)i});
    //             auto ct_i = m_cc->Encrypt(m_pk, pt_i); // Create a fresh ciphertext for `i`.
    
    //             // Now, both `ct_i` and `encrypted_idx` are well-formed ciphertexts.
    //             // The library will correctly align their levels before subtracting.
    //             auto diff_idx = m_cc->EvalSub(ct_i, encrypted_idx);
    //             auto term_to_add_idx = m_cc->EvalMult(encrypted_bit, diff_idx);
    //             encrypted_idx = m_cc->EvalAdd(encrypted_idx, term_to_add_idx);
    
    //             std::cout << "  Round " << i << "/" << k-1 << " completed." << std::endl;
    //         }
    
    //         std::cout << "✓ Sequential comparison finished." << std::endl;
    //         return {encrypted_max, encrypted_idx};
    //     }
    // private:
    //     CryptoContext<DCRTPoly> m_cc;
    //     PublicKey<DCRTPoly> m_pk;
    // };


//================================================================================
// NEW: Struct to bundle score and index
//================================================================================
struct EncryptedCandidate {
    Ciphertext<DCRTPoly> value;
    Ciphertext<DCRTPoly> index;
};

//================================================================================
// REWRITTEN: ComputeServer Class for Parallel Tournament
//================================================================================
class ComputeServer {
public:
    ComputeServer(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk) : m_cc(cc), m_pk(pk) {
        // Pre-encrypt Plaintext(1.0) for the selection logic
        Plaintext pt_one = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{1.0});
        m_ct_one = m_cc->Encrypt(m_pk, pt_one);
    }
    
    std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> findMaxTournament(
        const std::vector<Ciphertext<DCRTPoly>>& similarities, KeyHolder& oracle) {

        std::cout << "\n========================================" << std::endl;
        std::cout << "Finding Max via Parallel Tournament" << std::endl;
        std::cout << "========================================" << std::endl;

        // 1. Prepare initial candidates with their original indices
        std::vector<EncryptedCandidate> candidates;
        for (size_t i = 0; i < similarities.size(); ++i) {
            Plaintext pt_idx = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{(double)i});
            auto ct_idx = m_cc->Encrypt(m_pk, pt_idx);
            candidates.push_back({similarities[i], ct_idx});
        }

        int round = 1;
        while (candidates.size() > 1) {
            std::cout << "  Tournament Round " << round++ << " | "
                      << candidates.size() << " candidates -> ";

            std::vector<std::future<EncryptedCandidate>> futures;
            EncryptedCandidate odd_one_out;
            bool has_odd_one = (candidates.size() % 2 != 0);
            if (has_odd_one) {
                odd_one_out = candidates.back();
                candidates.pop_back();
            }

            // 2. Launch parallel comparisons for pairs
            for (size_t i = 0; i < candidates.size(); i += 2) {
                futures.push_back(
                    std::async(std::launch::async, &ComputeServer::secureCompareAndSelect, this, 
                               candidates[i], candidates[i+1], std::ref(oracle))
                );
            }

            // 3. Collect winners for the next round
            std::vector<EncryptedCandidate> next_round_candidates;
            for (auto& f : futures) {
                next_round_candidates.push_back(f.get());
            }
            if (has_odd_one) {
                next_round_candidates.push_back(odd_one_out); // The odd one gets a "bye"
            }
            candidates = std::move(next_round_candidates);
            std::cout << candidates.size() << " winners" << std::endl;
        }

        std::cout << "✓ Tournament finished." << std::endl;
        return {candidates[0].value, candidates[0].index};
    }

private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_pk;
    Ciphertext<DCRTPoly> m_ct_one;
    std::mutex m_rng_mutex; // Mutex for thread-safe random number generation

    EncryptedCandidate secureCompareAndSelect(
        EncryptedCandidate candA, EncryptedCandidate candB, KeyHolder& oracle) {
        
        // Use a lock to ensure each thread gets a unique random number
        double r;
        {
            std::lock_guard<std::mutex> lock(m_rng_mutex);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> distrib(-10000.0, 10000.0);
            r = distrib(gen);
        }

        // Comparison: Get Enc(bit), where bit = 1 if A > B, else 0
        auto ct_diff = m_cc->EvalSub(candA.value, candB.value);
        auto ct_masked_diff = m_cc->EvalAdd(ct_diff, r);
        auto encrypted_bit = oracle.IsNewMax(ct_masked_diff, r);

        // Homomorphic Selection: winner = bit * A + (1-bit) * B
        auto one_minus_bit = m_cc->EvalSub(m_ct_one, encrypted_bit);

        auto termA_val = m_cc->EvalMult(encrypted_bit, candA.value);
        auto termB_val = m_cc->EvalMult(one_minus_bit, candB.value);
        auto winner_val = m_cc->EvalAdd(termA_val, termB_val);

        auto termA_idx = m_cc->EvalMult(encrypted_bit, candA.index);
        auto termB_idx = m_cc->EvalMult(one_minus_bit, candB.index);
        auto winner_idx = m_cc->EvalAdd(termA_idx, termB_idx);
        
        return {winner_val, winner_idx};
    }
};


// Main function (updated to call the new server method)
int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║    Interactive Max via Sequential      ║" << std::endl;
    std::cout << "║       Double-Blind Comparison          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    try {
        auto [cryptoContext, keyPair] = generateCKKSKeys();
        auto [queryCt, encryptedStorage, queryVec, storageVecs] = 
            loadAndEncryptVectors(cryptoContext, keyPair.publicKey);
        auto similarities = computeCosineSimilarities(cryptoContext, queryCt, encryptedStorage);
        
        KeyHolder oracle(cryptoContext, keyPair.secretKey, keyPair.publicKey);
        ComputeServer server(cryptoContext, keyPair.publicKey);
        
        // **MODIFICATION**: Call the new sequential method
        auto [encrypted_max, encrypted_idx] = server.findMaxTournament(similarities, oracle);
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Decrypting Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        Plaintext maxPt, idxPt;
        cryptoContext->Decrypt(keyPair.secretKey, encrypted_max, &maxPt);
        cryptoContext->Decrypt(keyPair.secretKey, encrypted_idx, &idxPt);
        
        double maxVal = maxPt->GetRealPackedValue()[0];
        size_t idxVal = static_cast<size_t>(round(idxPt->GetRealPackedValue()[0]));
        
        std::cout << "✓ Decrypted maximum similarity: " << maxVal << std::endl;
        std::cout << "✓ Decrypted maximum index: " << idxVal << std::endl;
        
        // Verification (unchanged)
        std::cout << "\n========================================" << std::endl;
        std::cout << "Verification (Plaintext)" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::vector<double> plainSimilarities;
        for (const auto& storageVec : storageVecs) {
            double dot = std::inner_product(queryVec.begin(), queryVec.end(), storageVec.begin(), 0.0);
            plainSimilarities.push_back(dot);
        }
        
        auto plainMaxIt = std::max_element(plainSimilarities.begin(), plainSimilarities.end());
        size_t plainMaxIdx = std::distance(plainSimilarities.begin(), plainMaxIt);
        double plainMaxVal = *plainMaxIt;
        
        std::cout << "✓ Plaintext maximum similarity: " << plainMaxVal << std::endl;
        std::cout << "✓ Plaintext maximum index: " << plainMaxIdx << std::endl;
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Result Comparison" << std::endl;
        std::cout << "========================================" << std::endl;
        
        bool matchIdx = (idxVal == plainMaxIdx);
        bool matchVal = std::abs(maxVal - plainMaxVal) < 0.001;
        
        std::cout << "Index match: " << (matchIdx ? "✓ YES" : "✗ NO") << std::endl;
        std::cout << "Value match: " << (matchVal ? "✓ YES" : "✗ NO") 
                  << " (diff: " << std::abs(maxVal - plainMaxVal) << ")" << std::endl;
        
        if (matchIdx && matchVal) {
            std::cout << "\n✓✓✓ ALL TESTS PASSED ✓✓✓" << std::endl;
        } else {
            std::cout << "\n✗ TESTS FAILED" << std::endl;
        }
        
        return (matchIdx && matchVal) ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << std::endl;
        return 1;
    }
}