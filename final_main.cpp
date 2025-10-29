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
#include <future>
#include <mutex>
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

//================================================================================
// MODIFIED: Key Generation for Threshold FHE
//================================================================================
std::tuple<CryptoContext<DCRTPoly>, PublicKey<DCRTPoly>, std::vector<PrivateKey<DCRTPoly>>>
generateThresholdCKKSKeys() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Generating Threshold CKKS Keys" << std::endl;
    std::cout << "========================================" << std::endl;

    uint32_t multDepth      = 20;
    uint32_t scaleModSize   = 50;
    uint32_t batchSize      = 1024;
    SecurityLevel secLevel = HEStd_128_classic;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(secLevel);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY); // Enable the multi-party features
    std::cout << "✓ CryptoContext initialized for Threshold FHE" << std::endl;

    // --- Simulate Multi-Party Key Generation ---
    const int numParties = 3;
    std::vector<KeyPair<DCRTPoly>> keyPairs;
    
    // First party generates initial key pair
    keyPairs.push_back(cc->KeyGen());
    
    // Subsequent parties use MultipartyKeyGen in sequence
    for (int i = 1; i < numParties; ++i) {
        keyPairs.push_back(cc->MultipartyKeyGen(keyPairs[i-1].publicKey));
    }
    
    // The final public key (from the last party) is the collective public key
    auto collectivePublicKey = keyPairs.back().publicKey;

    // Collect all secret keys (these would be held by different parties in reality)
    std::vector<PrivateKey<DCRTPoly>> secretKeyShares;
    for(const auto& kp : keyPairs) {
        secretKeyShares.push_back(kp.secretKey);
    }
    std::cout << "✓ " << numParties << " secret key shares and 1 collective public key generated" << std::endl;
    
    // --- Generate Evaluation Keys in a Distributed Manner ---
    // EvalMult - following the pattern from threshold-fhe-5p.cpp
    auto evalMultKey1 = cc->KeySwitchGen(keyPairs[0].secretKey, keyPairs[0].secretKey);
    auto evalMultKey2 = cc->MultiKeySwitchGen(keyPairs[1].secretKey, keyPairs[1].secretKey, evalMultKey1);
    auto evalMultKey3 = cc->MultiKeySwitchGen(keyPairs[2].secretKey, keyPairs[2].secretKey, evalMultKey1);
    
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey1, evalMultKey2, keyPairs[1].publicKey->GetKeyTag());
    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, keyPairs[2].publicKey->GetKeyTag());
    
    auto evalMultCABC = cc->MultiMultEvalKey(keyPairs[2].secretKey, evalMultABC, keyPairs[2].publicKey->GetKeyTag());
    auto evalMultBABC = cc->MultiMultEvalKey(keyPairs[1].secretKey, evalMultABC, keyPairs[2].publicKey->GetKeyTag());
    auto evalMultAABC = cc->MultiMultEvalKey(keyPairs[0].secretKey, evalMultABC, keyPairs[2].publicKey->GetKeyTag());
    
    auto evalMultBCABC = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultCABC, evalMultBABC->GetKeyTag());
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultBCABC, keyPairs[2].publicKey->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});
    
    // EvalSum - following the pattern from threshold-fhe-5p.cpp
    cc->EvalSumKeyGen(keyPairs[0].secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
        cc->GetEvalSumKeyMap(keyPairs[0].secretKey->GetKeyTag()));
    
    auto evalSumKeysB = cc->MultiEvalSumKeyGen(keyPairs[1].secretKey, evalSumKeys, keyPairs[1].publicKey->GetKeyTag());
    auto evalSumKeysC = cc->MultiEvalSumKeyGen(keyPairs[2].secretKey, evalSumKeys, keyPairs[2].publicKey->GetKeyTag());
    
    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, keyPairs[1].publicKey->GetKeyTag());
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, keyPairs[2].publicKey->GetKeyTag());
    cc->InsertEvalSumKey(evalSumKeysJoin);
    
    // Rotation Keys - use regular EvalRotateKeyGen with first secret key share
    std::vector<int32_t> rotation_indices;
    for (int i = 1; i < batchSize; i *= 2) {
        rotation_indices.push_back(i);
    }
    cc->EvalRotateKeyGen(secretKeyShares[0], rotation_indices);
    std::cout << "✓ All distributed evaluation keys generated" << std::endl;
    
    return std::make_tuple(cc, collectivePublicKey, secretKeyShares);
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
    std::cout << "✓ All vectors loaded and encrypted (with collective public key)" << std::endl;
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
// MODIFIED: KeyHolder now manages multiple secret key shares for threshold decryption
//================================================================================
class KeyHolder {
public:
    KeyHolder(CryptoContext<DCRTPoly> cc, const std::vector<PrivateKey<DCRTPoly>>& skShares, PublicKey<DCRTPoly> pk)
        : m_cc(cc), m_skShares(skShares), m_pk(pk) {}

    Ciphertext<DCRTPoly> IsNewMax(Ciphertext<DCRTPoly> ct_masked_diff, double r) {
        // --- Secure Multi-Party Decryption ---
        std::vector<Ciphertext<DCRTPoly>> partialDecrypts;
        
        // 1. Generate partial decryptions from each key holder
        // The first party is the "lead" party in this protocol
        partialDecrypts.push_back(m_cc->MultipartyDecryptLead({ct_masked_diff}, m_skShares[0])[0]);
        for (size_t i = 1; i < m_skShares.size(); ++i) {
            partialDecrypts.push_back(m_cc->MultipartyDecryptMain({ct_masked_diff}, m_skShares[i])[0]);
        }

        // 2. Fuse the partial decryptions to get the final plaintext
        Plaintext pt_masked_diff;
        m_cc->MultipartyDecryptFusion(partialDecrypts, &pt_masked_diff);
        
        double v = pt_masked_diff->GetRealPackedValue()[0];

        // Comparison and re-encryption logic remains the same
        double bit = (v > r) ? 1.0 : 0.0;
        
        std::vector<double> bit_vec = {bit};
        Plaintext pt_bit = m_cc->MakeCKKSPackedPlaintext(bit_vec);
        return m_cc->Encrypt(m_pk, pt_bit);
    }

private:
    CryptoContext<DCRTPoly> m_cc;
    std::vector<PrivateKey<DCRTPoly>> m_skShares; // Holds all secret keys
    PublicKey<DCRTPoly> m_pk; // The collective public key
};


// Struct EncryptedCandidate and ComputeServer Class (unchanged)
struct EncryptedCandidate {
    Ciphertext<DCRTPoly> value;
    Ciphertext<DCRTPoly> index;
};

class ComputeServer {
public:
    ComputeServer(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk) : m_cc(cc), m_pk(pk) {
        Plaintext pt_one = m_cc->MakeCKKSPackedPlaintext(std::vector<double>{1.0});
        m_ct_one = m_cc->Encrypt(m_pk, pt_one);
    }
    
    std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> findMaxTournament(
        const std::vector<Ciphertext<DCRTPoly>>& similarities, KeyHolder& oracle) {

        std::cout << "\n========================================" << std::endl;
        std::cout << "Finding Max via Parallel Tournament" << std::endl;
        std::cout << "========================================" << std::endl;

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

            for (size_t i = 0; i < candidates.size(); i += 2) {
                futures.push_back(
                    std::async(std::launch::async, &ComputeServer::secureCompareAndSelect, this, 
                               candidates[i], candidates[i+1], std::ref(oracle))
                );
            }

            std::vector<EncryptedCandidate> next_round_candidates;
            for (auto& f : futures) {
                next_round_candidates.push_back(f.get());
            }
            if (has_odd_one) {
                next_round_candidates.push_back(odd_one_out);
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
    std::mutex m_rng_mutex;

    EncryptedCandidate secureCompareAndSelect(
        EncryptedCandidate candA, EncryptedCandidate candB, KeyHolder& oracle) {
        
        double r;
        {
            std::lock_guard<std::mutex> lock(m_rng_mutex);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> distrib(-10000.0, 10000.0);
            r = distrib(gen);
        }

        auto ct_diff = m_cc->EvalSub(candA.value, candB.value);
        auto ct_masked_diff = m_cc->EvalAdd(ct_diff, r);
        auto encrypted_bit = oracle.IsNewMax(ct_masked_diff, r);

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

//================================================================================
// MODIFIED: Main function to use the Threshold FHE scheme
//================================================================================
int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║ Interactive Max via Threshold FHE &    ║" << std::endl;
    std::cout << "║    Double-Blind Comparison             ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    try {
        // Use the new threshold key generation function
        auto [cryptoContext, collectivePubKey, secretKeyShares] = generateThresholdCKKSKeys();
        
        auto [queryCt, encryptedStorage, queryVec, storageVecs] = 
            loadAndEncryptVectors(cryptoContext, collectivePubKey);
        
        auto similarities = computeCosineSimilarities(cryptoContext, queryCt, encryptedStorage);
        
        // The oracle now holds all secret key shares
        KeyHolder oracle(cryptoContext, secretKeyShares, collectivePubKey);
        ComputeServer server(cryptoContext, collectivePubKey);
        
        auto [encrypted_max, encrypted_idx] = server.findMaxTournament(similarities, oracle);
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Decrypting Results (Threshold Protocol)" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // --- Final Decryption using the Multi-Party Protocol ---
        Plaintext maxPt, idxPt;
        
        // Decrypt Max Value
        std::vector<Ciphertext<DCRTPoly>> partialMax;
        partialMax.push_back(cryptoContext->MultipartyDecryptLead({encrypted_max}, secretKeyShares[0])[0]);
        for (size_t i = 1; i < secretKeyShares.size(); ++i) {
            partialMax.push_back(cryptoContext->MultipartyDecryptMain({encrypted_max}, secretKeyShares[i])[0]);
        }
        cryptoContext->MultipartyDecryptFusion(partialMax, &maxPt);

        // Decrypt Max Index
        std::vector<Ciphertext<DCRTPoly>> partialIdx;
        partialIdx.push_back(cryptoContext->MultipartyDecryptLead({encrypted_idx}, secretKeyShares[0])[0]);
        for (size_t i = 1; i < secretKeyShares.size(); ++i) {
            partialIdx.push_back(cryptoContext->MultipartyDecryptMain({encrypted_idx}, secretKeyShares[i])[0]);
        }
        cryptoContext->MultipartyDecryptFusion(partialIdx, &idxPt);
        
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