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
#include "openfhe.h"

using namespace lbcrypto;

// NPY File Reader for loading numpy arrays
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
        
        // Read data
        size_t numElements = numVectors * dimension;
        std::vector<float> data(numElements);
        file.read(reinterpret_cast<char*>(data.data()), numElements * sizeof(float));
        
        return data;
    }
};

// Key generation for CKKS scheme
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> generateCKKSKeys() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Generating CKKS Keys" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // CKKS parameters
    // NOTE: The required depth for HT protocol is much lower. 
    // Depth 5 is sufficient for k <= 1000.
    uint32_t multDepth = 15; 
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 1024; // This must be >= your vector dimension (512)
    SecurityLevel securityLevel = HEStd_128_classic;
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    
    // Enable required features
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    
    std::cout << "✓ CryptoContext initialized" << std::endl;
    std::cout << "  Ring Dimension: " << cryptoContext->GetRingDimension() << std::endl;
    std::cout << "  Batch Size: " << batchSize << std::endl;
    
    // Generate key pair
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    std::cout << "✓ Key pair generated" << std::endl;
    
    // Generate evaluation keys
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    
    // For the Permute function, we only need rotations up to k.
    // Generating for a bit more is safe and doesn't cost much.
    size_t k_max = 100; // Set this to the max number of vectors you're testing
    std::vector<int32_t> rotation_indices;
    for (size_t i = 1; i < k_max; ++i) {
         rotation_indices.push_back(i);
         rotation_indices.push_back(-i);
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indices);
    std::cout << "✓ Rotation keys generated" << std::endl;
    
    return std::make_tuple(cryptoContext, keyPair);
}

// Load and normalize query vector
std::vector<double> normalizeVector(const std::vector<double>& vec) {
    double norm = std::sqrt(std::inner_product(vec.begin(), vec.end(), vec.begin(), 0.0));
    if (norm == 0.0) {
        throw std::runtime_error("Cannot normalize zero vector");
    }
    std::vector<double> normalized(vec.size());
    std::transform(vec.begin(), vec.end(), normalized.begin(), 
                   [norm](double val) { return val / norm; });
    return normalized;
}

// Load and encrypt vectors from dataset
std::tuple<Ciphertext<DCRTPoly>, std::vector<Ciphertext<DCRTPoly>>, std::vector<double>, std::vector<std::vector<double>>>
loadAndEncryptVectors(CryptoContext<DCRTPoly> cryptoContext, PublicKey<DCRTPoly> publicKey) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Loading and Encrypting Vectors" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Load query vector
    size_t numVectorsQ, dimQ;
    std::vector<float> queryData = NPYReader::readNPY("datasets/dataset_1/query_vector.npy", numVectorsQ, dimQ);
    std::vector<double> queryVec(dimQ);
    std::transform(queryData.begin(), queryData.end(), queryVec.begin(), [](float f) { return static_cast<double>(f); });
    
    std::cout << "✓ Query vector loaded: " << dimQ << " dimensions" << std::endl;
    
    // Load storage vectors
    size_t numVectors, dimension;
    std::vector<float> storageData = NPYReader::readNPY("datasets/dataset_1/storage_vectors.npy", numVectors, dimension);
    
    std::cout << "✓ Storage vectors loaded: " << numVectors << " vectors, " << dimension << " dimensions" << std::endl;
    
    // Normalize query vector
    std::vector<double> normalizedQuery = normalizeVector(queryVec);
    double norm = std::sqrt(std::inner_product(normalizedQuery.begin(), normalizedQuery.end(), normalizedQuery.begin(), 0.0));
    std::cout << "✓ Query vector normalized to unit length (norm: " << norm << ")" << std::endl;
    
    // Convert storage vectors to double
    std::vector<std::vector<double>> storageVecs(numVectors, std::vector<double>(dimension));
    for (size_t i = 0; i < numVectors; ++i) {
        for (size_t j = 0; j < dimension; ++j) {
            storageVecs[i][j] = static_cast<double>(storageData[i * dimension + j]);
        }
    }
    
    // Encrypt query vector
    Plaintext queryPt = cryptoContext->MakeCKKSPackedPlaintext(normalizedQuery);
    Ciphertext<DCRTPoly> queryCt = cryptoContext->Encrypt(publicKey, queryPt);
    std::cout << "✓ Query vector encrypted" << std::endl;
    
    // Encrypt storage vectors
    std::cout << "\n[Encryption] Encrypting " << numVectors << " storage vectors..." << std::endl;
    std::vector<Ciphertext<DCRTPoly>> encryptedStorage;
    for (size_t i = 0; i < numVectors; ++i) {
        Plaintext pt = cryptoContext->MakeCKKSPackedPlaintext(storageVecs[i]);
        Ciphertext<DCRTPoly> ct = cryptoContext->Encrypt(publicKey, pt);
        encryptedStorage.push_back(ct);
        
        if ((i + 1) % 100 == 0 || i == 0 || i == numVectors - 1) {
            std::cout << "  Encrypted " << (i + 1) << "/" << numVectors << " vectors" << std::endl;
        }
    }
    
    std::cout << "✓ All vectors encrypted" << std::endl;
    
    return std::make_tuple(queryCt, encryptedStorage, normalizedQuery, storageVecs);
}

// Compute cosine similarities (dot products)
std::vector<Ciphertext<DCRTPoly>> computeCosineSimilarities(
    CryptoContext<DCRTPoly> cryptoContext,
    Ciphertext<DCRTPoly> queryCt,
    const std::vector<Ciphertext<DCRTPoly>>& storageVecs) {
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Computing Cosine Similarities" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<Ciphertext<DCRTPoly>> similarities;
    
    for (size_t i = 0; i < storageVecs.size(); ++i) {
        // Element-wise multiplication
        auto product = cryptoContext->EvalMult(queryCt, storageVecs[i]);
        
        // Sum all elements
        auto similarity = cryptoContext->EvalSum(product, cryptoContext->GetEncodingParams()->GetBatchSize());
        similarities.push_back(similarity);
        
        if ((i + 1) % 100 == 0 || i == 0 || i == storageVecs.size() - 1) {
            std::cout << "  Computed " << (i + 1) << "/" << storageVecs.size() << " similarities" << std::endl;
        }
    }
    
    std::cout << "✓ All similarities computed" << std::endl;
    return similarities;
}

//================================================================================
// KeyHolder (Oracle) Class
// Simulates the client who holds the secret key.
//================================================================================
class KeyHolder {
public:
    KeyHolder(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> sk, PublicKey<DCRTPoly> pk)
        : m_cc(cc), m_sk(sk), m_pk(pk) {}

    /**
     * @brief Implements the client-side of the HESign protocol (Protocol 1).
     * The oracle receives a masked ciphertext, decrypts it, computes the sign of each element,
     * re-encrypts the signs, and returns the result.
     * @param ct_masked_sub Ciphertext containing [x * r].
     * @return Ciphertext containing [sign(x * r)].
     */
    Ciphertext<DCRTPoly> HeSign(Ciphertext<DCRTPoly> ct_masked_sub) {
        Plaintext pt_masked_sub;
        m_cc->Decrypt(m_sk, ct_masked_sub, &pt_masked_sub);
        std::vector<double> masked_sub = pt_masked_sub->GetRealPackedValue();

        std::vector<double> signed_masked_sub(masked_sub.size());
        for (size_t i = 0; i < masked_sub.size(); ++i) {
            if (masked_sub[i] > 0)
                signed_masked_sub[i] = 1.0;
            else if (masked_sub[i] < 0)
                signed_masked_sub[i] = -1.0;
            else
                signed_masked_sub[i] = 0.0;
        }

        Plaintext pt_signed = m_cc->MakeCKKSPackedPlaintext(signed_masked_sub);
        return m_cc->Encrypt(m_pk, pt_signed);
    }

    /**
     * @brief Implements the client-side of the final argmax step.
     * The oracle receives scores, decrypts them, finds the index of the maximum score,
     * creates and encrypts a one-hot vector at that index, and returns it.
     * @param ct_scores Ciphertext containing the scores.
     * @param num_values The number of original values (k).
     * @return Encrypted one-hot vector [p].
     */
    Ciphertext<DCRTPoly> FindArgmax(Ciphertext<DCRTPoly> ct_scores, size_t num_values) {
        Plaintext pt_scores;
        m_cc->Decrypt(m_sk, ct_scores, &pt_scores);
        std::vector<double> scores = pt_scores->GetRealPackedValue();

        // Find the index of the maximum score among the first 'num_values' elements
        size_t max_idx = 0;
        double max_val = scores[0];
        for (size_t i = 1; i < num_values; ++i) {
            if (scores[i] > max_val) {
                max_val = scores[i];
                max_idx = i;
            }
        }
        
        // Create a one-hot vector indicating the position of the max value
        std::vector<double> p_vec(scores.size(), 0.0);
        p_vec[max_idx] = 1.0;

        Plaintext pt_p = m_cc->MakeCKKSPackedPlaintext(p_vec);
        return m_cc->Encrypt(m_pk, pt_p);
    }

private:
    CryptoContext<DCRTPoly> m_cc;
    PrivateKey<DCRTPoly> m_sk;
    PublicKey<DCRTPoly> m_pk;
};


//================================================================================
// ComputeServer Class (Modified with HEArgmax-HT Protocol, No Permutation)
// Simulates the server that performs computations on encrypted data.
//================================================================================
class ComputeServer {
public:
    ComputeServer(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk) : m_cc(cc), m_pk(pk) {}

    std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> findMaxInteractive(
        const std::vector<Ciphertext<DCRTPoly>>& similarities, KeyHolder& oracle) {
        if (similarities.empty()) {
            throw std::runtime_error("Input similarities vector cannot be empty.");
        }
        size_t k = similarities.size();
        std::cout << "Running interactive argmax for " << k << " values (Loose HT Protocol)..." << std::endl;

        // --- SERVER-SIDE: Protocol 2, Lines 1-5 ---
        // Compute all pairwise subtractions [sub_ij] = [x_i] - [x_j]
        // And get their signs interactively using HESign
        std::vector<std::vector<Ciphertext<DCRTPoly>>> sign_sub_matrix(k, std::vector<Ciphertext<DCRTPoly>>(k));
        
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < k; ++j) {
                if (i == j) continue;

                auto ct_sub_ij = m_cc->EvalSub(similarities[i], similarities[j]);

                // --- INTERACTIVE: HESign Protocol for each subtraction ---
                std::vector<double> r_vec(1, 0.0); // Only need one random number
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_real_distribution<> distrib(1.0, 10.0);
                r_vec[0] = (distrib(gen) > 5.0) ? distrib(gen) : -distrib(gen);
                
                auto pt_r = m_cc->MakeCKKSPackedPlaintext(r_vec);
                auto ct_masked_sub = m_cc->EvalMult(ct_sub_ij, pt_r);
                
                auto ct_signed_masked_sub = oracle.HeSign(ct_masked_sub);
                
                std::vector<double> sign_r_vec = { (r_vec[0] > 0) ? 1.0 : -1.0 };
                auto pt_sign_r = m_cc->MakeCKKSPackedPlaintext(sign_r_vec);
                sign_sub_matrix[i][j] = m_cc->EvalMult(ct_signed_masked_sub, pt_sign_r);
            }
        }
        std::cout << "✓ Completed all HESign interactions" << std::endl;


        // --- SERVER-SIDE: Protocol 2, Lines 6-10 ---
        // Compute score for each value by summing the signs
        std::vector<double> zeros(1, 0.0);
        auto pt_zero = m_cc->MakeCKKSPackedPlaintext(zeros);
        auto encrypted_zero = m_cc->Encrypt(m_pk, pt_zero);

        std::vector<Ciphertext<DCRTPoly>> ct_scores(k);
        for(size_t i=0; i < k; ++i) {
            ct_scores[i] = encrypted_zero->Clone();
            for (size_t j = 0; j < k; ++j) {
                if (i == j) continue;
                ct_scores[i] = m_cc->EvalAdd(ct_scores[i], sign_sub_matrix[i][j]);
            }
        }
        std::cout << "✓ Computed encrypted scores" << std::endl;

        // --- MODIFICATION: Permutation step (Protocol 2, line 11) is REMOVED ---
        // We now send the scores directly to the client/oracle.
        auto ct_scores_merged = m_cc->EvalMerge(ct_scores);
        
        // --- INTERACTIVE: Send scores to oracle to find argmax ---
        // The oracle now returns the one-hot vector for the true argmax, not a permuted one.
        auto ct_m_onehot = oracle.FindArgmax(ct_scores_merged, k);

        // --- MODIFICATION: Un-permutation step (Protocol 2, line 19) is REMOVED ---
        // The returned one-hot vector `ct_m_onehot` can be used directly.

        // --- SERVER-SIDE: Calculate final results using the one-hot vector ---
        auto ct_x = m_cc->EvalMerge(similarities);
        auto ct_prod_max = m_cc->EvalMult(ct_x, ct_m_onehot);
        auto encrypted_max = m_cc->EvalSum(ct_prod_max, k);

        // The vector size for MakeCKKSPackedPlaintext must not exceed BatchSize.
        // It was incorrectly initialized with `ringDim`.
        size_t batchSize = m_cc->GetEncodingParams()->GetBatchSize();
        std::vector<double> indices(batchSize, 0.0);
        for(size_t i=0; i<k; ++i) indices[i] = static_cast<double>(i);
        auto pt_indices = m_cc->MakeCKKSPackedPlaintext(indices);
        auto ct_prod_idx = m_cc->EvalMult(ct_m_onehot, pt_indices);
        auto encrypted_idx = m_cc->EvalSum(ct_prod_idx, k);

        return {encrypted_max, encrypted_idx};
    }

private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_pk;
};

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Interactive Max CKKS                 ║" << std::endl;
    std::cout << "║  (No Permutation / Loose Version)     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    try {
        // 1. Generate keys
        auto [cryptoContext, keyPair] = generateCKKSKeys();
        
        // 2. Load and encrypt vectors
        auto [queryCt, encryptedStorage, queryVec, storageVecs] = 
            loadAndEncryptVectors(cryptoContext, keyPair.publicKey);
        
        // 3. Compute cosine similarities
        auto similarities = computeCosineSimilarities(cryptoContext, queryCt, encryptedStorage);
        
        // 4. Create KeyHolder and ComputeServer
        KeyHolder oracle(cryptoContext, keyPair.secretKey, keyPair.publicKey);
        ComputeServer server(cryptoContext, keyPair.publicKey);
        
        // 5. Run interactive max
        auto [encrypted_max, encrypted_idx] = server.findMaxInteractive(similarities, oracle);
        
        // 6. Decrypt results
        std::cout << "\n========================================" << std::endl;
        std::cout << "Decrypting Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        Plaintext maxPt, idxPt;
        cryptoContext->Decrypt(keyPair.secretKey, encrypted_max, &maxPt);
        cryptoContext->Decrypt(keyPair.secretKey, encrypted_idx, &idxPt);
        
        std::vector<double> maxVal = maxPt->GetRealPackedValue();
        std::vector<double> idxVal = idxPt->GetRealPackedValue();
        
        std::cout << "✓ Decrypted maximum similarity: " << maxVal[0] << std::endl;
        std::cout << "✓ Decrypted maximum index: " << static_cast<size_t>(round(idxVal[0])) << std::endl;
        
        // 7. Verify with plaintext computation
        std::cout << "\n========================================" << std::endl;
        std::cout << "Verification (Plaintext)" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Compute plaintext similarities
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
        
        // Compare results
        std::cout << "\n========================================" << std::endl;
        std::cout << "Result Comparison" << std::endl;
        std::cout << "========================================" << std::endl;
        
        bool matchIdx = (static_cast<size_t>(round(idxVal[0])) == plainMaxIdx);
        bool matchVal = std::abs(maxVal[0] - plainMaxVal) < 0.001;
        
        std::cout << "Index match: " << (matchIdx ? "✓ YES" : "✗ NO") << std::endl;
        std::cout << "Value match: " << (matchVal ? "✓ YES" : "✗ NO") 
                  << " (diff: " << std::abs(maxVal[0] - plainMaxVal) << ")" << std::endl;
        
        if (matchIdx && matchVal) {
            std::cout << "\n✓✓✓ ALL TESTS PASSED ✓✓✓" << std::endl;
        } else {
            std::cout << "\n✗ TESTS FAILED" << std::endl;
        }
        
        std::cout << "========================================" << std::endl;
        
        return (matchIdx && matchVal) ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << std::endl;
        return 1;
    }
}