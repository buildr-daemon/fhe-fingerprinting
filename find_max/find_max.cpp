#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>

using namespace lbcrypto;

/**
 * @brief Approximates the square root of encrypted values using an iterative method.
 *
 * This function implements Algorithm 2: Sqrt(x; d) from the paper.
 * It requires the plaintext inputs to be scaled into the range [0, 1).
 *
 * @param cryptoContext The crypto context for HE operations.
 * @param ct_x Ciphertext containing values to find the square root of.
 * @param d The number of iterations for the approximation. Higher 'd' increases precision but also computational depth.
 * @return A ciphertext containing the approximate square root of the input values.
 */
Ciphertext<DCRTPoly> encrypted_sqrt(CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly>& ct_x, int d) {
    // Sqrt(x; d) Algorithm
    // a_0 = x
    // b_0 = x - 1
    // Loop d times:
    //   a_{n+1} = a_n * (1 - b_n / 2)
    //   b_{n+1} = b_n^2 * (b_n - 3) / 4

    auto ct_a = ct_x;
    auto ct_b = cryptoContext->EvalSub(ct_x, 1.0);

    for (int i = 0; i < d; ++i) {
        auto b_div_2 = cryptoContext->EvalMult(ct_b, 0.5);
        auto term_in_paren = cryptoContext->EvalSub(1.0, b_div_2);
        ct_a = cryptoContext->EvalMultAndRelinearize(ct_a, term_in_paren);

        auto b_minus_3 = cryptoContext->EvalSub(ct_b, 3.0);
        auto b_squared = cryptoContext->EvalSquare(ct_b);
        auto numerator = cryptoContext->EvalMultAndRelinearize(b_squared, b_minus_3);
        ct_b = cryptoContext->EvalMult(numerator, 0.25);
    }
    return ct_a;
}

/**
 * @brief Computes the absolute value of encrypted numbers.
 *
 * This uses the identity |x| = sqrt(x^2).
 *
 * @param cryptoContext The crypto context for HE operations.
 * @param ct Ciphertext containing values to find the absolute value of.
 * @param sqrt_iterations The number of iterations for the internal square root approximation.
 * @return A ciphertext containing the approximate absolute values.
 */
Ciphertext<DCRTPoly> encrypted_abs(CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly>& ct, int sqrt_iterations) {
    // The input to Sqrt must be in [0, 1). Cosine similarities are in [-1, 1], so (a-b) is in [-2, 2].
    // (a-b)^2 is therefore in [0, 4]. We must scale it down by 1/4.
    auto ct_sq = cryptoContext->EvalSquare(ct);
    auto ct_sq_scaled = cryptoContext->EvalMult(ct_sq, 0.25); // Scale into [0, 1]

    auto sqrt_val = encrypted_sqrt(cryptoContext, ct_sq_scaled, sqrt_iterations);

    // We scaled down the input by 1/4, so we must scale up the output by sqrt(4)=2.
    return cryptoContext->EvalMult(sqrt_val, 2.0);
}

/**
 * @brief Computes the maximum of two encrypted numbers element-wise.
 *
 * This function implements Algorithm 3: Max(a,b;d) from the paper.
 * The formula is max(a,b) = (a+b)/2 + |a-b|/2.
 *
 * @param cryptoContext The crypto context for HE operations.
 * @param ct1 Ciphertext for the first set of numbers.
 * @param ct2 Ciphertext for the second set of numbers.
 * @param sqrt_iterations The number of iterations for the absolute value's square root approximation.
 * @return A ciphertext containing the element-wise maximum of ct1 and ct2.
 */
Ciphertext<DCRTPoly> encrypted_max_pair(CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly>& ct1, const Ciphertext<DCRTPoly>& ct2, int sqrt_iterations) {
    auto a_plus_b  = cryptoContext->EvalAdd(ct1, ct2);
    auto a_minus_b = cryptoContext->EvalSub(ct1, ct2);

    auto term1 = cryptoContext->EvalMult(a_plus_b, 0.5);
    auto abs_val = encrypted_abs(cryptoContext, a_minus_b, sqrt_iterations);
    auto term2 = cryptoContext->EvalMult(abs_val, 0.5);

    return cryptoContext->EvalAdd(term1, term2);
}

/**
 * @brief Finds the maximum value within an encrypted vector.
 *
 * This function implements the ArrayMax algorithm described in Section 4.2 of the paper[cite: 208, 212].
 * It performs a tournament-style reduction using rotations to find the max value.
 *
 * @param cryptoContext The crypto context for HE operations.
 * @param ct_vector The encrypted vector. The number of elements should be a power of two.
 * @param vec_size The number of elements in the plaintext vector.
 * @param sqrt_iterations The number of iterations for the square root approximation in each max operation.
 * @return A ciphertext where every slot contains the maximum value from the original vector.
 */
Ciphertext<DCRTPoly> findEncryptedMax(CryptoContext<DCRTPoly>& cryptoContext, Ciphertext<DCRTPoly> ct_vector, uint32_t vec_size, int sqrt_iterations) {
    if (vec_size == 0) throw std::runtime_error("Vector size cannot be zero.");
    if (log2(vec_size) != floor(log2(vec_size))) throw std::runtime_error("Vector size must be a power of two for this implementation.");

    auto current_vec = ct_vector;
    int rotations = log2(vec_size);

    for (int i = 0; i < rotations; ++i) {
        int rotation_amount = pow(2, rotations - 1 - i);
        auto rotated_vec = cryptoContext->EvalRotate(current_vec, rotation_amount);
        current_vec = encrypted_max_pair(cryptoContext, current_vec, rotated_vec, sqrt_iterations);
    }
    
    return current_vec;
}

int main() {
    // --- Step 1: Set up the CryptoContext ---
    CCParams<CryptoContextCKKSRNS> parameters;

    // The multiplicative depth is determined by the number of iterations in the sqrt function
    // and the number of reduction rounds in findEncryptedMax.
    // Depth of Sqrt(d): ~3d multiplications
    // Depth of MaxPair: Depth of Sqrt + 2 = 3d + 2
    // Depth of findEncryptedMax(logN): logN * (Depth of MaxPair)
    // We choose d=3 for a reasonable balance of precision and speed.
    int sqrt_iterations = 3;
    uint32_t vec_size = 16; // Must be a power of 2
    uint32_t num_reductions = log2(vec_size);

    // Depth = num_reductions * (1_add + 1_sub + 1_mult + depth_abs + 1_mult + 1_add)
    // depth_abs = 1_square + 1_mult + depth_sqrt + 1_mult
    // depth_sqrt = 3 * d multiplications
    // Let's estimate generously. d=3 -> depth_sqrt=9. depth_abs=12. depth_max_pair=14.
    // Total depth = log2(16) * 14 = 4 * 14 = 56. Let's set it higher to be safe.
    uint32_t multDepth = 60;
    
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(vec_size);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    auto keys = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keys.secretKey);
    cryptoContext->EvalRotateKeyGen(keys.secretKey, {1, 2, 4, 8}); // Rotations needed for reduction

    // --- Step 2: Prepare and Encrypt Data ---
    std::vector<double> cosine_similarities = {
        0.81, -0.22, 0.45, 0.91, -0.99, 0.11, 0.0, 0.5,
        0.67, -0.1, 0.33, 0.89, -0.5, 0.2, 0.77, 0.98
    };

    double true_max = *std::max_element(cosine_similarities.begin(), cosine_similarities.end());

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(cosine_similarities);
    auto ct_vector = cryptoContext->Encrypt(keys.publicKey, ptxt);

    // --- Step 3: Compute the Encrypted Maximum ---
    std::cout << "Finding maximum value in the encrypted vector..." << std::endl;
    Ciphertext<DCRTPoly> ct_max = findEncryptedMax(cryptoContext, ct_vector, vec_size, sqrt_iterations);

    // --- Step 4: Decrypt and Verify ---
    Plaintext result_ptxt;
    cryptoContext->Decrypt(keys.secretKey, ct_max, &result_ptxt);
    result_ptxt->SetLength(vec_size);

    std::vector<double> final_vec = result_ptxt->GetRealPackedValue();

    std::cout << "--- Verification ---" << std::endl;
    std::cout << "Original Vector Max: " << true_max << std::endl;
    std::cout << "Encrypted Computation Result (first slot): " << final_vec[0] << std::endl;
    std::cout << "Approximation Error: " << std::abs(true_max - final_vec[0]) << std::endl;
    
    // The result should be replicated across all slots
    std::cout << "\nAll slots of the final ciphertext should contain the max value:" << std::endl;
    for(size_t i = 0; i < final_vec.size(); ++i) {
        std::cout << final_vec[i] << " ";
    }
    std::cout << std::endl;

    return 0;
}