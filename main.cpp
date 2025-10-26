//==================================================================================
// Main Entry Point - Multiparty CKKS System
// 
// This is a central entry point that can trigger various operations:
// 1. Multiparty key generation
// 2. Vector encryption
// 3. Homomorphic computation (cosine similarity + max + threshold)
// 4. Threshold decryption
//==================================================================================

#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <cmath>
#include <cstdio>

// Forward declaration of the multiparty key generation function
void generateMultipartyKeys();

// Forward declaration of the comparison function
void compareResults();

void printUsage() {
    std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Multiparty CKKS System - Main Menu   ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    std::cout << "\nUsage: ./main [command] [options]" << std::endl;
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  keygen              - Generate multiparty keys for 2 users" << std::endl;
    std::cout << "  encrypt [dataset]   - Encrypt vectors from dataset (default: 1)" << std::endl;
    std::cout << "  compute [threshold] [max-method] - Compute encrypted max similarity (default: 0.85, softmax)" << std::endl;
    std::cout << "  decrypt             - Threshold decrypt the results" << std::endl;
    std::cout << "  plaintext [dataset] [threshold] - Compute plaintext similarity for comparison" << std::endl;
    std::cout << "  compare [dataset] [threshold] [max-method] - Compare plaintext vs encrypted max similarity" << std::endl;
    std::cout << "  full [dataset] [threshold] [max-method] - Run complete pipeline (keygen→encrypt→compute→decrypt)" << std::endl;
    std::cout << "  help                - Show this help message" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  ./main keygen              # Generate multiparty keys" << std::endl;
    std::cout << "  ./main encrypt 1           # Encrypt dataset_1" << std::endl;
    std::cout << "  ./main compute 0.85        # Compute with threshold 0.85 (softmax)" << std::endl;
    std::cout << "  ./main compute 0.85 pairwise # Compute with threshold 0.85 (pairwise)" << std::endl;
    std::cout << "  ./main decrypt             # Decrypt results" << std::endl;
    std::cout << "  ./main plaintext 1 0.85    # Compute plaintext similarity for comparison" << std::endl;
    std::cout << "  ./main compare 1 0.85 pairwise # Compare plaintext vs encrypted (pairwise)" << std::endl;
    std::cout << "  ./main full 1 0.85 pairwise # Run complete pipeline on dataset_1 (pairwise)" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    // If no arguments provided, show usage
    if (argc < 2) {
        printUsage();
        std::cout << "Running default action: Key Generation\n" << std::endl;
        
        try {
            generateMultipartyKeys();
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    
    std::string command = argv[1];
    
    if (command == "keygen") {
        try {
            generateMultipartyKeys();
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    else if (command == "encrypt") {
        std::string datasetId = "1";
        if (argc >= 3) {
            datasetId = argv[2];
        }
        std::string cmd = "./harness/encrypt_vectors " + datasetId;
        std::cout << "\n[Executing] " << cmd << "\n" << std::endl;
        return system(cmd.c_str());
    }
    else if (command == "compute") {
        std::string threshold = "0.85";
        std::string maxMethod = "softmax";
        if (argc >= 3) {
            threshold = argv[2];
        }
        if (argc >= 4) {
            maxMethod = argv[3];
            if (maxMethod != "softmax" && maxMethod != "pairwise") {
                std::cerr << "Error: Invalid max method. Use 'softmax' or 'pairwise'" << std::endl;
                return 1;
            }
        }
        std::string cmd = "./harness/compute_similarity " + threshold + " " + maxMethod;
        std::cout << "\n[Executing] " << cmd << "\n" << std::endl;
        return system(cmd.c_str());
    }
    else if (command == "decrypt") {
        std::string cmd = "./harness/decrypt_result";
        std::cout << "\n[Executing] " << cmd << "\n" << std::endl;
        return system(cmd.c_str());
    }
    else if (command == "plaintext") {
        std::string datasetId = "1";
        std::string threshold = "0.85";
        if (argc >= 3) {
            datasetId = argv[2];
        }
        if (argc >= 4) {
            threshold = argv[3];
        }
        std::string cmd = "./harness/plaintext_similarity " + datasetId + " " + threshold;
        std::cout << "\n[Executing] " << cmd << "\n" << std::endl;
        return system(cmd.c_str());
    }
    else if (command == "compare") {
        std::string datasetId = "1";
        std::string threshold = "0.85";
        std::string maxMethod = "softmax";
        if (argc >= 3) {
            datasetId = argv[2];
        }
        if (argc >= 4) {
            threshold = argv[3];
        }
        if (argc >= 5) {
            maxMethod = argv[4];
            if (maxMethod != "softmax" && maxMethod != "pairwise") {
                std::cerr << "Error: Invalid max method. Use 'softmax' or 'pairwise'" << std::endl;
                return 1;
            }
        }
        
        std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
        std::cout << "║   COMPARING PLAINTEXT VS ENCRYPTED     ║" << std::endl;
        std::cout << "╚════════════════════════════════════════╝" << std::endl;
        
        // Step 1: Generate multiparty keys
        std::cout << "\n[Step 1/6] Generating multiparty keys..." << std::endl;
        try {
            generateMultipartyKeys();
        } catch (const std::exception& e) {
            std::cerr << "Error in keygen: " << e.what() << std::endl;
            return 1;
        }
        
        // Step 2: Encrypt vectors
        std::cout << "\n[Step 2/6] Encrypting vectors..." << std::endl;
        std::string encryptCmd = "./harness/encrypt_vectors " + datasetId;
        if (system(encryptCmd.c_str()) != 0) {
            std::cerr << "Error in encryption" << std::endl;
            return 1;
        }
        
        // Step 3: Run plaintext computation
        std::cout << "\n[Step 3/6] Computing plaintext similarity..." << std::endl;
        std::string plaintextCmd = "./harness/plaintext_similarity " + datasetId + " " + threshold;
        if (system(plaintextCmd.c_str()) != 0) {
            std::cerr << "Error in plaintext computation" << std::endl;
            return 1;
        }
        
        // Step 4: Run encrypted computation
        std::cout << "\n[Step 4/6] Computing encrypted similarity..." << std::endl;
        std::string computeCmd = "./harness/compute_similarity " + threshold + " " + maxMethod;
        if (system(computeCmd.c_str()) != 0) {
            std::cerr << "Error in encrypted computation" << std::endl;
            return 1;
        }
        
        // Step 5: Decrypt results and capture output
        std::cout << "\n[Step 5/6] Decrypting encrypted results..." << std::endl;
        std::string decryptCmd = "./harness/decrypt_result > decrypt_output.txt 2>&1";
        if (system(decryptCmd.c_str()) != 0) {
            std::cerr << "Error in decryption" << std::endl;
            return 1;
        }
        
        // Step 6: Compare results
        std::cout << "\n[Step 6/6] Comparing results..." << std::endl;
        try {
            compareResults();
        } catch (const std::exception& e) {
            std::cerr << "Error comparing results: " << e.what() << std::endl;
            return 1;
        }
        
        return 0;
    }
    else if (command == "full") {
        std::string datasetId = "1";
        std::string threshold = "0.85";
        std::string maxMethod = "softmax";
        if (argc >= 3) {
            datasetId = argv[2];
        }
        if (argc >= 4) {
            threshold = argv[3];
        }
        if (argc >= 5) {
            maxMethod = argv[4];
            if (maxMethod != "softmax" && maxMethod != "pairwise") {
                std::cerr << "Error: Invalid max method. Use 'softmax' or 'pairwise'" << std::endl;
                return 1;
            }
        }
        
        std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
        std::cout << "║     FULL PIPELINE EXECUTION            ║" << std::endl;
        std::cout << "╚════════════════════════════════════════╝" << std::endl;
        
        // Step 1: Key generation
        std::cout << "\n[Step 1/4] Generating multiparty keys..." << std::endl;
        try {
            generateMultipartyKeys();
        } catch (const std::exception& e) {
            std::cerr << "Error in keygen: " << e.what() << std::endl;
            return 1;
        }
        
        // Step 2: Encryption
        std::cout << "\n[Step 2/4] Encrypting vectors..." << std::endl;
        std::string encryptCmd = "./harness/encrypt_vectors " + datasetId;
        if (system(encryptCmd.c_str()) != 0) {
            std::cerr << "Error in encryption" << std::endl;
            return 1;
        }
        
        // Step 3: Computation
        std::cout << "\n[Step 3/4] Computing encrypted max similarity..." << std::endl;
        std::string computeCmd = "./harness/compute_similarity " + threshold + " " + maxMethod;
        if (system(computeCmd.c_str()) != 0) {
            std::cerr << "Error in computation" << std::endl;
            return 1;
        }
        
        // Step 4: Decryption
        std::cout << "\n[Step 4/4] Threshold decryption..." << std::endl;
        std::string decryptCmd = "./harness/decrypt_result";
        if (system(decryptCmd.c_str()) != 0) {
            std::cerr << "Error in decryption" << std::endl;
            return 1;
        }
        
        std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
        std::cout << "║   PIPELINE COMPLETED SUCCESSFULLY      ║" << std::endl;
        std::cout << "╚════════════════════════════════════════╝" << std::endl;
        
        return 0;
    }
    else if (command == "help" || command == "-h" || command == "--help") {
        printUsage();
        return 0;
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        printUsage();
        return 1;
    }
    
    return 0;
}

// Function to compare plaintext and encrypted max similarity results
void compareResults() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "COMPARING PLAINTEXT VS ENCRYPTED RESULTS" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Read plaintext max similarity
    std::ifstream plaintextFile("plaintext_results/max_similarity.txt");
    if (!plaintextFile) {
        throw std::runtime_error("Cannot open plaintext_results/max_similarity.txt");
    }
    
    double plaintextMaxSim;
    plaintextFile >> plaintextMaxSim;
    plaintextFile.close();
    
    // Read encrypted max similarity from captured output
    std::ifstream decryptFile("decrypt_output.txt");
    if (!decryptFile) {
        throw std::runtime_error("Cannot open decrypt_output.txt");
    }
    
    double encryptedMaxSim = 0.0;
    std::string line;
    bool foundMaxSim = false;
    
    // Parse the decrypt output to find the max similarity value
    while (std::getline(decryptFile, line)) {
        // Look for the line containing the max similarity value
        if (line.find("Maximum Cosine Similarity") != std::string::npos) {
            // The next line should contain the value
            if (std::getline(decryptFile, line)) {
                // Extract the number from the formatted line
                // Format is typically: "│ 0.123456                   │"
                size_t start = line.find_first_of("0123456789.-");
                if (start != std::string::npos) {
                    size_t end = line.find_last_of("0123456789.");
                    if (end != std::string::npos) {
                        std::string valueStr = line.substr(start, end - start + 1);
                        encryptedMaxSim = std::stod(valueStr);
                        foundMaxSim = true;
                        break;
                    }
                }
            }
        }
    }
    decryptFile.close();
    
    if (!foundMaxSim) {
        std::cout << "\nWarning: Could not parse encrypted max similarity from output" << std::endl;
        std::cout << "Please check the decrypt_output.txt file manually" << std::endl;
        return;
    }
    
    // Calculate errors
    double absoluteError = std::abs(plaintextMaxSim - encryptedMaxSim);
    double relativeError = (plaintextMaxSim != 0.0) ? (absoluteError / std::abs(plaintextMaxSim)) * 100.0 : 0.0;
    
    // Display results
    std::cout << "\n╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║              RESULTS COMPARISON         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    std::cout << "\nPlaintext Max Similarity:  " << plaintextMaxSim << std::endl;
    std::cout << "Encrypted Max Similarity:   " << encryptedMaxSim << std::endl;
    std::cout << "\nAbsolute Error:            " << absoluteError << std::endl;
    std::cout << "Relative Error:             " << relativeError << "%" << std::endl;
    
    // Clean up temporary file
    std::remove("decrypt_output.txt");
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "COMPARISON COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
}

