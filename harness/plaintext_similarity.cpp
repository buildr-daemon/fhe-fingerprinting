//==================================================================================
// Plaintext Similarity Computation Module
// 
// This program performs the same computations as compute_similarity.cpp but on
// plaintext data for comparison and validation purposes:
// 1. Loads plaintext storage and query vectors
// 2. Computes cosine similarities (dot products)
// 3. Computes maximum similarity
// 4. Performs threshold check
// 5. Saves results for comparison with encrypted results
//==================================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cstring>

namespace fs = std::filesystem;

// Simple NPY file reader for float32 arrays (same as in encrypt_vectors.cpp)
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

class PlaintextSimilarityComputer {
private:
    std::string dataPath;
    std::string resultsPath;
    double threshold;
    
public:
    PlaintextSimilarityComputer(const std::string& dataPath = "datasets", 
                               const std::string& resPath = "plaintext_results",
                               double tau = 0.85)
        : dataPath(dataPath), resultsPath(resPath), threshold(tau) {
        fs::create_directories(resultsPath);
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
    
    // Load vectors from NPY files
    std::pair<std::vector<double>, std::vector<std::vector<double>>> loadVectors(const std::string& datasetId) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Loading Plaintext Vectors" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::string datasetPath = dataPath + "/dataset_" + datasetId;
        
        // Load query vector
        std::string queryFile = datasetPath + "/query_vector.npy";
        std::cout << "\n[Loading] Query vector from: " << queryFile << std::endl;
        
        size_t queryVectors, queryDimension;
        std::vector<float> queryData = NPYReader::readNPY(queryFile, queryVectors, queryDimension);
        
        // Convert to double vector
        std::vector<double> queryVector(queryDimension);
        for (size_t i = 0; i < queryDimension; ++i) {
            queryVector[i] = static_cast<double>(queryData[i]);
        }
        
        // Normalize query vector to unit length
        std::cout << "\n[Normalization] Computing unit normalization for query vector..." << std::endl;
        auto normalizedQuery = normalizeVector(queryVector);
        
        // Verify normalization
        double norm = 0.0;
        for (double val : normalizedQuery) {
            norm += val * val;
        }
        norm = std::sqrt(norm);
        std::cout << "  Original norm: " << std::sqrt(std::inner_product(queryVector.begin(), queryVector.end(), queryVector.begin(), 0.0)) << std::endl;
        std::cout << "  Normalized norm: " << norm << std::endl;
        std::cout << "✓ Query vector normalized to unit length" << std::endl;
        
        std::cout << "✓ Query vector loaded: " << normalizedQuery.size() << " dimensions" << std::endl;
        
        // Load storage vectors
        std::string storageFile = datasetPath + "/storage_vectors.npy";
        std::cout << "\n[Loading] Storage vectors from: " << storageFile << std::endl;
        
        size_t numVectors, dimension;
        std::vector<float> storageData = NPYReader::readNPY(storageFile, numVectors, dimension);
        
        std::cout << "\n[Dataset] Loaded storage vectors" << std::endl;
        std::cout << "  Number of vectors: " << numVectors << std::endl;
        std::cout << "  Dimension: " << dimension << std::endl;
        
        // Convert to vector of double vectors
        std::vector<std::vector<double>> storageVectors;
        storageVectors.reserve(numVectors);
        
        for (size_t i = 0; i < numVectors; ++i) {
            std::vector<double> vec(dimension);
            for (size_t j = 0; j < dimension; ++j) {
                vec[j] = static_cast<double>(storageData[i * dimension + j]);
            }
            storageVectors.push_back(vec);
        }
        
        std::cout << "✓ Storage vectors loaded: " << storageVectors.size() << " vectors" << std::endl;
        
        return {normalizedQuery, storageVectors};
    }
    
    // Compute cosine similarity between two vectors
    double computeCosineSimilarity(const std::vector<double>& vec1, 
                                  const std::vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw std::runtime_error("Vector dimensions don't match");
        }
        
        // Compute dot product
        double dotProduct = 0.0;
        for (size_t i = 0; i < vec1.size(); ++i) {
            dotProduct += vec1[i] * vec2[i];
        }
        
        // Compute magnitudes
        double mag1 = 0.0, mag2 = 0.0;
        for (size_t i = 0; i < vec1.size(); ++i) {
            mag1 += vec1[i] * vec1[i];
            mag2 += vec2[i] * vec2[i];
        }
        mag1 = std::sqrt(mag1);
        mag2 = std::sqrt(mag2);
        
        // Avoid division by zero
        if (mag1 == 0.0 || mag2 == 0.0) {
            return 0.0;
        }
        
        return dotProduct / (mag1 * mag2);
    }
    
    // Compute all cosine similarities
    std::vector<double> computeAllSimilarities(const std::vector<double>& queryVector,
                                             const std::vector<std::vector<double>>& storageVectors) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Cosine Similarities" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::vector<double> similarities;
        similarities.reserve(storageVectors.size());
        
        std::cout << "\n[Processing] Computing " << storageVectors.size() << " similarities..." << std::endl;
        
        for (size_t i = 0; i < storageVectors.size(); ++i) {
            double similarity = computeCosineSimilarity(queryVector, storageVectors[i]);
            similarities.push_back(similarity);
            
            if ((i + 1) % 100 == 0 || i == 0 || i == storageVectors.size() - 1) {
                std::cout << "  Computed " << (i + 1) << "/" << storageVectors.size() 
                         << " similarities" << std::endl;
            }
        }
        
        std::cout << "✓ All similarities computed" << std::endl;
        return similarities;
    }
    
    // Compute maximum similarity
    double computeMaxSimilarity(const std::vector<double>& similarities) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Maximum Similarity" << std::endl;
        std::cout << "========================================" << std::endl;
        
        auto maxElement = std::max_element(similarities.begin(), similarities.end());
        double maxSimilarity = *maxElement;
        size_t maxIndex = std::distance(similarities.begin(), maxElement);
        
        std::cout << "\n[Result] Maximum similarity: " << maxSimilarity << std::endl;
        std::cout << "[Index] Vector index: " << maxIndex << std::endl;
        
        return maxSimilarity;
    }
    
    // Perform threshold check
    bool computeThresholdCheck(double maxSimilarity) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Computing Threshold Check" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::cout << "\n[Threshold] τ = " << threshold << std::endl;
        std::cout << "[Max Similarity] = " << maxSimilarity << std::endl;
        std::cout << "[Check] max > τ ? " << (maxSimilarity > threshold ? "YES" : "NO") << std::endl;
        
        bool isUnique = maxSimilarity > threshold;
        
        std::cout << "[Result] Vector is " << (isUnique ? "UNIQUE" : "NOT UNIQUE") << std::endl;
        
        return isUnique;
    }
    
    // Save results
    void saveResults(const std::vector<double>& similarities,
                    double maxSimilarity,
                    bool thresholdResult) {
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "Saving Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Save all similarities
        std::string similaritiesFile = resultsPath + "/all_similarities.txt";
        std::ofstream simFile(similaritiesFile);
        for (const auto& sim : similarities) {
            simFile << sim << "\n";
        }
        simFile.close();
        std::cout << "✓ All similarities saved to: " << similaritiesFile << std::endl;
        
        // Save max similarity
        std::string maxFile = resultsPath + "/max_similarity.txt";
        std::ofstream maxFileStream(maxFile);
        maxFileStream << maxSimilarity << "\n";
        maxFileStream.close();
        std::cout << "✓ Max similarity saved to: " << maxFile << std::endl;
        
        // Save threshold result
        std::string thresholdFile = resultsPath + "/threshold_result.txt";
        std::ofstream threshFile(thresholdFile);
        threshFile << (thresholdResult ? "1" : "0") << "\n";
        threshFile.close();
        std::cout << "✓ Threshold result saved to: " << thresholdFile << std::endl;
        
        // Save metadata
        std::ofstream metaFile(resultsPath + "/results_metadata.txt");
        metaFile << "threshold=" << threshold << "\n";
        metaFile << "num_similarities=" << similarities.size() << "\n";
        metaFile << "max_similarity=" << maxSimilarity << "\n";
        metaFile << "is_unique=" << (thresholdResult ? "true" : "false") << "\n";
        metaFile << "algorithm=plaintext_comparison\n";
        metaFile.close();
        std::cout << "✓ Metadata saved" << std::endl;
    }
    
    // Print detailed statistics
    void printStatistics(const std::vector<double>& similarities) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Similarity Statistics" << std::endl;
        std::cout << "========================================" << std::endl;
        
        if (similarities.empty()) {
            std::cout << "No similarities computed" << std::endl;
            return;
        }
        
        // Compute statistics
        double sum = std::accumulate(similarities.begin(), similarities.end(), 0.0);
        double mean = sum / similarities.size();
        
        double variance = 0.0;
        for (const auto& sim : similarities) {
            variance += (sim - mean) * (sim - mean);
        }
        variance /= similarities.size();
        double stdDev = std::sqrt(variance);
        
        auto minMax = std::minmax_element(similarities.begin(), similarities.end());
        double minSim = *minMax.first;
        double maxSim = *minMax.second;
        
        // Count similarities above threshold
        size_t aboveThreshold = std::count_if(similarities.begin(), similarities.end(),
                                            [this](double sim) { return sim > threshold; });
        
        std::cout << "\n[Statistics]" << std::endl;
        std::cout << "  Count: " << similarities.size() << std::endl;
        std::cout << "  Mean: " << mean << std::endl;
        std::cout << "  Std Dev: " << stdDev << std::endl;
        std::cout << "  Min: " << minSim << std::endl;
        std::cout << "  Max: " << maxSim << std::endl;
        std::cout << "  Above threshold (" << threshold << "): " << aboveThreshold << std::endl;
        std::cout << "  Percentage above threshold: " 
                 << (100.0 * aboveThreshold / similarities.size()) << "%" << std::endl;
    }
    
    void run(const std::string& datasetId) {
        try {
            // Load vectors
            auto [queryVector, storageVectors] = loadVectors(datasetId);
            if (storageVectors.empty()) {
                throw std::runtime_error("No storage vectors loaded");
            }
            
            std::cout << "\n[Note] Using separate query vector for comparison" << std::endl;
            
            // Compute all similarities
            auto similarities = computeAllSimilarities(queryVector, storageVectors);
            
            // Print statistics
            printStatistics(similarities);
            
            // Compute maximum
            double maxSim = computeMaxSimilarity(similarities);
            
            // Compute threshold check
            bool thresholdResult = computeThresholdCheck(maxSim);
            
            // Save results
            saveResults(similarities, maxSim, thresholdResult);
            
            // Print summary
            std::cout << "\n========================================" << std::endl;
            std::cout << "Plaintext Computation Complete" << std::endl;
            std::cout << "========================================" << std::endl;
            std::cout << "\n✓ All plaintext computations completed" << std::endl;
            std::cout << "✓ Results saved for comparison with encrypted results" << std::endl;
            std::cout << "\nNext step: Compare with encrypted results" << std::endl;
            std::cout << "========================================" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "\n✗ Plaintext computation failed: " << e.what() << std::endl;
            throw;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Plaintext Similarity Computer         ║" << std::endl;
    std::cout << "║  Comparison Module                      ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝" << std::endl;
    
    // Parse arguments
    std::string datasetId = "1";
    double threshold = 0.85;
    
    if (argc >= 2) {
        datasetId = argv[1];
    }
    if (argc >= 3) {
        threshold = std::stod(argv[2]);
    }
    
    std::cout << "\n[Parameters]" << std::endl;
    std::cout << "  Dataset: " << datasetId << std::endl;
    std::cout << "  Threshold: " << threshold << std::endl;
    
    try {
        PlaintextSimilarityComputer computer("datasets", "plaintext_results", threshold);
        computer.run(datasetId);
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << std::endl;
        return 1;
    }
}
