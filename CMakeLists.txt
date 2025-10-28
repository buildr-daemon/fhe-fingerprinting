cmake_minimum_required(VERSION 3.10)
project(MultipartyCKKS)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenFHE
set(OpenFHE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openfhe-development/build)
find_package(OpenFHE REQUIRED)

# Include OpenFHE headers
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

# Link directories
link_directories(${OpenFHE_LIBDIR})
link_directories(/opt/homebrew/opt/libomp/lib)

# Original example executable
add_executable(understanding_ckks understanding_ckks.cpp)
target_link_libraries(understanding_ckks ${OpenFHE_LIBRARIES})
set_target_properties(understanding_ckks PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Create a library for create_key functionality
add_library(create_key_lib STATIC harness/create_key.cpp)
target_compile_definitions(create_key_lib PRIVATE CREATE_KEY_AS_LIBRARY)
target_link_libraries(create_key_lib ${OpenFHE_LIBRARIES})

# Main executable that uses the create_key library
add_executable(main main.cpp)
target_link_libraries(main create_key_lib ${OpenFHE_LIBRARIES})
set_target_properties(main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Standalone create_key executable (optional, for direct execution)
add_executable(create_key harness/create_key.cpp)
target_link_libraries(create_key ${OpenFHE_LIBRARIES})
set_target_properties(create_key PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Encrypt vectors executable
add_executable(encrypt_vectors harness/encrypt_vectors.cpp)
target_link_libraries(encrypt_vectors ${OpenFHE_LIBRARIES})
set_target_properties(encrypt_vectors PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Compute similarity executable
add_executable(compute_similarity harness/compute_similarity.cpp)
target_link_libraries(compute_similarity ${OpenFHE_LIBRARIES})
set_target_properties(compute_similarity PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Decrypt result executable
add_executable(decrypt_result harness/decrypt_result.cpp)
target_link_libraries(decrypt_result ${OpenFHE_LIBRARIES})
set_target_properties(decrypt_result PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Plaintext similarity executable (no OpenFHE dependency)
add_executable(plaintext_similarity harness/plaintext_similarity.cpp)
set_target_properties(plaintext_similarity PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Find max executable
add_executable(find_max find_max/find_max.cpp)
target_link_libraries(find_max ${OpenFHE_LIBRARIES})
set_target_properties(find_max PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/find_max
)


# New main executable for interactive max
add_executable(new-main new-main.cpp)
target_link_libraries(new-main ${OpenFHE_LIBRARIES})
set_target_properties(new-main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
