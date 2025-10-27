cmake_minimum_required(VERSION 3.10)
project(RankingTest)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenFHE
set(OpenFHE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/openfhe-development/build)
find_package(OpenFHE REQUIRED)

# Find OpenMP (C++ only, we don't need C)
find_package(OpenMP COMPONENTS CXX QUIET)

# Include OpenFHE headers
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

# Include OpenMP headers if found
if(OpenMP_CXX_FOUND)
    include_directories(${OpenMP_CXX_INCLUDE_DIR})
    message(STATUS "OpenMP found: ${OpenMP_CXX_INCLUDE_DIR}")
    # Add compiler flags for OpenMP
    add_compile_options(${OpenMP_CXX_FLAGS})
else()
    # Try to find OpenMP in common locations
    if(EXISTS "/opt/homebrew/opt/libomp/include")
        include_directories("/opt/homebrew/opt/libomp/include")
        message(STATUS "OpenMP found at /opt/homebrew/opt/libomp/include")
        add_compile_options(-Xpreprocessor -fopenmp -lomp)
    elseif(EXISTS "/usr/local/opt/libomp/include")
        include_directories("/usr/local/opt/libomp/include")
        message(STATUS "OpenMP found at /usr/local/opt/libomp/include")
        add_compile_options(-Xpreprocessor -fopenmp -lomp)
    else()
        message(WARNING "OpenMP not found - ranking functions will run sequentially")
        add_compile_definitions(DISABLE_OPENMP)
    endif()
endif()

# Include openfhe-statistics headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src)

# Link directories
link_directories(${OpenFHE_LIBDIR})
link_directories(/opt/homebrew/opt/libomp/lib)

# Add openfhe-statistics source files
set(OPENFHE_STATS_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src/ranking.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src/utils-basics.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src/utils-eval.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src/utils-matrices.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../resources/openfhe-statistics/src/utils-ptxt.cpp
)

# Create the ranking test executable
add_executable(ranking_test ranking_test.cpp ${OPENFHE_STATS_SRC})
target_link_libraries(ranking_test ${OpenFHE_LIBRARIES})

# Link OpenMP if found
if(OpenMP_CXX_FOUND)
    target_link_libraries(ranking_test ${OpenMP_CXX_LIBRARIES})
elseif(EXISTS "/opt/homebrew/opt/libomp/lib")
    target_link_directories(ranking_test PRIVATE "/opt/homebrew/opt/libomp/lib")
    target_link_libraries(ranking_test omp)
elseif(EXISTS "/usr/local/opt/libomp/lib")
    target_link_directories(ranking_test PRIVATE "/usr/local/opt/libomp/lib")
    target_link_libraries(ranking_test omp)
endif()

set_target_properties(ranking_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
