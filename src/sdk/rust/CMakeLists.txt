# src/sdk/rust/CMakeLists.txt
# AppMesh Rust SDK CMake configuration
cmake_minimum_required(VERSION 3.15)

# Find Rust compiler
find_program(CARGO cargo)
if(NOT CARGO)
    message(FATAL_ERROR "Cargo not found. Please install Rust: https://rustup.rs")
endif()

# Create custom target for AppMesh Rust SDK
add_custom_target(appmesh_rust_sdk ALL
    COMMAND ${CARGO} build --release
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building AppMesh Rust SDK"
)

# Install targets
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/target/release/
    DESTINATION lib
    FILES_MATCHING 
    PATTERN "libappmesh.rlib"    # Linux/macOS static lib
    PATTERN "libappmesh.so"      # Linux shared lib
    PATTERN "appmesh.dll"        # Windows dynamic lib
    PATTERN "appmesh.lib"        # Windows static lib
    PATTERN "appmesh.dylib"      # macOS dynamic lib
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/
    DESTINATION include/appmesh/rust
    FILES_MATCHING PATTERN "*.rs"
)

# Add test target
add_custom_target(appmesh_rust_test
    COMMAND ${CARGO} test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running AppMesh Rust SDK tests"
)