cmake_minimum_required(VERSION 3.22)
project(soci_sgx_sdk VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(SOCI_SGX_MODE "OFF" CACHE STRING "OFF, SIM or HW")
set_property(CACHE SOCI_SGX_MODE PROPERTY STRINGS OFF SIM HW)
option(SOCI_BUILD_PYTHON "Build pybind11 module" ON)
option(SOCI_BUILD_JAVA "Build JNI library" ON)
option(SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS "Enable SOCI-plus experimental secure protocols" OFF)

if(NOT SOCI_SGX_MODE MATCHES "^(OFF|SIM|HW)$")
  message(FATAL_ERROR "SOCI_SGX_MODE must be OFF, SIM, or HW")
endif()
if(NOT SOCI_SGX_MODE STREQUAL "OFF")
  if(NOT DEFINED ENV{SGX_SDK})
    set(ENV{SGX_SDK} /opt/intel/sgxsdk)
  endif()
  if(NOT EXISTS "$ENV{SGX_SDK}/bin/x64/sgx_edger8r")
    message(FATAL_ERROR "Intel SGX SDK 2.26 is required for ${SOCI_SGX_MODE}; refusing fallback to OFF")
  endif()
  include(cmake/IntelSGX.cmake)
endif()

find_path(GMP_INCLUDE_DIR gmpxx.h REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)
find_package(OpenSSL REQUIRED)
if(NOT SOCI_SGX_MODE STREQUAL "OFF")
  target_include_directories(soci_sgx_crypto_benchmark PRIVATE ${GMP_INCLUDE_DIR})
  target_link_libraries(soci_sgx_crypto_benchmark PRIVATE ${GMPXX_LIBRARY} ${GMP_LIBRARY})
  target_compile_definitions(soci_sgx_crypto_benchmark PRIVATE
    SOCI_SGX_BENCHMARK_MODE="${SOCI_SGX_MODE}")
  target_include_directories(soci_sgx_threshold_test PRIVATE ${GMP_INCLUDE_DIR})
  target_link_libraries(soci_sgx_threshold_test PRIVATE ${GMPXX_LIBRARY} ${GMP_LIBRARY})
  target_include_directories(soci_threshold_runtime PRIVATE ${GMP_INCLUDE_DIR})
  target_link_libraries(soci_threshold_runtime PRIVATE ${GMPXX_LIBRARY} ${GMP_LIBRARY})
  target_include_directories(soci_threshold_protocol PRIVATE ${GMP_INCLUDE_DIR})
  target_link_libraries(soci_threshold_protocol PUBLIC ${GMPXX_LIBRARY} ${GMP_LIBRARY})
endif()

add_library(soci_sdk SHARED
  src/crypto.cpp src/serialization.cpp src/runtime.cpp src/c_api.cpp
  src/secure_ops.cpp src/predicate_engine.cpp src/optimization.cpp
  src/encrypted_branch_bound.cpp src/lagrangian_relaxation.cpp)
target_include_directories(soci_sdk PUBLIC include PRIVATE src ${GMP_INCLUDE_DIR})
target_link_libraries(soci_sdk PRIVATE ${GMPXX_LIBRARY} ${GMP_LIBRARY} OpenSSL::Crypto)
target_compile_definitions(soci_sdk PRIVATE SOCI_SGX_MODE="${SOCI_SGX_MODE}"
  SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS=$<BOOL:${SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS}>)
set_target_properties(soci_sdk PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)

add_executable(soci_cp_service services/service_main.cpp)
target_compile_definitions(soci_cp_service PRIVATE SOCI_SERVICE_ROLE="CP")
target_link_libraries(soci_cp_service PRIVATE soci_sdk)
add_executable(soci_csp_service services/service_main.cpp)
target_compile_definitions(soci_csp_service PRIVATE SOCI_SERVICE_ROLE="CSP")
target_link_libraries(soci_csp_service PRIVATE soci_sdk)
add_executable(soci_cpp_example examples/cpp/basic.cpp)
target_link_libraries(soci_cpp_example PRIVATE soci_sdk)
add_executable(soci_benchmark benchmark/performance.cpp)
target_link_libraries(soci_benchmark PRIVATE soci_sdk)

if(SOCI_BUILD_PYTHON)
  find_package(pybind11 CONFIG QUIET)
  if(pybind11_FOUND)
    pybind11_add_module(_soci bindings/python/module.cpp)
    target_link_libraries(_soci PRIVATE soci_sdk)
    install(TARGETS _soci LIBRARY DESTINATION soci)
  else()
    message(STATUS "pybind11 not found; Python extension skipped")
  endif()
endif()
if(SOCI_BUILD_JAVA)
  find_package(JNI QUIET)
  if(NOT JNI_FOUND AND DEFINED ENV{JAVA_HOME})
    find_path(SOCI_JNI_INCLUDE_DIR jni.h
      PATHS "$ENV{JAVA_HOME}/include" NO_DEFAULT_PATH)
    find_path(SOCI_JNI_PLATFORM_INCLUDE_DIR jni_md.h
      PATHS "$ENV{JAVA_HOME}/include/linux" NO_DEFAULT_PATH)
    if(SOCI_JNI_INCLUDE_DIR AND SOCI_JNI_PLATFORM_INCLUDE_DIR)
      set(JNI_FOUND TRUE)
      set(JNI_INCLUDE_DIRS
        "${SOCI_JNI_INCLUDE_DIR}" "${SOCI_JNI_PLATFORM_INCLUDE_DIR}")
    endif()
  endif()
  if(JNI_FOUND)
    add_library(soci_jni SHARED bindings/java/native/soci_jni.cpp)
    target_include_directories(soci_jni PRIVATE ${JNI_INCLUDE_DIRS})
    target_link_libraries(soci_jni PRIVATE soci_sdk)
    add_library(soci_demo_bridge SHARED
      examples/optimization-demo/native/confidential_demo_bridge.cpp)
    target_include_directories(soci_demo_bridge PRIVATE
      ${JNI_INCLUDE_DIRS} include src)
    target_link_libraries(soci_demo_bridge PRIVATE soci_sdk)
    target_compile_definitions(soci_demo_bridge PRIVATE
      SOCI_DEMO_MODE="${SOCI_SGX_MODE}")
    if(NOT SOCI_SGX_MODE STREQUAL "OFF")
      target_link_directories(soci_demo_bridge PRIVATE "${SGX_LIBRARY_DIR}")
      target_link_libraries(soci_demo_bridge PRIVATE soci_threshold_optimizer)
      target_compile_definitions(soci_demo_bridge PRIVATE
        SOCI_DEMO_HAS_THRESHOLD=1)
    endif()
  else()
    message(STATUS "JNI headers not found; JNI library skipped")
  endif()
endif()

enable_testing()
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME soci_plus_protocol_algebra
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/test_soci_plus_protocol.py)
endif()
add_executable(soci_tests tests/test_sdk.cpp)
target_link_libraries(soci_tests PRIVATE soci_sdk)
target_compile_definitions(soci_tests PRIVATE
  SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS=$<BOOL:${SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS}>)
if(SOCI_SGX_MODE STREQUAL "OFF")
  add_test(NAME soci_tests COMMAND soci_tests)
  if(SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS)
    add_executable(soci_scmp_tests tests/test_scmp.cpp)
    target_link_libraries(soci_scmp_tests PRIVATE soci_sdk)
    add_test(NAME soci_scmp_tests COMMAND soci_scmp_tests)
    add_executable(soci_secure_protocol_tests tests/test_secure_protocols.cpp)
    target_link_libraries(soci_secure_protocol_tests PRIVATE soci_sdk)
    add_test(NAME soci_secure_protocol_tests COMMAND soci_secure_protocol_tests)
    add_executable(soci_secure_ops_tests tests/test_secure_ops.cpp)
    target_link_libraries(soci_secure_ops_tests PRIVATE soci_sdk)
    add_test(NAME soci_secure_ops_tests COMMAND soci_secure_ops_tests)
    add_executable(soci_predicate_engine_tests tests/test_predicate_engine.cpp)
    target_link_libraries(soci_predicate_engine_tests PRIVATE soci_sdk)
    add_test(NAME soci_predicate_engine_tests COMMAND soci_predicate_engine_tests)
    add_executable(soci_encrypted_optimizer_tests
      tests/test_encrypted_optimizer.cpp)
    target_link_libraries(soci_encrypted_optimizer_tests PRIVATE soci_sdk)
    add_test(NAME soci_encrypted_optimizer_tests
      COMMAND soci_encrypted_optimizer_tests)
    add_executable(soci_lagrangian_relaxation_tests
      tests/test_lagrangian_relaxation.cpp)
    target_link_libraries(soci_lagrangian_relaxation_tests PRIVATE soci_sdk)
    add_test(NAME soci_lagrangian_relaxation_tests
      COMMAND soci_lagrangian_relaxation_tests)
    add_test(NAME soci_optimizer_source_security
      COMMAND ${CMAKE_COMMAND} -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_SOURCE_DIR}/tests/check_optimizer_security.cmake)
    add_executable(soci_optimizer_benchmark
      benchmark/encrypted_optimizer.cpp)
    target_include_directories(soci_optimizer_benchmark PRIVATE benchmark)
    target_link_libraries(soci_optimizer_benchmark PRIVATE soci_sdk)
    add_test(NAME soci_optimizer_benchmark_smoke
      COMMAND soci_optimizer_benchmark --rows 3 --k 1)
  endif()
else()
  add_test(NAME soci_threshold_wire_transport COMMAND soci_threshold_wire_test)
  add_test(NAME soci_sgx_cp_lifecycle COMMAND soci_sgx_lifecycle_test
    "${CMAKE_BINARY_DIR}/soci_cp_enclave.signed.so" "${SOCI_SGX_MODE}")
  add_test(NAME soci_sgx_csp_lifecycle COMMAND soci_sgx_lifecycle_test
    "${CMAKE_BINARY_DIR}/soci_csp_enclave.signed.so" "${SOCI_SGX_MODE}")
  add_test(NAME soci_sgx_crypto_correctness COMMAND soci_sgx_crypto_benchmark
    "${CMAKE_BINARY_DIR}/soci_provisioning_enclave.signed.so" 3)
  add_test(NAME soci_sgx_threshold_correctness COMMAND soci_sgx_threshold_test
    "${CMAKE_BINARY_DIR}/soci_provisioning_enclave.signed.so"
    "${CMAKE_BINARY_DIR}/soci_cp_enclave.signed.so"
    "${CMAKE_BINARY_DIR}/soci_csp_enclave.signed.so" "${SOCI_SGX_MODE}")
  add_test(NAME soci_threshold_secure_ops_integration
    COMMAND soci_threshold_secure_ops_test
      "${CMAKE_BINARY_DIR}/soci_provisioning_enclave.signed.so"
      "${CMAKE_BINARY_DIR}/soci_cp_enclave.signed.so"
      "${CMAKE_BINARY_DIR}/soci_csp_enclave.signed.so" "${SOCI_SGX_MODE}"
      "$<TARGET_FILE:soci_threshold_runtime>")
  set_tests_properties(soci_sgx_crypto_correctness PROPERTIES TIMEOUT 600)
  set_tests_properties(soci_sgx_threshold_correctness
    soci_threshold_secure_ops_integration PROPERTIES TIMEOUT 600)
  if(SOCI_SGX_MODE STREQUAL "SIM")
    set_tests_properties(
      soci_sgx_cp_lifecycle soci_sgx_csp_lifecycle soci_sgx_crypto_correctness
      soci_sgx_threshold_correctness
      soci_threshold_secure_ops_integration
      PROPERTIES ENVIRONMENT "LD_LIBRARY_PATH=$ENV{SGX_SDK}/lib64")
  endif()
endif()

install(TARGETS soci_sdk soci_cp_service soci_csp_service
  LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
if(NOT SOCI_SGX_MODE STREQUAL "OFF")
  install(TARGETS soci_threshold_optimizer soci_threshold_protocol
    ARCHIVE DESTINATION lib)
endif()
install(DIRECTORY include/ DESTINATION include)

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/build-manifest.json" CONTENT
"{\n  \"project\":\"soci-sgx-sdk\",\n  \"version\":\"${PROJECT_VERSION}\",\n  \"cmake_preset\":\"$ENV{CMAKE_PRESET_NAME}\",\n  \"soci_sgx_mode\":\"${SOCI_SGX_MODE}\",\n  \"compiler\":\"${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}\",\n  \"sgx_sdk\":\"2.26 (required for SIM/HW)\",\n  \"source_revision\":\"$ENV{GIT_COMMIT}\",\n  \"container_image_digest\":\"$ENV{CONTAINER_IMAGE_DIGEST}\"\n}\n")
