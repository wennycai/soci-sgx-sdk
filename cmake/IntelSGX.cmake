set(SGX_SDK "$ENV{SGX_SDK}")
set(SGX_ARCH x64)
set(SGX_INCLUDE_DIR "${SGX_SDK}/include")
set(SGX_LIBRARY_DIR "${SGX_SDK}/lib64")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(SGX_SIGN "${SGX_SDK}/bin/x64/sgx_sign")
set(GMP_SGX_ROOT "${SGX_SDK}/gmp-sgx" CACHE PATH "SGX trusted GMP prefix")
set(GMP_SGX_LIBRARY "${GMP_SGX_ROOT}/lib/libgmp_sgx.a")
if(NOT EXISTS "${GMP_SGX_LIBRARY}" OR NOT EXISTS "${GMP_SGX_ROOT}/include/gmp.h")
  message(FATAL_ERROR
    "Trusted assembly GMP is missing. Run scripts/build_gmp_sgx.sh ${GMP_SGX_ROOT}")
endif()
if(SOCI_SGX_MODE STREQUAL "SIM")
  set(SGX_TRTS sgx_trts_sim)
  set(SGX_TSERVICE sgx_tservice_sim)
  set(SGX_URTS sgx_urts_sim)
else()
  set(SGX_TRTS sgx_trts)
  set(SGX_TSERVICE sgx_tservice)
  set(SGX_URTS sgx_urts)
endif()
message(STATUS "Intel SGX SDK: ${SGX_SDK}; strict mode: ${SOCI_SGX_MODE}")

set(SOCI_TEST_SIGNING_KEY "${CMAKE_BINARY_DIR}/sgx/test_signing_key.pem")
add_custom_command(OUTPUT "${SOCI_TEST_SIGNING_KEY}"
  COMMAND openssl genrsa -3 -out "${SOCI_TEST_SIGNING_KEY}.tmp" 3072
  COMMAND "${CMAKE_COMMAND}" -E rename
          "${SOCI_TEST_SIGNING_KEY}.tmp" "${SOCI_TEST_SIGNING_KEY}"
  COMMENT "Generating shared TEST-ONLY enclave signing key" VERBATIM)
add_custom_target(soci_test_signing_key DEPENDS "${SOCI_TEST_SIGNING_KEY}")

function(add_soci_enclave ROLE CONFIG)
  string(TOLOWER "${ROLE}" role_lower)
  set(gen "${CMAKE_BINARY_DIR}/sgx/${role_lower}")
  file(MAKE_DIRECTORY "${gen}")
  set(edl "${PROJECT_SOURCE_DIR}/trusted/common/soci.edl")
  add_custom_command(
    OUTPUT "${gen}/soci_t.c" "${gen}/soci_t.h"
    COMMAND "${SGX_EDGER8R}" --trusted "${edl}"
            --search-path "${SGX_INCLUDE_DIR}" --trusted-dir "${gen}"
    DEPENDS "${edl}" VERBATIM)
  add_library(soci_${role_lower}_enclave_unsigned SHARED
    "${gen}/soci_t.c" trusted/common/enclave_core.c)
  target_include_directories(soci_${role_lower}_enclave_unsigned PRIVATE
    "${gen}" "${SGX_INCLUDE_DIR}" "${SGX_INCLUDE_DIR}/tlibc"
    "${GMP_SGX_ROOT}/include")
  target_compile_options(soci_${role_lower}_enclave_unsigned PRIVATE
    -m64 -nostdinc -fvisibility=hidden -fpie -fstack-protector)
  target_compile_definitions(soci_${role_lower}_enclave_unsigned PRIVATE SOCI_SGX_TRUSTED=1)
  if(role_lower STREQUAL "cp")
    target_compile_definitions(soci_${role_lower}_enclave_unsigned PRIVATE SOCI_ENCLAVE_ROLE=1)
  elseif(role_lower STREQUAL "csp")
    target_compile_definitions(soci_${role_lower}_enclave_unsigned PRIVATE SOCI_ENCLAVE_ROLE=2)
  else()
    target_compile_definitions(soci_${role_lower}_enclave_unsigned PRIVATE SOCI_ENCLAVE_ROLE=0)
  endif()
  target_link_directories(soci_${role_lower}_enclave_unsigned PRIVATE "${SGX_LIBRARY_DIR}")
  target_link_options(soci_${role_lower}_enclave_unsigned PRIVATE
    -m64 -nostdlib -nodefaultlibs -nostartfiles
    "LINKER:--no-undefined"
    "LINKER:-Bstatic" "LINKER:-Bsymbolic" "LINKER:-pie"
    "LINKER:-eenclave_entry" "LINKER:--export-dynamic"
    "LINKER:--defsym,__ImageBase=0"
    "LINKER:--version-script=${PROJECT_SOURCE_DIR}/trusted/common/enclave.lds")
  target_link_libraries(soci_${role_lower}_enclave_unsigned PRIVATE
    "-Wl,--whole-archive" ${SGX_TRTS} "-Wl,--no-whole-archive"
    "-Wl,--start-group" "${GMP_SGX_LIBRARY}" sgx_tstdc sgx_tcxx
    sgx_tcrypto ${SGX_TSERVICE} "-Wl,--end-group")
  set_target_properties(soci_${role_lower}_enclave_unsigned PROPERTIES
    PREFIX "" OUTPUT_NAME "soci_${role_lower}_enclave" SUFFIX ".so")

  set(signed "${CMAKE_BINARY_DIR}/soci_${role_lower}_enclave.signed.so")
  add_custom_command(OUTPUT "${signed}"
    COMMAND "${SGX_SIGN}" sign -key "${SOCI_TEST_SIGNING_KEY}"
      -enclave "$<TARGET_FILE:soci_${role_lower}_enclave_unsigned>"
      -out "${signed}" -config "${CONFIG}"
    DEPENDS soci_${role_lower}_enclave_unsigned soci_test_signing_key
            "${SOCI_TEST_SIGNING_KEY}" "${CONFIG}" VERBATIM)
  add_custom_target(soci_${role_lower}_enclave ALL DEPENDS "${signed}")
endfunction()

add_soci_enclave(cp "${PROJECT_SOURCE_DIR}/trusted/cp_enclave/Enclave.config.xml")
add_soci_enclave(csp "${PROJECT_SOURCE_DIR}/trusted/csp_enclave/Enclave.config.xml")
add_soci_enclave(provisioning "${PROJECT_SOURCE_DIR}/trusted/provisioning_enclave/Enclave.config.xml")

set(SGX_U_GEN "${CMAKE_BINARY_DIR}/sgx/untrusted")
file(MAKE_DIRECTORY "${SGX_U_GEN}")
add_custom_command(
  OUTPUT "${SGX_U_GEN}/soci_u.c" "${SGX_U_GEN}/soci_u.h"
  COMMAND "${SGX_EDGER8R}" --untrusted "${PROJECT_SOURCE_DIR}/trusted/common/soci.edl"
          --search-path "${SGX_INCLUDE_DIR}" --untrusted-dir "${SGX_U_GEN}"
  DEPENDS "${PROJECT_SOURCE_DIR}/trusted/common/soci.edl" VERBATIM)
add_executable(soci_sgx_lifecycle_test tests/test_sgx_lifecycle.cpp "${SGX_U_GEN}/soci_u.c")
target_include_directories(soci_sgx_lifecycle_test PRIVATE "${SGX_INCLUDE_DIR}" "${SGX_U_GEN}")
target_link_directories(soci_sgx_lifecycle_test PRIVATE "${SGX_LIBRARY_DIR}")
target_link_libraries(soci_sgx_lifecycle_test PRIVATE ${SGX_URTS} pthread)
if(SOCI_SGX_MODE STREQUAL "HW")
  # Link against the SDK ABI, but at runtime load uRTS from the host PSW
  # package. The SDK copy deliberately refuses hardware enclave creation.
  set_target_properties(soci_sgx_lifecycle_test PROPERTIES SKIP_BUILD_RPATH TRUE)
endif()
add_dependencies(soci_sgx_lifecycle_test soci_cp_enclave soci_csp_enclave)
add_executable(soci_sgx_crypto_benchmark benchmark/sgx_sim_performance.cpp "${SGX_U_GEN}/soci_u.c")
target_include_directories(soci_sgx_crypto_benchmark PRIVATE "${SGX_INCLUDE_DIR}" "${SGX_U_GEN}")
target_link_directories(soci_sgx_crypto_benchmark PRIVATE "${SGX_LIBRARY_DIR}")
target_link_libraries(soci_sgx_crypto_benchmark PRIVATE ${SGX_URTS} pthread)
if(SOCI_SGX_MODE STREQUAL "HW")
  set_target_properties(soci_sgx_crypto_benchmark PROPERTIES SKIP_BUILD_RPATH TRUE)
endif()
add_dependencies(soci_sgx_crypto_benchmark soci_provisioning_enclave)
add_executable(soci_sgx_threshold_test tests/test_sgx_threshold.cpp "${SGX_U_GEN}/soci_u.c")
target_include_directories(soci_sgx_threshold_test PRIVATE "${SGX_INCLUDE_DIR}" "${SGX_U_GEN}")
target_link_directories(soci_sgx_threshold_test PRIVATE "${SGX_LIBRARY_DIR}")
target_link_libraries(soci_sgx_threshold_test PRIVATE ${SGX_URTS} pthread)
if(SOCI_SGX_MODE STREQUAL "HW")
  set_target_properties(soci_sgx_threshold_test PROPERTIES SKIP_BUILD_RPATH TRUE)
endif()
add_dependencies(soci_sgx_threshold_test soci_provisioning_enclave soci_cp_enclave soci_csp_enclave)
add_executable(soci_threshold_runtime services/threshold_runtime.cpp "${SGX_U_GEN}/soci_u.c")
target_include_directories(soci_threshold_runtime PRIVATE "${SGX_INCLUDE_DIR}" "${SGX_U_GEN}")
target_link_directories(soci_threshold_runtime PRIVATE "${SGX_LIBRARY_DIR}")
target_link_libraries(soci_threshold_runtime PRIVATE ${SGX_URTS} pthread)
if(SOCI_SGX_MODE STREQUAL "HW")
  set_target_properties(soci_threshold_runtime PROPERTIES SKIP_BUILD_RPATH TRUE)
endif()
add_dependencies(soci_threshold_runtime soci_provisioning_enclave soci_cp_enclave soci_csp_enclave)
