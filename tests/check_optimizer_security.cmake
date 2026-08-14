if(NOT DEFINED SOURCE_DIR)
  message(FATAL_ERROR "SOURCE_DIR is required")
endif()

set(PRODUCTION_SOLVER_FILES
  "${SOURCE_DIR}/src/encrypted_branch_bound.cpp"
  "${SOURCE_DIR}/src/lagrangian_relaxation.cpp")

foreach(FILE_PATH IN LISTS PRODUCTION_SOLVER_FILES)
  file(READ "${FILE_PATH}" CONTENTS)
  foreach(FORBIDDEN IN ITEMS decrypt decryptForTesting revealFinalBit
                             ThresholdProtocolClient)
    string(FIND "${CONTENTS}" "${FORBIDDEN}" POSITION)
    if(NOT POSITION EQUAL -1)
      message(FATAL_ERROR
        "Production optimizer source ${FILE_PATH} contains ${FORBIDDEN}")
    endif()
  endforeach()
endforeach()
