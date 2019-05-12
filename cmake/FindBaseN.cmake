
# BASEN_FOUND - system has the base-n library
# BASEN_INCLUDE_DIR - the base-n include directory

if(BASEN_INCLUDE_DIR)
    set(BASEN_FIND_QUIETLY TRUE)
endif()

find_path(BASEN_INCLUDE_DIR basen.hpp
    PATHS
    "${CMAKE_SOURCE_DIR}/3rdparty/basen"
     NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BaseN DEFAULT_MSG BASEN_INCLUDE_DIR)

mark_as_advanced(BASEN_INCLUDE_DIR)
