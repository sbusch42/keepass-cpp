
# ZSTR_FOUND - system has the zstr library
# ZSTR_INCLUDE_DIR - the zstr include directory

if(ZSTR_INCLUDE_DIR)
    set(ZSTR_FIND_QUIETLY TRUE)
endif()

find_path(ZSTR_INCLUDE_DIR zstr.hpp
    PATHS
    "${CMAKE_SOURCE_DIR}/3rdparty/zstr"
     NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZStr DEFAULT_MSG ZSTR_INCLUDE_DIR)

mark_as_advanced(ZSTR_INCLUDE_DIR)
