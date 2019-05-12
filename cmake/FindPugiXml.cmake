
# PUGIXML_FOUND - system has the pugixml library
# PUGIXML_INCLUDE_DIR - the pugixml include directory
# PUGIXML_LIBRARY - the pugixml library name

if(PUGIXML_INCLUDE_DIR AND PUGIXML_LIBRARY)
    set(PUGIXML_FIND_QUIETLY TRUE)
endif()

find_path(PUGIXML_INCLUDE_DIR pugixml.hpp)

find_library(PUGIXML_LIBRARY NAMES pugixml)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PugiXml DEFAULT_MSG PUGIXML_INCLUDE_DIR PUGIXML_LIBRARY)

mark_as_advanced(PUGIXML_INCLUDE_DIR PUGIXML_LIBRARY)
