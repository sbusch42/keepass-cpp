
find_path(GCRYPT_INCLUDE_DIR gcrypt.h)
find_library(GCRYPT_LIBRARY NAMES gcrypt)
find_library(GPGERROR_LIBRARY NAMES gpg-error)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(GCrypt
	FOUND_VAR
		GCRYPT_FOUND
	REQUIRED_VARS
		GCRYPT_LIBRARY
		GCRYPT_INCLUDE_DIR
		GPGERROR_LIBRARY
)

mark_as_advanced(GCRYPT_INCLUDE_DIR GCRYPT_LIBRARY GPGERROR_LIBRARY)
