INCLUDE(FindZLIB)

IF(NOT ZLIB_FOUND)
	message(FATAL_ERROR "zlib is required for hfs!")
ENDIF(NOT ZLIB_FOUND)

include_directories(${ZLIB_INCLUDE_DIR})

link_directories(${PROJECT_BINARY_DIR}/common)
add_library(hfs btree.c catalog.c extents.c xattr.c fastunicodecompare.c flatfile.c hfslib.c rawfile.c utility.c volume.c hfscompress.c)
target_link_libraries(hfs common ${ZLIB_LIBRARIES})

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED json-c)
find_package(OpenSSL REQUIRED)
find_package(Iconv REQUIRED)
include_directories(${JSONC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${Iconv_INCLUDE_DIRS})
set(LZFSE_DIR ${PROJECT_SOURCE_DIR}/third_party/lzfse)
add_library(hfs_lzfse STATIC ${LZFSE_DIR}/lzfse_decode.c ${LZFSE_DIR}/lzfse_decode_base.c
    ${LZFSE_DIR}/lzfse_fse.c ${LZFSE_DIR}/lzvn_decode_base.c)
include_directories(${LZFSE_DIR})
add_executable(hfsplus hfs.c manifest.c format.c verify.c fit.c)
target_link_libraries(hfsplus hfs hfs_lzfse ${JSONC_LDFLAGS} ${OPENSSL_CRYPTO_LIBRARY} ${Iconv_LIBRARIES})
set_property(TARGET hfsplus APPEND PROPERTY COMPILE_OPTIONS ${JSONC_CFLAGS_OTHER})

install(TARGETS hfsplus DESTINATION bin)

