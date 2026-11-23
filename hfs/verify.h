#ifndef HFS_NATIVE_VERIFY_H
#define HFS_NATIVE_VERIFY_H
#include <stdint.h>
int hfs_verify_image(const char* path);
int hfs_verify_memory(const void *memory, uint64_t size);
#endif
