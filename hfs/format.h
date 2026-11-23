#ifndef HFS_FORMAT_COMMAND_H
#define HFS_FORMAT_COMMAND_H
#include "common.h"
int hfs_format_command(int argc, const char* argv[]);
int hfs_format_memory(io_func *io, uint64_t size, uint32_t bs, const char *name, int sensitive);
#endif
