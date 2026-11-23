#ifndef HFS_MANIFEST_H
#define HFS_MANIFEST_H
#include "common.h"
/* These checked commands open the image themselves, after input validation. */
int hfs_manifest_command(int argc, const char** argv);
int hfs_manifest_import_memory(io_func *io, const char *tree, const char *manifest);
int hfs_manifest_export_memory(io_func *io, const char *tree, const char *manifest);
#endif
