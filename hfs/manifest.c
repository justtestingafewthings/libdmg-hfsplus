/* Driverless, checked HFS+ tree interchange. Catalog bytes use disk byte order.
 * Allocation records are rebuilt; CNIDs and native hardlink records are retained.
 * The JSON and storage files must stay beside each other when moved. */
#define _GNU_SOURCE
#include <hfs/hfsplus.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <zlib.h>
#include "lzfse.h"
#define insert lzfse_insert_bits
#include "lzvn_decode_base.h"
#undef insert
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <iconv.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include "manifest.h"

static void fail(const char* message);

#ifdef __APPLE__
/* openat, mkdirat and symlinkat were added after OS X 10.8. This tool is
 * single-threaded, so a directory fd can safely serve as the temporary cwd. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0x1000000
#endif
static int enter_dir(int dir) {
    int previous = open(".", O_RDONLY | O_DIRECTORY);
    if(previous < 0 || fchdir(dir)) fail("cannot enter host directory");
    return previous;
}
static void leave_dir(int previous) {
    if(fchdir(previous)) fail("cannot restore host directory");
    close(previous);
}
static int legacy_openat(int dir, const char* name, int flags, ...) {
    mode_t mode = 0;
    if(flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    int previous = enter_dir(dir);
    int result = open(name, flags & ~O_CLOEXEC, mode);
    if(result >= 0 && (flags & O_CLOEXEC) && fcntl(result, F_SETFD, FD_CLOEXEC) < 0) {
        close(result);
        result = -1;
    }
    leave_dir(previous);
    return result;
}
static int legacy_mkdirat(int dir, const char* name, mode_t mode) {
    int previous = enter_dir(dir);
    int result = mkdir(name, mode);
    leave_dir(previous);
    return result;
}
static int legacy_symlinkat(const char* target, int dir, const char* name) {
    int previous = enter_dir(dir);
    int result = symlink(target, name);
    leave_dir(previous);
    return result;
}
static ssize_t legacy_readlinkat(int dir, const char* name, char* target, size_t size) {
    int previous = enter_dir(dir);
    ssize_t result = readlink(name, target, size);
    leave_dir(previous);
    return result;
}
static int legacy_linkat(int source_dir, const char* source, int target_dir,
                         const char* target, int flags) {
    char directory[PATH_MAX], path[PATH_MAX];
    if(flags || fcntl(source_dir, F_GETPATH, directory) < 0 ||
       snprintf(path, sizeof(path), "%s/%s", directory, source) >= sizeof(path)) {
        errno = EINVAL;
        return -1;
    }
    int previous = enter_dir(target_dir);
    int result = link(path, target);
    leave_dir(previous);
    return result;
}
#define openat legacy_openat
#define mkdirat legacy_mkdirat
#define symlinkat legacy_symlinkat
#define readlinkat legacy_readlinkat
#define linkat legacy_linkat
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1070
static ssize_t legacy_getline(char** line, size_t* capacity, FILE* input) {
    if(!line || !capacity || !input) { errno = EINVAL; return -1; }
    size_t length = 0;
    int ch;
    while((ch = fgetc(input)) != EOF) {
        if(length + 1 >= *capacity) {
            size_t size = *capacity ? *capacity * 2 : 128;
            if(size <= length + 1) size = length + 2;
            char* next = realloc(*line, size);
            if(!next) return -1;
            *line = next;
            *capacity = size;
        }
        (*line)[length++] = (char)ch;
        if(ch == '\n') break;
    }
    if(!length) return -1;
    (*line)[length] = 0;
    return (ssize_t)length;
}
#define getline legacy_getline
#endif
#endif

#define SCHEMA "apple-firmware.hfs-native/1"
#define CHUNK (1024 * 1024)
typedef json_object J;
typedef union { HFSPlusCatalogFile file; HFSPlusCatalogFolder folder; } Record;
typedef struct {
    Volume* volume;
    J *document, *nodes, *index;
    int tree, storage, inventory, metadata_only;
} Context;

static void fail(const char* message) {
    fprintf(stderr, "hfs manifest: %s\n", message);
    exit(!strcmp(message, "no space left in volume") ? 2 : 1);
}
static J* field(J* j, const char* name) {
    J* result;
    if(!j || !json_object_object_get_ex(j, name, &result)) fail(name);
    return result;
}
static const char* string(J* j, const char* name) {
    J* result = field(j, name);
    if(!json_object_is_type(result, json_type_string)) fail(name);
    const char* text = json_object_get_string(result);
    if(strlen(text) != (size_t)json_object_get_string_len(result)) fail("embedded NUL in string");
    return text;
}
static uint32_t number(J* j, const char* name) {
    J* result = field(j, name);
    int64_t n = json_object_get_int64(result);
    if(!json_object_is_type(result, json_type_int) || n < 0 || n > UINT32_MAX) fail(name);
    return (uint32_t)n;
}
static void putstr(J* j, const char* name, const char* value) {
    json_object_object_add(j, name, json_object_new_string(value));
}
static void putnum(J* j, const char* name, uint32_t value) {
    json_object_object_add(j, name, json_object_new_int64(value));
}
static char* hex(const void* data, size_t n) {
    const unsigned char* bytes = data;
    char* result = malloc(n * 2 + 1);
    if(!result) fail("allocation failed");
    for(size_t i = 0; i < n; i++) sprintf(result + i * 2, "%02x", bytes[i]);
    result[n * 2] = 0;
    return result;
}
static unsigned char* unhex(const char* input, size_t* size) {
    size_t n = strlen(input);
    if(n % 2 || n > 32 * 1024 * 1024) fail("invalid hexadecimal data");
    unsigned char* result = malloc(n / 2 + 1);
    if(!result) fail("allocation failed");
    for(size_t i = 0; i < n; i += 2) {
        unsigned int value;
        if(!strchr("0123456789abcdef", input[i]) || !strchr("0123456789abcdef", input[i+1]) ||
           sscanf(input+i, "%2x", &value) != 1) fail("invalid hexadecimal digit");
        result[i/2] = value;
    }
    *size = n / 2;
    return result;
}
static void puthex(J* j, const char* name, const void* data, size_t n) {
    char* encoded = hex(data, n);
    putstr(j, name, encoded);
    free(encoded);
}
static uint32_t cnid(HFSPlusCatalogRecord* record) {
    return ((HFSPlusCatalogFile*)record)->fileID;
}
static int isfolder(HFSPlusCatalogRecord* record) { return record->recordType == kHFSPlusFolderRecord; }
static void diskrecord(Record* r) {
    if(isfolder((HFSPlusCatalogRecord*)r)) flipCatalogFolder(&r->folder);
    else flipCatalogFile(&r->file);
}
static Record decode_record(J* node) {
    Record result = {0};
    size_t n;
    unsigned char* bytes = unhex(string(node, "catalog"), &n);
    if(n != sizeof(HFSPlusCatalogFolder) && n != sizeof(HFSPlusCatalogFile)) fail("catalog size");
    memcpy(&result, bytes, n);
    free(bytes);
    /* Both disk record types have a zero high byte. */
    if(((unsigned char*)&result)[0] != 0 || (((unsigned char*)&result)[1] != 1 &&
       ((unsigned char*)&result)[1] != 2)) fail("catalog type");
    if(((unsigned char*)&result)[1] == 1) flipCatalogFolder(&result.folder);
    else flipCatalogFile(&result.file);
    if(n != (isfolder((HFSPlusCatalogRecord*)&result) ? sizeof(HFSPlusCatalogFolder) : sizeof(HFSPlusCatalogFile)))
        fail("catalog type/size mismatch");
    HFSPlusForkData empty_fork = {0};
    if(!isfolder((HFSPlusCatalogRecord*)&result) &&
       (memcmp(&result.file.dataFork, &empty_fork, sizeof(empty_fork)) ||
        memcmp(&result.file.resourceFork, &empty_fork, sizeof(empty_fork)))) fail("catalog contains allocation records");
    if(cnid((HFSPlusCatalogRecord*)&result) != number(node, "id")) fail("catalog CNID mismatch");
    return result;
}
static J* byid(Context* c, uint32_t id) {
    char key[16]; J* node;
    snprintf(key, sizeof(key), "%u", id);
    if(!json_object_object_get_ex(c->index, key, &node)) fail("missing native hardlink/parent CNID");
    return node;
}
static void indexnode(Context* c, J* node) {
    char key[16]; J* old;
    snprintf(key, sizeof(key), "%u", number(node, "id"));
    if(json_object_object_get_ex(c->index, key, &old)) fail("duplicate CNID");
    json_object_object_add(c->index, key, json_object_get(node));
}
/* Open each component relative to a trusted directory. Never follow host links. */
static int relative(int base, const char* path, int flags, int parent, char** leaf) {
    if(!*path || *path == '/' || strlen(path) > 4095) fail("unsafe host path");
    char* copy = strdup(path), *save = NULL, *part = strtok_r(copy, "/", &save);
    int dir = dup(base), result = -1;
    while(part) {
        if(!strcmp(part, ".") || !strcmp(part, "..")) fail("unsafe path component");
        char* next = strtok_r(NULL, "/", &save);
        if(!next) {
            if(parent) { *leaf = strdup(part); result = dir; }
            else { result = openat(dir, part, flags | O_NOFOLLOW | O_CLOEXEC, 0600); close(dir); }
            break;
        }
        int nextdir = openat(dir, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dir);
        if(nextdir < 0) fail("host parent is missing or a symlink");
        dir = nextdir; part = next;
    }
    free(copy);
    if(result < 0) fail("cannot open host path");
    return result;
}
static void hashfd(int fd, char output[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE], buffer[CHUNK]; unsigned int length;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) fail("SHA256 initialization");
    if(lseek(fd, 0, SEEK_SET) < 0) fail("seek");
    ssize_t n;
    while((n = read(fd, buffer, sizeof(buffer))) > 0)
        if(EVP_DigestUpdate(ctx, buffer, n) != 1) fail("SHA256 update");
    if(n < 0 || EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != 32) fail("SHA256 read/final");
    EVP_MD_CTX_free(ctx);
    char* encoded = hex(digest, 32); strcpy(output, encoded); free(encoded);
    if(lseek(fd, 0, SEEK_SET) < 0) fail("seek");
}
static J* descriptor(Context* c, const char* location, const char* path) {
    int fd = relative(!strcmp(location, "tree") ? c->tree : c->storage, path, O_RDONLY, 0, NULL);
    struct stat st; char digest[65];
    if(fstat(fd, &st) || !S_ISREG(st.st_mode)) fail("content is not a regular file");
    hashfd(fd, digest); close(fd);
    J* value = json_object_new_object();
    putstr(value, "location", location); putstr(value, "path", path); putstr(value, "sha256", digest);
    json_object_object_add(value, "size", json_object_new_int64(st.st_size));
    return value;
}
static int contentfd(Context* c, J* value) {
    const char* location = string(value, "location");
    if(strcmp(location, "tree") && strcmp(location, "storage")) fail("content location");
    int fd = relative(!strcmp(location, "tree") ? c->tree : c->storage,
                      string(value, "path"), O_RDONLY, 0, NULL);
    struct stat st; char digest[65];
    J* size = field(value, "size");
    if(!json_object_is_type(size, json_type_int) || json_object_get_int64(size) < 0 ||
       fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != json_object_get_int64(size))
        fail("content size or type changed");
    hashfd(fd, digest);
    if(strcmp(digest, string(value, "sha256"))) fail("content hash changed; regenerate the manifest before importing edited files");
    return fd;
}
static void writefd(int fd, const void* bytes, size_t n) {
    const unsigned char* p = bytes;
    while(n) { ssize_t done = write(fd, p, n); if(done <= 0) fail("host file write"); p += done; n -= done; }
}
static void forkhashout(Context* c, HFSPlusCatalogFile* file, HFSPlusForkData* fork, int fd, EVP_MD_CTX* hash) {
    io_func* io = openRawFile(file->fileID, fork, (HFSPlusCatalogRecord*)file, c->volume);
    unsigned char* buffer = malloc(CHUNK);
    if(!io || !buffer) fail("open native fork");
    for(uint64_t pos = 0; pos < fork->logicalSize;) {
        size_t n = fork->logicalSize - pos > CHUNK ? CHUNK : fork->logicalSize - pos;
        if(!READ(io, pos, n, buffer)) fail("read native fork");
        if(hash) { if(EVP_DigestUpdate(hash, buffer, n) != 1) fail("fork digest"); }
        if(fd >= 0) writefd(fd, buffer, n);
        pos += n;
    }
    free(buffer); CLOSE(io);
}
static void forkout(Context* c, HFSPlusCatalogFile* file, HFSPlusForkData* fork, int fd) {
    forkhashout(c,file,fork,fd,NULL);
}
static uint32_t le32(const unsigned char* p) { return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint32_t be32(const unsigned char* p) { return (uint32_t)p[3] | (uint32_t)p[2]<<8 | (uint32_t)p[1]<<16 | (uint32_t)p[0]<<24; }
static uint64_t be64(const unsigned char* p) { return (uint64_t)be32(p)<<32 | be32(p+4); }
static uint64_t le64(const unsigned char* p) { return le32(p) | (uint64_t)le32(p+4)<<32; }
static char* journal_digest(Context* c, J* content) {
    int fd = contentfd(c, content); struct stat st;
    if(fstat(fd, &st) || st.st_size < 52 || st.st_size > 1048576) fail("journal info size");
    unsigned char* bytes = malloc(st.st_size); unsigned char digest[32]; unsigned int length;
    if(!bytes || read(fd, bytes, st.st_size) != st.st_size) fail("read journal info");
    close(fd);
    /* This field is an allocation address, not logical filesystem content. */
    memset(bytes+36, 0, 8);
    if(EVP_Digest(bytes, st.st_size, digest, &length, EVP_sha256(), NULL) != 1 || length != 32) fail("journal info digest");
    free(bytes); return hex(digest, 32);
}
static void decodedwrite(int fd, EVP_MD_CTX* hash, const void* p, size_t n) {
    if(hash) { if(EVP_DigestUpdate(hash, p, n) != 1) fail("decoded SHA256 update"); }
    if(fd >= 0) writefd(fd, p, n);
}
static void inflateblock(int fd, EVP_MD_CTX* hash, unsigned char* p, size_t size, size_t expected, uint32_t type) {
    unsigned char buffer[65537]; uLongf n = expected;
    if(expected > 65536 || !size) fail("compression block size");
    if(type == 1) {
        if(size != expected) fail("inline uncompressed decmpfs size");
        decodedwrite(fd, hash, p, expected);
    } else if(type == 9 || type == 10 ||
              ((type == 3 || type == 4 || type == 11 || type == 12) && p[0] == 0xff) ||
              ((type == 7 || type == 8) && p[0] == 0x06)) {
        if(size - 1 != expected) fail("uncompressed decmpfs block size");
        decodedwrite(fd, hash, p+1, expected);
    } else if(type == 3 || type == 4) {
        if(uncompress(buffer, &n, p, size) != Z_OK || n != expected) fail("invalid decmpfs zlib stream");
        decodedwrite(fd, hash, buffer, n);
    } else if(type == 7 || type == 8) {
        lzvn_decoder_state state = {0};
        state.src = p; state.src_end = p + size;
        state.dst = state.dst_begin = state.dst_current = buffer;
        state.dst_end = buffer + expected + 1;
        lzvn_decode(&state);
        if((size_t)(state.dst - buffer) != expected || !state.end_of_stream)
            fail("invalid decmpfs LZVN stream");
        decodedwrite(fd, hash, buffer, expected);
    } else if(type == 11 || type == 12) {
        if(lzfse_decode_buffer(buffer, expected + 1, p, size, NULL) != expected)
            fail("invalid decmpfs LZFSE stream");
        decodedwrite(fd, hash, buffer, expected);
    } else fail("unsupported decmpfs compression type");
}
static void compressedout(unsigned char* attr, size_t size, io_func* io, uint64_t resource_size, int fd, EVP_MD_CTX* hash) {
    if(size < 16 || le32(attr) != 0x636d7066) fail("invalid decmpfs header");
    uint32_t type = le32(attr+4);
    uint64_t remaining = le32(attr+8) | (uint64_t)le32(attr+12)<<32;
    if(type == 1 || type == 3 || type == 7 || type == 9 || type == 11) {
        inflateblock(fd, hash, attr+16, size-16, remaining, type);
    }
    else if(type == 4) {
        unsigned char header[16], count[8];
        if(!io || !READ(io, 0, 16, header)) fail("compressed resource header");
        uint32_t start = be32(header);
        if((uint64_t)start + 8 > resource_size || !READ(io, start, 8, count)) fail("resource block table");
        uint32_t blocks = le32(count+4);
        if(blocks != (remaining + 65535)/65536 || (uint64_t)start + 8 + (uint64_t)blocks*8 > resource_size)
            fail("compressed resource block count");
        for(uint32_t i = 0; i < blocks; i++) {
            unsigned char pair[8];
            if(!READ(io, (uint64_t)start+8+(uint64_t)i*8, 8, pair)) fail("resource block descriptor");
            uint64_t offset = (uint64_t)start+4+le32(pair); uint32_t n = le32(pair+4);
            if(n > 131072 || offset + n > resource_size) fail("resource block bounds");
            unsigned char* buffer = malloc(n);
            if(!buffer || !READ(io, offset, n, buffer)) fail("compressed resource data");
            size_t expected = remaining > 65536 ? 65536 : remaining;
            inflateblock(fd, hash, buffer, n, expected, type); remaining -= expected; free(buffer);
        }
    } else if(type == 8 || type == 10 || type == 12) {
        uint64_t blocks = (remaining + 65535) / 65536;
        if(!io || blocks > (UINT32_MAX / 4) - 1 || (blocks + 1) * 4 > resource_size)
            fail("compressed resource offset table");
        for(uint64_t i = 0; i < blocks; i++) {
            unsigned char offsets[8];
            if(!READ(io, i * 4, 8, offsets)) fail("compressed resource offsets");
            uint32_t start = le32(offsets), end = le32(offsets+4);
            if(start < (blocks + 1) * 4 || end < start || end > resource_size || end - start > 131072)
                fail("compressed resource block bounds");
            size_t length = end - start, expected = remaining > 65536 ? 65536 : remaining;
            unsigned char* buffer = malloc(length ? length : 1);
            if(!buffer || !READ(io, start, length, buffer)) fail("compressed resource data");
            inflateblock(fd, hash, buffer, length, expected, type);
            remaining -= expected; free(buffer);
        }
    } else fail("unsupported decmpfs compression type; no incomplete export was accepted");
}
static void logicalhashout(Context* c, HFSPlusCatalogFile* file, int fd, EVP_MD_CTX* hash) {
    if(!(file->permissions.ownerFlags & UF_COMPRESSED)) { forkhashout(c, file, &file->dataFork, fd, hash); return; }
    unsigned char* attr = NULL;
    size_t size = getAttribute(c->volume, file->fileID, "com.apple.decmpfs", &attr);
    io_func* io = NULL;
    if(size >= 16 && (le32(attr+4) == 4 || le32(attr+4) == 8 || le32(attr+4) == 10 || le32(attr+4) == 12))
        io = openRawFile(file->fileID, &file->resourceFork, (HFSPlusCatalogRecord*)file, c->volume);
    compressedout(attr, size, io, file->resourceFork.logicalSize, fd, hash);
    if(io) CLOSE(io);
    free(attr);
}
static void logicalout(Context* c, HFSPlusCatalogFile* file, int fd) {
    logicalhashout(c,file,fd,NULL);
}
static uint64_t logicalsize(Context* c, HFSPlusCatalogFile* file) {
    uint64_t size=file->dataFork.logicalSize;
    if(file->permissions.ownerFlags & UF_COMPRESSED) {
        unsigned char* attr=NULL; size_t n=getAttribute(c->volume,file->fileID,"com.apple.decmpfs",&attr);
        if(n<16) fail("compression header size"); size=le64(attr+8); free(attr);
    }
    return size;
}
static J* inventorycontent(Context* c, HFSPlusCatalogFile* file, HFSPlusForkData* fork, int inline_bytes) {
    uint64_t size=fork ? fork->logicalSize : logicalsize(c,file);
    J* desc=json_object_new_object(); putstr(desc,"location","image");
    json_object_object_add(desc,"size",json_object_new_uint64(size));
    if(!c->metadata_only || inline_bytes) {
        EVP_MD_CTX* hash=EVP_MD_CTX_new(); unsigned char digest[32]; unsigned int length;
        if(!hash || EVP_DigestInit_ex(hash,EVP_sha256(),NULL)!=1) fail("inventory digest initialization");
        if(fork) forkhashout(c,file,fork,-1,hash); else logicalhashout(c,file,-1,hash);
        if(EVP_DigestFinal_ex(hash,digest,&length)!=1 || length!=32) fail("inventory digest final");
        EVP_MD_CTX_free(hash); puthex(desc,"sha256",digest,32);
    }
    if(inline_bytes) {
        if(!fork || size>64*1024*1024) fail("inventory inline fork size");
        unsigned char* data=malloc((size_t)size+1);
        io_func* io=openRawFile(file->fileID,fork,(HFSPlusCatalogRecord*)file,c->volume);
        if(!data || !io || (size && !READ(io,0,(size_t)size,data))) fail("read inline fork");
        puthex(desc,"inline_hex",data,(size_t)size); free(data); CLOSE(io);
    }
    return desc;
}
typedef struct { int fd; uint64_t size; } ContentReader;
static int contentread(io_func* io, off_t offset, size_t size, void* buffer) {
    ContentReader* reader = io->data;
    if(offset < 0 || (uint64_t)offset + size > reader->size) return FALSE;
    return pread(reader->fd, buffer, size, offset) == (ssize_t)size;
}
static void verifycompression(Context* c, J* node, Record* record) {
    if(isfolder((HFSPlusCatalogRecord*)record) || !(record->file.permissions.ownerFlags & UF_COMPRESSED)) return;
    J* content = field(node, "content");
    size_t size; unsigned char* attr = unhex(string(field(node, "xattrs"), "com.apple.decmpfs"), &size);
    if(size < 16 || (le32(attr+8) | (uint64_t)le32(attr+12)<<32) != (uint64_t)json_object_get_int64(field(content, "size")))
        fail("compression logical size disagrees with expanded file");
    ContentReader reader = {-1, 0}; io_func io = {0}; io.data = &reader; io.read = contentread;
    if(le32(attr+4) == 4 || le32(attr+4) == 8 || le32(attr+4) == 10 || le32(attr+4) == 12) {
        J* resource = field(node, "resource_fork"); reader.fd = contentfd(c, resource);
        reader.size = json_object_get_int64(field(resource, "size"));
    }
    EVP_MD_CTX* hash = EVP_MD_CTX_new(); unsigned char digest[32]; unsigned int length;
    if(!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) fail("decoded SHA256 init");
    compressedout(attr, size, &io, reader.size, -1, hash);
    if(EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) fail("decoded SHA256 final");
    char* encoded = hex(digest, 32);
    if(strcmp(encoded, string(content, "sha256"))) fail("compressed storage does not match expanded content");
    EVP_MD_CTX_free(hash); free(encoded); free(attr); if(reader.fd >= 0) close(reader.fd);
}
static char* hostcomponent(HFSUniStr255* name) {
    /* Native private directories contain NUL characters and have no host path. */
    for(unsigned i = 0; i < name->length; i++) if(!name->unicode[i]) return NULL;
    char buffer[2048], *in = (char*)name->unicode, *out = buffer;
    size_t insize = name->length * 2, outsize = sizeof(buffer)-1;
    iconv_t codec = iconv_open("UTF-8", endianness == IS_LITTLE_ENDIAN ? "UTF-16LE" : "UTF-16BE");
    if(codec == (iconv_t)-1 || iconv(codec, &in, &insize, &out, &outsize) == (size_t)-1) fail("invalid UTF-16 catalog name");
    iconv_close(codec); *out = 0;
    if(!strcmp(buffer, ".") || !strcmp(buffer, "..") || !*buffer || strchr(buffer, '/')) fail("unrepresentable host name");
    return strdup(buffer);
}
static void namefield(J* node, HFSUniStr255* name) {
    unsigned char buffer[510];
    for(unsigned i = 0; i < name->length; i++) { buffer[i*2] = name->unicode[i] >> 8; buffer[i*2+1] = name->unicode[i]; }
    puthex(node, "name_utf16be", buffer, name->length*2);
}
static HFSUniStr255 nodename(J* node) {
    size_t n; unsigned char* p = unhex(string(node, "name_utf16be"), &n);
    HFSUniStr255 name = {0};
    if(n % 2 || n > 510 || !n) fail("invalid native name");
    name.length = n/2;
    for(unsigned i = 0; i < name.length; i++) name.unicode[i] = p[i*2]*256 + p[i*2+1];
    free(p); return name;
}
static J* savefork(Context* c, HFSPlusCatalogFile* file, HFSPlusForkData* fork, const char* suffix) {
    if(c->inventory) return inventorycontent(c,file,fork,
        !strcmp(suffix,"resource") && !(file->permissions.ownerFlags & UF_COMPRESSED));
    char path[64]; snprintf(path, sizeof(path), "%u-%s", file->fileID, suffix);
    int fd = relative(c->storage, path, O_RDWR|O_CREAT|O_EXCL, 0, NULL);
    forkout(c, file, fork, fd); close(fd);
    return descriptor(c, "storage", path);
}
static void exportnode(Context* c, HFSPlusCatalogRecord* record, uint32_t parent, HFSUniStr255* name, const char* path, unsigned depth) {
    if(depth > 512) fail("catalog nesting limit");
    J* node = json_object_new_object();
    uint32_t id = cnid(record);
    putnum(node, "id", id); putnum(node, "parent", parent); namefield(node, name);
    if(path) putstr(node, "path", path); else json_object_object_add(node, "path", NULL);
    Record copy = {0};
    size_t recsize = isfolder(record) ? sizeof(HFSPlusCatalogFolder) : sizeof(HFSPlusCatalogFile);
    memcpy(&copy, record, recsize);
    if(!isfolder(record)) { memset(&copy.file.dataFork, 0, sizeof(copy.file.dataFork)); memset(&copy.file.resourceFork, 0, sizeof(copy.file.resourceFork)); }
    diskrecord(&copy); puthex(node, "catalog", &copy, recsize);
    J* attrs = json_object_new_object();
    XAttrList *list = getAllExtendedAttributesStrict(id, c->volume), *a = list;
    while(a) {
        unsigned char* data = NULL; size_t n = getAttribute(c->volume, id, a->name, &data);
        if(!data) fail("unsupported extended attribute storage");
        puthex(attrs, a->name, data, n); free(data);
        XAttrList* next = a->next; free(a->name); free(a); a = next;
    }
    json_object_object_add(node, "xattrs", attrs);
    json_object_array_add(c->nodes, node); indexnode(c, node);
    if(isfolder(record)) {
        if(!c->inventory && path && *path) {
            char* leaf; int dir = relative(c->tree, path, 0, 1, &leaf);
            if(mkdirat(dir, leaf, 0700)) fail("create export directory");
            free(leaf); close(dir);
        }
        CatalogRecordList *children = getFolderContentsRaw(id, c->volume);
        for(CatalogRecordList* child = children; child; child = child->next) {
            char *component = hostcomponent(&child->name), *childpath = NULL;
            if(path && component && asprintf(&childpath, "%s%s%s", path, *path ? "/" : "", component) < 0) fail("allocation");
            exportnode(c, child->record, id, &child->name, childpath, depth+1);
            free(component); free(childpath);
        }
        releaseCatalogRecordList(children);
        return;
    }
    HFSPlusCatalogFile* file = (HFSPlusCatalogFile*)record;
    if(file->userInfo.fileType == kHardLinkFileType) {
        HFSPlusCatalogFile* target = malloc(sizeof(*file)); memcpy(target, file, sizeof(*file));
        target = (HFSPlusCatalogFile*)getLinkTarget((HFSPlusCatalogRecord*)target, parent, NULL, c->volume);
        if(!target || target->recordType != kHFSPlusFileRecord) fail("unresolved native hardlink");
        putnum(node, "link_target", target->fileID); free(target);
        if(file->dataFork.logicalSize || file->resourceFork.logicalSize) fail("hardlink stub has forks");
        return;
    }
    int type = file->permissions.fileMode & S_IFMT;
    if(type == S_IFLNK) {
        if(!file->dataFork.logicalSize || file->dataFork.logicalSize > 4095) fail("symlink size");
        char target[4096]; io_func* io = openRawFile(id, &file->dataFork, record, c->volume);
        if(!io || !READ(io, 0, file->dataFork.logicalSize, target)) fail("symlink data");
        CLOSE(io);
        if(memchr(target, 0, file->dataFork.logicalSize)) fail("NUL in symlink");
        puthex(node, "target_hex", target, file->dataFork.logicalSize); target[file->dataFork.logicalSize] = 0;
        if(!c->inventory && path) { char* leaf; int dir = relative(c->tree, path, 0, 1, &leaf); if(symlinkat(target, dir, leaf)) fail("export symlink"); free(leaf); close(dir); }
    } else if(type == S_IFREG || type == 0) {
        char stored[64]; snprintf(stored, sizeof(stored), "%u-logical", id);
        const char* contentpath = path ? path : stored;
        if(c->inventory) json_object_object_add(node,"content",inventorycontent(c,file,NULL,0));
        else {
            int fd = relative(path ? c->tree : c->storage, contentpath, O_RDWR|O_CREAT|O_EXCL, 0, NULL);
            logicalout(c, file, fd); close(fd);
            json_object_object_add(node, "content", descriptor(c, path ? "tree" : "storage", contentpath));
        }
        if(parent == kHFSRootFolderID && path && !strcmp(path, ".journal_info_block") &&
           (c->volume->volumeHeader->attributes & 0x2000)) {
            if(file->dataFork.extents[0].startBlock != c->volume->volumeHeader->journalInfoBlock)
                fail("volume journal info does not match its catalog file");
            char* digest;
            if(c->inventory) {
                uint64_t size=file->dataFork.logicalSize;
                if(size<52 || size>1048576 || (file->permissions.ownerFlags & UF_COMPRESSED)) fail("journal info size/type");
                unsigned char* bytes=malloc((size_t)size); unsigned char hash[32]; unsigned int length;
                io_func* io=openRawFile(id,&file->dataFork,record,c->volume);
                if(!bytes || !io || !READ(io,0,(size_t)size,bytes)) fail("read journal info");
                memset(bytes+36,0,8);
                if(EVP_Digest(bytes,(size_t)size,hash,&length,EVP_sha256(),NULL)!=1 || length!=32) fail("journal digest");
                digest=hex(hash,32); free(bytes); CLOSE(io);
            } else digest = journal_digest(c, field(node, "content"));
            putstr(node, "journal_info_normalized_sha256", digest); free(digest);
        }
        if((file->permissions.ownerFlags & UF_COMPRESSED) && file->dataFork.logicalSize)
            json_object_object_add(node, "data_fork", savefork(c, file, &file->dataFork, "data"));
    } else if(file->dataFork.logicalSize) fail("special node with data fork");
    if(file->resourceFork.logicalSize)
        json_object_object_add(node, "resource_fork", savefork(c, file, &file->resourceFork, "resource"));
}
static void make_host_links(Context* c) {
    for(size_t i = 0; i < json_object_array_length(c->nodes); i++) {
        J *node = json_object_array_get_idx(c->nodes, i), *target, *path;
        if(!json_object_object_get_ex(node, "link_target", &target)) continue;
        J* backing = byid(c, json_object_get_int64(target));
        if(!json_object_object_get_ex(node, "path", &path) || !path) continue;
        J* content = field(backing, "content");
        char* leaf; int dir = relative(c->tree, json_object_get_string(path), 0, 1, &leaf);
        int base = !strcmp(string(content, "location"), "tree") ? c->tree : c->storage;
        if(linkat(base, string(content, "path"), dir, leaf, 0)) fail("export host hardlink");
        free(leaf); close(dir);
    }
}
static void forkimport(Context* c, HFSPlusCatalogFile* file, HFSPlusForkData* fork, J* content) {
    int fd = contentfd(c, content);
    io_func* io = openRawFile(file->fileID, fork, (HFSPlusCatalogRecord*)file, c->volume);
    int64_t length = json_object_get_int64(field(content, "size"));
    if((uint64_t)length / c->volume->volumeHeader->blockSize +
       (length % c->volume->volumeHeader->blockSize != 0) > c->volume->volumeHeader->freeBlocks)
        fail("no space left in volume");
    if(!io || !allocate(io->data, length)) fail("allocate native fork");
    unsigned char* buffer = malloc(CHUNK); uint64_t offset = 0; ssize_t n;
    if(!buffer) fail("allocation");
    while((n = read(fd, buffer, CHUNK)) > 0) { if(!WRITE(io, offset, n, buffer)) fail("write native fork"); offset += n; }
    if(n < 0 || offset != (uint64_t)length) fail("import file changed during read");
    free(buffer); close(fd); CLOSE(io);
}
typedef struct { uint32_t parent; HFSUniStr255 name; } NativeKey;
static int folding_keys;
static int compare_native_keys(const void* a, const void* b) {
    const NativeKey *x = a, *y = b;
    if(x->parent != y->parent) return x->parent < y->parent ? -1 : 1;
    if(folding_keys) {
        uint16_t left[255], right[255];
        memcpy(left, x->name.unicode, x->name.length*2); memcpy(right, y->name.unicode, y->name.length*2);
        return FastUnicodeCompare(left, x->name.length, right, y->name.length);
    }
    for(unsigned i = 0; i < x->name.length && i < y->name.length; i++)
        if(x->name.unicode[i] != y->name.unicode[i]) return x->name.unicode[i] < y->name.unicode[i] ? -1 : 1;
    return x->name.length < y->name.length ? -1 : x->name.length > y->name.length;
}
static J* rootnode(Context* c, const char* path) {
    for(size_t i = 0; i < json_object_array_length(c->nodes); i++) {
        J* node = json_object_array_get_idx(c->nodes, i), *value;
        if(number(node, "parent") == kHFSRootFolderID && json_object_object_get_ex(node, "path", &value) && value &&
           !strcmp(json_object_get_string(value), path)) return node;
    }
    fail("missing root journal catalog file"); return NULL;
}
static void validate_journal(Context* c) {
    if(!(number(c->document, "volume_attributes") & 0x2000)) return;
    if(!(number(c->document, "volume_attributes") & 0x100)) fail("source journal volume was not cleanly unmounted");
    J* info = rootnode(c, ".journal_info_block"), *journal = rootnode(c, ".journal");
    J* content = field(info, "content"); unsigned char bytes[52];
    int fd = contentfd(c, content);
    if(read(fd, bytes, 52) != 52 || be32(bytes) != 1) fail("unsupported external/uninitialized journal");
    close(fd);
    if(be64(bytes+44) != (uint64_t)json_object_get_int64(field(field(journal, "content"), "size"))) fail("journal size mismatch");
    char* digest = journal_digest(c, content);
    if(strcmp(digest, string(info, "journal_info_normalized_sha256"))) fail("journal info normalized digest mismatch");
    free(digest);
    fd = contentfd(c, field(journal, "content"));
    if(read(fd, bytes, 48) != 48) fail("journal header read");
    close(fd);
    uint64_t start, end;
    if(le32(bytes) == 0x4a4e4c78 && le32(bytes+4) == 0x12345678) { start = le64(bytes+8); end = le64(bytes+16); }
    else if(be32(bytes) == 0x4a4e4c78 && be32(bytes+4) == 0x12345678) { start = be64(bytes+8); end = be64(bytes+16); }
    else fail("unknown journal header");
    if(start != end) fail("journal contains pending transactions; replay is not supported");
}
static void validate_node(Context* c, J* node, Record* record, int root) {
    int folder = isfolder((HFSPlusCatalogRecord*)record);
    unsigned type = folder ? S_IFDIR : record->file.permissions.fileMode & S_IFMT;
    int hardlink = !folder && record->file.userInfo.fileType == kHardLinkFileType;
    int compressed = !folder && (record->file.permissions.ownerFlags & UF_COMPRESSED);
    J *path = field(node, "path"), *content = NULL, *target = NULL, *data = NULL, *resource = NULL, *link = NULL;
    int has_content = json_object_object_get_ex(node, "content", &content);
    int has_target = json_object_object_get_ex(node, "target_hex", &target);
    int has_data = json_object_object_get_ex(node, "data_fork", &data);
    int has_resource = json_object_object_get_ex(node, "resource_fork", &resource);
    int has_link = json_object_object_get_ex(node, "link_target", &link);
    if(!folder && type && type != S_IFREG && type != S_IFLNK && type != S_IFCHR &&
       type != S_IFBLK && type != S_IFIFO && type != S_IFSOCK) fail("unsupported catalog file mode");
    if((has_link != hardlink) || (has_content != (!folder && !hardlink && (type == S_IFREG || !type))) ||
       (has_target != (!folder && !hardlink && type == S_IFLNK)) ||
       (has_data && (!has_content || !compressed)) || (has_resource && (folder || hardlink)) ||
       (compressed && !has_content)) fail("catalog type disagrees with file contents");
    if(path && !json_object_is_type(path, json_type_string)) fail("namespace path type");
    const char* actual = path ? string(node, "path") : NULL;
    if(root) {
        if(!actual || *actual) fail("root namespace path");
    } else {
        J* parent = byid(c, number(node, "parent"));
        J* parent_path = field(parent, "path");
        HFSUniStr255 name = nodename(node);
        char* component = hostcomponent(&name);
        if(parent_path && component) {
            const char* prefix = string(parent, "path");
            char* expected;
            if(asprintf(&expected, "%s%s%s", prefix, *prefix ? "/" : "", component) < 0) fail("allocation");
            if(!actual || strcmp(actual, expected)) fail("namespace path differs from catalog");
            free(expected);
        } else if(actual) fail("private catalog node has a host path");
        free(component);
    }
    if(folder && actual && *actual) close(relative(c->tree, actual, O_RDONLY|O_DIRECTORY, 0, NULL));
    if(hardlink) {
        J* backing = byid(c, number(node, "link_target"));
        Record backing_record = decode_record(backing);
        if(isfolder((HFSPlusCatalogRecord*)&backing_record) ||
           backing_record.file.userInfo.fileType == kHardLinkFileType ||
           ((backing_record.file.permissions.fileMode & S_IFMT) != S_IFREG &&
            (backing_record.file.permissions.fileMode & S_IFMT) != 0)) fail("invalid hardlink backing record");
        HFSUniStr255 name = nodename(backing), expected = {0};
        char inode_name[32];
        snprintf(inode_name, sizeof(inode_name), "iNode%d", (int32_t)record->file.permissions.special.iNodeNum);
        ASCIIToUnicode(inode_name, &expected);
        if(name.length != expected.length || memcmp(name.unicode, expected.unicode, name.length*2))
            fail("hardlink reference differs from native backing name");
        J* directory = byid(c, number(backing, "parent"));
        HFSUniStr255 private_name = nodename(directory);
        static const uint16_t private_directory[] = {0, 0, 0, 0, 'H', 'F', 'S', '+', ' ', 'P', 'r', 'i', 'v', 'a', 't', 'e', ' ', 'D', 'a', 't', 'a'};
        if(number(directory, "parent") != kHFSRootFolderID ||
           private_name.length != sizeof(private_directory)/sizeof(private_directory[0]) ||
           memcmp(private_name.unicode, private_directory, sizeof(private_directory)))
            fail("hardlink backing is outside the native private directory");
        content = field(backing, "content");
    }
    if(!actual || folder || has_target) return;
    if(content) {
        struct stat stored, host;
        int fd = contentfd(c, content);
        if(fstat(fd, &stored)) fail("stat content");
        close(fd);
        fd = relative(c->tree, actual, O_RDONLY, 0, NULL);
        if(fstat(fd, &host) || !S_ISREG(host.st_mode) ||
           host.st_dev != stored.st_dev || host.st_ino != stored.st_ino) fail("host file or hardlink alias changed");
        close(fd);
    }
}
static void validate(Context* c) {
    if(strcmp(string(c->document, "schema"), SCHEMA)) fail("manifest schema");
    uint32_t attributes = number(c->document, "volume_attributes");
    if(!(attributes & 0x100) || (attributes & 0x800)) fail("unclean/inconsistent source volume");
    number(c->document, "last_mounted_version");
    size_t volume_size; unsigned char* volume_bytes = unhex(string(c->document, "encodings_bitmap"), &volume_size);
    free(volume_bytes); if(volume_size != 8) fail("encodings bitmap size");
    volume_bytes = unhex(string(c->document, "volume_finder_info"), &volume_size);
    free(volume_bytes); if(volume_size != 24) fail("volume FinderInfo size");
    uint32_t block = number(c->document, "block_size"), comparison = number(c->document, "key_compare_type");
    if(block < 512 || block > 1048576 || (block & (block-1)) ||
       (comparison != kHFSCaseFolding && comparison != kHFSBinaryCompare)) fail("volume geometry");
    J* dates = field(c->document, "volume_dates");
    if(!json_object_is_type(dates, json_type_array) || json_object_array_length(dates) != 4) fail("volume dates");
    for(unsigned i = 0; i < 4; i++) {
        J* date = json_object_array_get_idx(dates, i); int64_t value = json_object_get_int64(date);
        if(!json_object_is_type(date, json_type_int) || value < 0 || value > UINT32_MAX) fail("volume date value");
    }
    size_t count = json_object_array_length(c->nodes);
    if(!count || count > 2000000) fail("native node count");
    NativeKey* names = calloc(count, sizeof(*names));
    if(!names) fail("catalog key validation allocation");
    for(size_t i = 0; i < count; i++) {
        J* node = json_object_array_get_idx(c->nodes, i);
        names[i].parent = number(node, "parent"); names[i].name = nodename(node);
    }
    folding_keys = number(c->document, "key_compare_type") == kHFSCaseFolding;
    qsort(names, count, sizeof(*names), compare_native_keys);
    for(size_t i = 1; i < count; i++) if(!compare_native_keys(&names[i-1], &names[i])) fail("duplicate native catalog name");
    free(names);
    for(size_t i = 0; i < count; i++) indexnode(c, json_object_array_get_idx(c->nodes, i));
    J* seen = json_object_new_object();
    J* children = json_object_new_object();
    for(size_t i = 1; i < count; i++) {
        char key[16]; J* value;
        snprintf(key, sizeof(key), "%u", number(json_object_array_get_idx(c->nodes, i), "parent"));
        if(json_object_object_get_ex(children, key, &value)) json_object_set_int(value, json_object_get_int(value)+1);
        else json_object_object_add(children, key, json_object_new_int(1));
    }
    for(size_t i = 0; i < count; i++) {
        J* node = json_object_array_get_idx(c->nodes, i); Record record = decode_record(node);
        HFSUniStr255 name = nodename(node); (void)name;
        uint32_t id = number(node, "id"), parent = number(node, "parent");
        if((i == 0 && (id != kHFSRootFolderID || parent != 1 || !isfolder((HFSPlusCatalogRecord*)&record))) ||
           (i && (id < 16 || id == UINT32_MAX || parent == id))) fail("invalid CNID topology");
        if(i) {
            Record p = decode_record(byid(c, parent));
            if(!isfolder((HFSPlusCatalogRecord*)&p)) fail("parent is not a folder");
            /* Export order is a preorder; requiring it also rules out cycles. */
            char key[16]; J* previous;
            snprintf(key, sizeof(key), "%u", parent);
            if(!json_object_object_get_ex(seen, key, &previous)) fail("parent must precede child");
        }
        char idkey[16]; snprintf(idkey, sizeof(idkey), "%u", id);
        json_object_object_add(seen, idkey, json_object_new_boolean(1));
        J* value;
        if(isfolder((HFSPlusCatalogRecord*)&record) && record.folder.valence !=
           (json_object_object_get_ex(children, idkey, &value) ? (uint32_t)json_object_get_int(value) : 0))
            fail("folder valence differs from catalog");
        validate_node(c, node, &record, i == 0);
        const char* fields[] = {"content", "data_fork", "resource_fork"};
        for(unsigned k = 0; k < 3; k++) if(json_object_object_get_ex(node, fields[k], &value)) close(contentfd(c, value));
        verifycompression(c, node, &record);
        if(json_object_object_get_ex(node, "target_hex", &value)) {
            size_t n; unsigned char* p = unhex(string(node, "target_hex"), &n);
            if(!n || n > 4095 || memchr(p, 0, n)) fail("invalid symlink target");
            J* path = field(node, "path");
            if(path) {
                char* leaf; char actual[4096]; int dir = relative(c->tree, json_object_get_string(path), 0, 1, &leaf);
                ssize_t length = readlinkat(dir, leaf, actual, sizeof(actual)); free(leaf); close(dir);
                if(length != (ssize_t)n || memcmp(actual, p, n)) fail("symlink target changed");
            }
            free(p);
        }
        J* attrs = field(node, "xattrs");
        if(!json_object_is_type(attrs, json_type_object)) fail("xattrs type");
        json_object_object_foreach(attrs, key, attr) {
            if(!json_object_is_type(attr, json_type_string)) fail("xattr value must be hexadecimal text");
            size_t n; unsigned char* p = unhex(string(attrs, key), &n); free(p);
            if(!*key || strlen(key) > 127 || n + strlen(key)*2 + 32 > 8192/2)
                fail("unsupported xattr name or inline size");
            for(const unsigned char* letter = (const unsigned char*)key; *letter; letter++)
                if(*letter > 127) fail("unsupported non-ASCII extended attribute name");
        }
    }
    json_object_put(seen);
    json_object_put(children);
    validate_journal(c);
}
static void insert(Context* c, J* node) {
    Record record = decode_record(node); uint32_t id = number(node, "id");
    if(id == kHFSRootFolderID) {
        HFSPlusCatalogKey key = {0}; int exact;
        key.parentID = id; key.keyLength = 6;
        HFSPlusCatalogThread* old = search(c->volume->catalogTree, (BTKey*)&key, &exact, NULL, NULL);
        if(!old || !exact) fail("destination root thread");
        if(!removeFromBTree(c->volume->catalogTree, (BTKey*)&key)) fail("remove destination root thread");
        key.parentID = old->parentID; key.nodeName = old->nodeName;
        key.keyLength = 6 + key.nodeName.length*2;
        free(old);
        if(!removeFromBTree(c->volume->catalogTree, (BTKey*)&key)) fail("remove destination root name");
    }
    {
        HFSPlusCatalogKey key = {0}; HFSPlusCatalogThread thread = {0};
        key.parentID = number(node, "parent"); key.nodeName = nodename(node);
        key.keyLength = 6 + key.nodeName.length*2;
        Record disk = record; diskrecord(&disk);
        if(!addToBTree(c->volume->catalogTree, (BTKey*)&key,
            isfolder((HFSPlusCatalogRecord*)&record) ? sizeof(HFSPlusCatalogFolder) : sizeof(HFSPlusCatalogFile), (unsigned char*)&disk)) fail("insert catalog record");
        thread.recordType = isfolder((HFSPlusCatalogRecord*)&record) ? kHFSPlusFolderThreadRecord : kHFSPlusFileThreadRecord;
        thread.parentID = key.parentID; thread.nodeName = key.nodeName;
        size_t length = 10 + key.nodeName.length*2; flipCatalogThread(&thread, TRUE);
        key.parentID = id; key.nodeName.length = 0; key.keyLength = 6;
        if(!addToBTree(c->volume->catalogTree, (BTKey*)&key, length, (unsigned char*)&thread)) fail("insert catalog thread");
    }
    J* value;
    if(!isfolder((HFSPlusCatalogRecord*)&record)) {
        if(json_object_object_get_ex(node, "target_hex", &value)) {
            size_t n; unsigned char* p = unhex(json_object_get_string(value), &n);
            io_func* io = openRawFile(id, &record.file.dataFork, (HFSPlusCatalogRecord*)&record, c->volume);
            if(!io || !WRITE(io, 0, n, p)) fail("import symlink");
            CLOSE(io); free(p);
        } else if(json_object_object_get_ex(node, "content", &value)) {
            if(record.file.permissions.ownerFlags & UF_COMPRESSED) {
                if(json_object_object_get_ex(node, "data_fork", &value)) forkimport(c, &record.file, &record.file.dataFork, value);
            } else forkimport(c, &record.file, &record.file.dataFork, value);
        }
        if(json_object_object_get_ex(node, "resource_fork", &value)) forkimport(c, &record.file, &record.file.resourceFork, value);
        if(!updateCatalog(c->volume, (HFSPlusCatalogRecord*)&record)) fail("update file forks");
    }
    J* attrs = field(node, "xattrs");
    json_object_object_foreach(attrs, key, attr) {
        size_t n; unsigned char* p = unhex(json_object_get_string(attr), &n);
        if(!setAttribute(c->volume, id, key, p, n)) fail("import extended attribute");
        free(p);
    }
}
static void putbe16(unsigned char* p, uint16_t n) { p[0] = n >> 8; p[1] = n; }
static void putbe32(unsigned char* p, uint32_t n) { p[0] = n >> 24; p[1] = n >> 16; p[2] = n >> 8; p[3] = n; }
static void relocate_journal(Context* c) {
    c->volume->volumeHeader->attributes = number(c->document, "volume_attributes");
    c->volume->volumeHeader->lastMountedVersion = number(c->document, "last_mounted_version");
    size_t size; unsigned char* bytes = unhex(string(c->document, "volume_finder_info"), &size);
    memcpy(c->volume->volumeHeader->finderInfo, bytes, size); free(bytes);
    bytes = unhex(string(c->document, "encodings_bitmap"), &size);
    c->volume->volumeHeader->encodingsBitmap = be64(bytes); free(bytes);
    if(!(c->volume->volumeHeader->attributes & 0x2000)) return;
    HFSPlusCatalogFile* info = (HFSPlusCatalogFile*)getRecordByCNID(number(rootnode(c, ".journal_info_block"), "id"), c->volume);
    HFSPlusCatalogFile* journal = (HFSPlusCatalogFile*)getRecordByCNID(number(rootnode(c, ".journal"), "id"), c->volume);
    if(!info || !journal || info->recordType != kHFSPlusFileRecord || journal->recordType != kHFSPlusFileRecord)
        fail("rebuilt journal catalog records");
    uint64_t blocks = 0; uint32_t start = journal->dataFork.extents[0].startBlock;
    for(unsigned i = 0; i < 8 && journal->dataFork.extents[i].blockCount; i++) {
        if(journal->dataFork.extents[i].startBlock != start + blocks) fail("rebuilt journal is fragmented");
        blocks += journal->dataFork.extents[i].blockCount;
    }
    if(blocks != journal->dataFork.totalBlocks) fail("rebuilt journal has overflow extents");
    uint64_t offset = (uint64_t)start*c->volume->volumeHeader->blockSize;
    unsigned char address[8]; putbe32(address, offset>>32); putbe32(address+4, offset);
    io_func* io = openRawFile(info->fileID, &info->dataFork, (HFSPlusCatalogRecord*)info, c->volume);
    if(!io || !WRITE(io, 36, 8, address)) fail("relocate journal info offset");
    CLOSE(io);
    c->volume->volumeHeader->journalInfoBlock = info->dataFork.extents[0].startBlock;
    free(info); free(journal);
}
static void prepare_attributes(Context* c) {
    uint64_t bytes = 0;
    unsigned node_size = c->volume->attrTree ? c->volume->attrTree->headerRec->nodeSize : 8192;
    for(size_t i = 0; i < json_object_array_length(c->nodes); i++) {
        J* attrs = field(json_object_array_get_idx(c->nodes, i), "xattrs");
        json_object_object_foreach(attrs, key, attr) {
            size_t n = strlen(json_object_get_string(attr))/2;
            if(n + strlen(key)*2 + 32 > node_size/2) fail("inline xattr exceeds attribute node capacity");
            bytes += n + strlen(key)*2 + 32;
        }
    }
    if(!bytes || c->volume->attrTree) return;
    /* Preallocate enough nodes to avoid repeated growth. The header's map
     * covers this bounded tree; larger manifests need explicit map nodes. */
    uint32_t nodes = (bytes*2 + 8191)/8192 + 16;
    if(nodes > (8192-256)*8) fail("attribute tree exceeds supported header bitmap");
    HFSPlusForkData* fork = &c->volume->volumeHeader->attributesFile;
    fork->clumpSize = 128*1024;
    io_func* io = openRawFile(kHFSAttributesFileID, fork, NULL, c->volume);
    if(!io || !allocate(io->data, (uint64_t)nodes*8192)) fail("allocate attribute tree");
    unsigned char header[8192] = {0};
    header[8] = kBTHeaderNode; putbe16(header+10, 3);
    putbe16(header+32, 8192); putbe16(header+34, 266);
    putbe32(header+36, nodes); putbe32(header+40, nodes-1);
    putbe32(header+46, fork->clumpSize); putbe32(header+52, 6);
    header[248] = 0x80;
    putbe16(header+8190, 14); putbe16(header+8188, 120);
    putbe16(header+8186, 248); putbe16(header+8184, 8184);
    if(!WRITE(io, 0, sizeof(header), header)) fail("write attribute header");
    c->volume->attrTree = openAttributesTree(io);
    if(!c->volume->attrTree) fail("open new attribute tree");
}
static int manifest_command(int argc, const char** argv, io_func *memory) {
    int inventory = !strcmp(argv[2], "inventory");
    int metadata_only = inventory && argc == 5 && !strcmp(argv[4], "--metadata-only");
    int exporting = inventory || !strcmp(argv[2], "extractall");
    int validating = !strcmp(argv[2], "validateall");
    if((inventory && argc != 4 && !metadata_only) || (!inventory && (exporting || validating) && (argc != 6 || strcmp(argv[4], "--manifest"))) ||
       ((!exporting && !validating) && (argc != 7 || strcmp(argv[4], "/") || strcmp(argv[5], "--manifest"))))
        fail("usage: IMAGE extractall TREE --manifest JSON | IMAGE addall TREE / --manifest JSON");
    const char *tree = inventory ? NULL : argv[3], *manifest = argv[inventory ? 3 : (exporting || validating) ? 5 : 6];
    char* storage; if(asprintf(&storage, "%s.files", manifest) < 0) fail("allocation");
    Context c = {0}; c.inventory=inventory; c.metadata_only=metadata_only; c.tree=c.storage=-1;
    c.index = json_object_new_object();
    if(exporting) {
        if(access(manifest, F_OK) == 0 || (!inventory && (mkdir(tree, 0700) || mkdir(storage, 0700)))) fail("export destinations must be new");
        c.document = json_object_new_object(); c.nodes = json_object_new_array();
        putstr(c.document, "schema", metadata_only ? "apple-firmware.hfs-inventory-metadata/1" : inventory ? "apple-firmware.hfs-inventory/1" : SCHEMA); json_object_object_add(c.document, "nodes", c.nodes);
    } else {
        int fd = open(manifest, O_RDONLY|O_NOFOLLOW);
        struct stat st;
        if(fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
           st.st_size <= 0 || st.st_size > 256 * 1024 * 1024) fail("manifest input size/type");
        c.document = json_object_from_fd(fd);
        close(fd);
        if(!c.document) fail("cannot read manifest JSON");
        c.nodes = field(c.document, "nodes");
        if(!json_object_is_type(c.nodes, json_type_array)) fail("nodes type");
    }
    if(!inventory) {
    c.tree = open(tree, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    c.storage = open(storage, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(c.tree < 0 || c.storage < 0) fail("open tree/storage directories");
    }
    if(!exporting) validate(&c); /* No image is opened for writing until all inputs pass. */
    if(validating) {
        close(c.tree); close(c.storage); json_object_put(c.index); json_object_put(c.document); free(storage);
        return 0;
    }
    io_func* io = memory ? memory : exporting ? openFlatFileRO(argv[1]) : openFlatFile(argv[1]);
    if(!io || !(c.volume = openVolume(io))) fail("open HFS volume");
    if(exporting) {
        if(c.volume->volumeHeader->startupFile.logicalSize || c.volume->volumeHeader->startupFile.totalBlocks)
            fail("startup-file metadata is unsupported");
        putnum(c.document, "block_size", c.volume->volumeHeader->blockSize);
        putnum(c.document, "volume_attributes", c.volume->volumeHeader->attributes);
        putnum(c.document, "last_mounted_version", c.volume->volumeHeader->lastMountedVersion);
        unsigned char bitmap[8];
        uint64_t bits = c.volume->volumeHeader->encodingsBitmap;
        putbe32(bitmap, bits>>32); putbe32(bitmap+4, bits);
        puthex(c.document, "encodings_bitmap", bitmap, 8);
        puthex(c.document, "volume_finder_info", c.volume->volumeHeader->finderInfo, 24);
        putnum(c.document, "key_compare_type", c.volume->catalogTree->headerRec->keyCompareType);
        J* dates = json_object_new_array();
        HFSPlusVolumeHeader* v = c.volume->volumeHeader;
        uint32_t values[] = {v->createDate, v->modifyDate, v->backupDate, v->checkedDate};
        for(unsigned i = 0; i < 4; i++) json_object_array_add(dates, json_object_new_int64(values[i]));
        json_object_object_add(c.document, "volume_dates", dates);
        HFSPlusCatalogRecord* root = getRecordByCNID(kHFSRootFolderID, c.volume);
        /* The root name is in its thread record, not its folder record. */
        HFSPlusCatalogKey key = {0}; int exact;
        key.parentID = kHFSRootFolderID; key.keyLength = 6;
        HFSPlusCatalogThread* thread = search(c.volume->catalogTree, (BTKey*)&key, &exact, NULL, NULL);
        if(!root || !thread || !exact) fail("root catalog/thread");
        exportnode(&c, root, 1, &thread->nodeName, "", 0); free(root); free(thread);
        if(!inventory) make_host_links(&c);
        int fd = open(manifest, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
        if(fd < 0 || json_object_to_fd(fd, c.document, JSON_C_TO_STRING_PRETTY) || fsync(fd)) fail("write manifest");
        if(close(fd)) fail("close manifest");
    } else {
        if(number(c.document, "block_size") != c.volume->volumeHeader->blockSize ||
           number(c.document, "key_compare_type") != c.volume->catalogTree->headerRec->keyCompareType) fail("destination block size or case mode differs");
        CatalogRecordList* children = getFolderContentsRaw(kHFSRootFolderID, c.volume);
        if(children || c.volume->volumeHeader->fileCount) fail("destination must be freshly formatted and empty");
        prepare_attributes(&c);
        uint32_t files = 0, folders = 0, maxid = 16;
        for(size_t i = 0; i < json_object_array_length(c.nodes); i++) {
            J* node = json_object_array_get_idx(c.nodes, i); Record r = decode_record(node);
            if(isfolder((HFSPlusCatalogRecord*)&r)) { if(i) folders++; } else files++;
            uint32_t id = number(node, "id"); if(id >= maxid) maxid = id+1;
            insert(&c, node);
        }
        c.volume->volumeHeader->fileCount = files; c.volume->volumeHeader->folderCount = folders;
        c.volume->volumeHeader->nextCatalogID = maxid;
        relocate_journal(&c);
        J* dates = field(c.document, "volume_dates");
        c.volume->volumeHeader->createDate = json_object_get_int64(json_object_array_get_idx(dates, 0));
        c.volume->volumeHeader->modifyDate = json_object_get_int64(json_object_array_get_idx(dates, 1));
        c.volume->volumeHeader->backupDate = json_object_get_int64(json_object_array_get_idx(dates, 2));
        c.volume->volumeHeader->checkedDate = json_object_get_int64(json_object_array_get_idx(dates, 3));
        if(!updateVolume(c.volume)) fail("write volume header");
    }
    closeVolume(c.volume); CLOSE(io); close(c.tree); close(c.storage);
    json_object_put(c.index); json_object_put(c.document); free(storage);
    return 0;
}

static int extractfiles(int argc,const char** argv) {
    if(argc!=6 || strcmp(argv[4],"--request")) fail("usage: IMAGE extractfiles TREE --request JSON");
    Context c={0}; int streaming=!strcmp(argv[5],"-"); char* line=NULL; size_t capacity=0;
    c.tree=open(argv[3],O_RDONLY|O_DIRECTORY|O_NOFOLLOW); if(c.tree<0) fail("open extraction tree");
    io_func* io=openFlatFileRO(argv[1]); if(!io || !(c.volume=openVolume(io))) fail("open extraction volume");
    do {
        J* request;
        if(streaming) {
            ssize_t length=getline(&line,&capacity,stdin);
            if(length<0) { if(!feof(stdin)) fail("read extraction request"); break; }
            if(length>16*1024*1024) fail("request too large");
            request=json_tokener_parse(line);
        } else {
            struct stat st; int fd=open(argv[5],O_RDONLY|O_NOFOLLOW);
            if(fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>16*1024*1024) fail("request size/type");
            request=json_object_from_fd(fd); close(fd);
        }
        J* files=field(request,"files");
        if(!json_object_is_type(files,json_type_array)) fail("request files type");
        for(size_t i=0;i<json_object_array_length(files);i++) {
            J* entry=json_object_array_get_idx(files,i);
            HFSPlusCatalogRecord* record=getRecordByCNID(number(entry,"id"),c.volume);
            if(!record || record->recordType!=kHFSPlusFileRecord) fail("extraction requires file inode");
            HFSPlusCatalogFile* file=(HFSPlusCatalogFile*)record;
            int type=file->permissions.fileMode & S_IFMT;
            if((type!=S_IFREG && type!=0) || file->userInfo.fileType==kHardLinkFileType) fail("extraction requires regular backing inode");
            int fd=relative(c.tree,string(entry,"path"),O_WRONLY|O_CREAT|O_EXCL,0,NULL);
            EVP_MD_CTX* hash=EVP_MD_CTX_new(); unsigned char digest[32]; unsigned int length;
            if(!hash || EVP_DigestInit_ex(hash,EVP_sha256(),NULL)!=1) fail("extraction digest initialization");
            logicalhashout(&c,file,fd,hash); if(close(fd)) fail("close extracted file");
            if(EVP_DigestFinal_ex(hash,digest,&length)!=1 || length!=32) fail("extraction digest final");
            EVP_MD_CTX_free(hash); puthex(entry,"sha256",digest,32);
            json_object_object_add(entry,"size",json_object_new_uint64(logicalsize(&c,file))); free(record);
        }
        if(puts(json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN))<0 || fflush(stdout)) fail("write extraction receipt");
        json_object_put(request);
    } while(streaming);
    free(line); closeVolume(c.volume); CLOSE(io); close(c.tree); return 0;
}

int hfs_manifest_command(int argc, const char **argv) {
    if(argc>=3 && !strcmp(argv[2],"extractfiles")) return extractfiles(argc,argv);
    return manifest_command(argc,argv,NULL);
}
int hfs_manifest_import_memory(io_func *io, const char *tree, const char *manifest) {
    if (!io) return 1;
    const char *args[]={"hfsplus",":memory:","addall",tree,"/","--manifest",manifest};
    return manifest_command(7,args,io);
}

int hfs_manifest_export_memory(io_func *io, const char *tree, const char *manifest) {
    if (!io) return 1;
    const char *args[]={"hfsplus",":memory:","extractall",tree,"--manifest",manifest};
    return manifest_command(6,args,io);
}
