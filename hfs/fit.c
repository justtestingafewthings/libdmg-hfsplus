/* Plan with the real allocator in memory; publish one verified bare image. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef _WIN32
int hfs_fit_command(int argc, const char **argv) {
    (void)argc;
    (void)argv;
    return 1;
}
#else
#include "../common/image_fit.h"
#include "format.h"
#include "manifest.h"
#include "verify.h"
#include <hfs/hfsplus.h>
#include <json-c/json.h>
typedef struct {
    const char *tree, *manifest;
    uint32_t bs;
    int sensitive, preserve_uuid;
    unsigned char uuid[8];
} plan_context;
static uint32_t read32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static int load_config(plan_context *p, const char *path) {
    json_object *doc = json_object_from_file(path), *v;
    int64_t bs, compare;
    if (!doc)
        return 1;
    if (!json_object_object_get_ex(doc, "block_size", &v) || !json_object_is_type(v, json_type_int))
        goto bad;
    bs = json_object_get_int64(v);
    if (!json_object_object_get_ex(doc, "key_compare_type", &v) || !json_object_is_type(v, json_type_int))
        goto bad;
    compare = json_object_get_int64(v);
    if (bs < 512 || bs > 1048576 || (bs & (bs - 1)) || (compare != 0xbc && compare != 0xcf))
        goto bad;
    p->bs = (uint32_t)bs;
    p->sensitive = compare == 0xbc;
    json_object_put(doc);
    return 0;
bad:
    json_object_put(doc);
    fprintf(stderr, "invalid native HFS format parameters\n");
    return 1;
}
static int build_image(void *data, uint64_t size, void *opaque, uint64_t *free_bytes) {
    plan_context *p = opaque;
    io_func *io = fit_io(data, size);
    if (!io || hfs_format_memory(io, size, p->bs, "HFS", p->sensitive)) {
        if (io)
            CLOSE(io);
        return 1;
    }
    if (hfs_manifest_import_memory(io, p->tree, p->manifest))
        return 1; /* closes io */
    if (p->preserve_uuid) {
        memcpy((char *)data + 1024 + 104, p->uuid, 8);
        memcpy((char *)data + size - 1024 + 104, p->uuid, 8);
    }
    *free_bytes = (uint64_t)read32((unsigned char *)data + 1024 + 48) * p->bs;
    return 0;
}
static int export_manifest(const char *image, fit_image *memory, const char *tree, const char *json) {
    int status;
    pid_t child;
    const char *args[] = {"hfsplus", image, "extractall", tree, "--manifest", json};
    fflush(NULL);
    child = fork();
    if (child == 0) {
        int ret = memory ? hfs_manifest_export_memory(fit_io(memory->data, memory->size), tree, json)
                         : hfs_manifest_command(6, args);
        fflush(NULL);
        _exit(ret ? 1 : 0);
    }
    if (child < 0)
        return 1;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR)
            return 1;
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
static void normalize_journal(json_object *doc) {
    json_object *nodes;
    if (!json_object_object_get_ex(doc, "nodes", &nodes))
        return;
    for (size_t i = 0; i < json_object_array_length(nodes); i++) {
        json_object *n = json_object_array_get_idx(nodes, i), *hash, *content;
        if (json_object_object_get_ex(n, "journal_info_normalized_sha256", &hash) &&
            json_object_object_get_ex(n, "content", &content))
            json_object_object_add(content, "sha256", json_object_get(hash));
    }
}
static int shrink_image(int argc, const char **argv) {
    const char *path = argv[1];
    uint64_t size;
    struct stat original;
    fit_image image = {0};
    plan_context p = {0};
    char *workspace = NULL, *tree = NULL, *manifest = NULL, *checktree = NULL, *checkjson = NULL;
    json_object *a = NULL, *b = NULL;
    int ret = 1, fd;
    if (argc != 4 || !fit_size(argv[3], &size) || size < 16 * FIT_MIB || size > FIT_LIMIT ||
        lstat(path, &original) || (!S_ISREG(original.st_mode) || original.st_nlink != 1) ||
        size >= (uint64_t)original.st_size || hfs_verify_image(path))
        goto done;
    workspace = fit_workspace("hfs-shrink");
    if (!workspace)
        goto done;
    tree = malloc(strlen(workspace) + 24);
    manifest = malloc(strlen(workspace) + 32);
    checktree = malloc(strlen(workspace) + 24);
    checkjson = malloc(strlen(workspace) + 32);
    if (!tree || !manifest || !checktree || !checkjson)
        goto done;
    sprintf(tree, "%s/tree", workspace);
    sprintf(manifest, "%s/manifest.json", workspace);
    sprintf(checktree, "%s/verification", workspace);
    sprintf(checkjson, "%s/verification.json", workspace);
    if (export_manifest(path, NULL, tree, manifest) || load_config(&p, manifest) || size % p.bs)
        goto done;
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        goto done;
    ssize_t got = pread(fd, p.uuid, 8, 1024 + 104);
    close(fd);
    if (got != 8)
        goto done;
    p.preserve_uuid = 1;
    p.tree = tree;
    p.manifest = manifest;
    if (fit_probe(size, build_image, &p, &image) || hfs_verify_memory(image.data, image.size) ||
        export_manifest(NULL, &image, checktree, checkjson))
        goto done;
    a = json_object_from_file(manifest);
    b = json_object_from_file(checkjson);
    if (!a || !b)
        goto done;
    normalize_journal(a);
    normalize_journal(b);
    if (!json_object_equal(a, b)) {
        fprintf(stderr, "shrink changed native metadata or file contents\n");
        goto done;
    }
    ret = fit_publish(path, &image, &original);
    if (!ret)
        fit_report(&image);
done:
    fit_release(&image);
    if (a)
        json_object_put(a);
    if (b)
        json_object_put(b);
    if (workspace) {
        if (fit_remove_tree(workspace))
            fprintf(stderr, "cannot remove shrink workspace %s\n", workspace);
        free(workspace);
    }
    free(tree);
    free(manifest);
    free(checktree);
    free(checkjson);
    if (ret)
        fprintf(stderr, "shrink failed; source image was not replaced (requires a supported bare HFS+/HFSX "
                        "image, 16 MiB..2 GiB)\n");
    return ret;
}
static int fit_usage(void) {
    fprintf(stderr, "usage: hfsplus IMAGE fit TREE --manifest JSON [--size N] [--reserve N] [--maximum N]\n");
    return 1;
}
int hfs_fit_command(int argc, const char **argv) {
    plan_context p = {0};
    fit_image image = {0};
    fit_options options = {2 * FIT_MIB, 0, FIT_LIMIT, 0};
    int i, ret = 1;
    if (argc >= 3 && !strcmp(argv[2], "shrink"))
        return shrink_image(argc, argv);
    struct stat destination;
    if (argc < 6)
        return fit_usage();
    if (!lstat(argv[1], &destination) || errno != ENOENT) {
        fprintf(stderr, "fit output must be a new path\n");
        return 1;
    }
    p.tree = argv[3];
    for (i = 4; i < argc; i += 2) {
        if (i + 1 >= argc)
            return fit_usage();
        if (!strcmp(argv[i], "--manifest")) {
            if (p.manifest)
                return fit_usage();
            p.manifest = argv[i + 1];
        } else if (fit_option(&options, argv[i], argv[i + 1]) != 1)
            return fit_usage();
    }
    if (!p.manifest)
        return fit_usage();
    if (!fit_options_valid(&options, 16 * FIT_MIB) || load_config(&p, p.manifest))
        return 1;
    uint64_t reserve = options.reserve, exact = options.exact, maximum = options.maximum;
    /* The formatter increases its reserved B-trees at 128 and 512 MiB.
     * Search each interval separately; available space is not monotonic
     * across those boundaries. */
    int planned = 1;
    uint64_t starts[] = {16 * FIT_MIB, 128 * FIT_MIB, 512 * FIT_MIB};
    uint64_t ends[] = {127 * FIT_MIB, 511 * FIT_MIB, FIT_LIMIT};
    if (exact)
        planned = fit_plan(build_image, &p, 16 * FIT_MIB, maximum, exact, reserve, &image);
    else
        for (unsigned range = 0; range < 3 && starts[range] <= maximum; range++) {
            uint64_t end = maximum < ends[range] ? maximum : ends[range];
            planned = fit_plan(build_image, &p, starts[range], end, 0, reserve, &image);
            if (planned != 2)
                break;
            fit_release(&image);
        }
    if (planned == 2)
        fprintf(stderr, "payload cannot fit with the required free-space reserve\n");
    if (!planned && !hfs_verify_memory(image.data, image.size)) {
        ret = fit_publish(argv[1], &image, NULL);
        if (!ret)
            fit_report(&image);
    }
    fit_release(&image);
    return ret;
}

#endif
