// Option processing code adapted from libfuse/lib/helper.c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include <fuse/fuse_opt.h>
#include <glib.h>

#include "config.h"
#include "dhtfs-config.h"

enum {
    KEY_HELP,
    KEY_VERSION,
};

// clang-format off
#define CMD_OPT(t, p) { t, G_STRUCT_OFFSET(struct config, p), 1 }
// clang-format on

// Command-line options
static const struct fuse_opt fuse_cmd_opts[] = {
    CMD_OPT("-d", foreground),
    CMD_OPT("debug", foreground),
    CMD_OPT("-f", foreground),
    CMD_OPT("-s", singlethread),
    CMD_OPT("host=%s", dht_host),
    CMD_OPT("port=%d", dht_port),
    CMD_OPT("name=%s", fs_name),
    CMD_OPT("cache=%s", cache_path),
    CMD_OPT("umask=%o", umask),
    CMD_OPT("umask_cache=%o", umask_cache),
    CMD_OPT("attr_timeout=%lf", attr_timeout),
    CMD_OPT("no_inode_timeout=%lf", no_inode_timeout),
    CMD_OPT("snapshot=%lu", snap_time),
    CMD_OPT("snapshot_period=%u", snap_period),
    FUSE_OPT_KEY("-h", KEY_HELP),
    FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_KEY("-V", KEY_VERSION),
    FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_KEY("-d", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_KEY("debug", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

static void cmd_usage(const char* progname)
{
    fprintf(stderr,
        "usage: %s mountpoint [options]\n\n", progname);
    fprintf(stderr,
        "general options:\n"
        "    -o opt,[opt...]        mount options\n"
        "    -h   --help            print help\n"
        "    -V   --version         print version\n"
        "\n");
}

static void cmd_help(void)
{
    fprintf(stderr,
        "DHTFS options:\n"
        "    -o host=HOST           DHT host (default: %s)\n"
        "    -o port=PORT           DHT port (default: %d)\n"
        "    -o name=NAME           name of the file system\n"
        "    -o cache=PATH          path to the directory to use for caching\n"
        "    -o umask=MASK          file-creation umask (default: %#o)\n"
        "    -o cache_umask=MASK    file-creation umask for cache (default: %#o)\n"
        "    -o attr_timeout=F      attribute caching timeout (default: %.1fs)\n"
        "    -o no_inode_timeout=F  non-existent inode timeout (default: %.1fs)\n"
        "    -o snapshot=TIMESTAMP  mount read-only snapshot at the given time\n"
        "    -o snapshot_period=SEC interval in seconds for periodic snapshotting\n"
        "\n"
        "If name is not specified, the name `%s' is assumed. Cache path\n"
        "has to reside on a BTRFS file system and the path must be writable by\n"
        "the current user. If cache path is not given, dhtfs will attempt to\n"
        "use the home directory of the current user.\n"
        "\n"
        "Period snapshotting is disabled by default.\n"
        "\n"
        "FUSE options:\n"
        "    -d   -o debug          enable debug output (implies -f)\n"
        "    -f                     foreground operation\n"
        "    -s                     disable multi-threaded operation\n"
        "\n",
        CONFIG_DEFAULT_HOST,
        CONFIG_DEFAULT_PORT,
        CONFIG_DEFAULT_UMASK,
        CONFIG_DEFAULT_UMASK_CACHE,
        CONFIG_DEFAULT_ATTR_TIMEOUT,
        CONFIG_DEFAULT_NO_INODE_TIMEOUT,
        CONFIG_DEFAULT_NAME);
}

static void cmd_version(void)
{
    fprintf(stderr, "DHTFS version: %s\n", PACKAGE_VERSION);
}

// Process a command-line option
static int cmd_opt_proc(void* data, const char* arg, int key, struct fuse_args* args)
{
    struct config* config = data;

    switch (key) {
    case KEY_HELP:
        cmd_usage(args->argv[0]);
        cmd_help();
        return fuse_opt_add_arg(args, "-h");
    case KEY_VERSION:
        cmd_version();
        return 1;
    case FUSE_OPT_KEY_NONOPT:
        // The only non-option argument is the mountpoint
        if (config->mountpoint == NULL) {
            char mountpoint[MAXPATHLEN];
            if (realpath(arg, mountpoint) == NULL) {
                fprintf(stderr, "fuse: bad mount point `%s': %s\n",
                    arg,
                    g_strerror(errno));
                return -1;
            }
            return fuse_opt_add_opt(&config->mountpoint, mountpoint);
        } else {
            fprintf(stderr, "fuse: invalid argument `%s'\n", arg);
            return -1;
        }
    default:
        break;
    }
    return 1;
}

// Read configuration from the command-line. Return 0 on success or -1 on error.
int fs_config_read(struct config* config, struct fuse_args* args)
{
    g_return_val_if_fail(config != NULL, -1);
    g_return_val_if_fail(args != NULL, -1);

    memset(config, 0, sizeof(*config));
    // Set defaults before reading
    config->dht_port = CONFIG_DEFAULT_PORT;
    config->umask = CONFIG_DEFAULT_UMASK;
    config->umask_cache = CONFIG_DEFAULT_UMASK_CACHE;
    config->attr_timeout = CONFIG_DEFAULT_ATTR_TIMEOUT;
    config->no_inode_timeout = CONFIG_DEFAULT_NO_INODE_TIMEOUT;
    // Parse the options
    int err = fuse_opt_parse(args, config, fuse_cmd_opts, cmd_opt_proc);
    if (err != 0) {
        free(config->mountpoint);
        free(config->dht_host);
        free(config->fs_name);
        free(config->cache_path);
        return err;
    }
    if (config->dht_host == NULL)
        config->dht_host = strdup(CONFIG_DEFAULT_HOST);
    if (config->fs_name == NULL)
        config->fs_name = strdup(CONFIG_DEFAULT_NAME);

    return 0;
}

// Free fields of struct config populated by a successful call to fs_config_read()
void fs_config_free_fields(struct config* config)
{
    g_return_if_fail(config != NULL);

    free(config->mountpoint);
    free(config->dht_host);
    free(config->fs_name);
    free(config->cache_path);
}
