#pragma once

#include <fuse/fuse_opt.h>

// Whether we enable benchmarking
#define BENCHMARK

// DHT defaults
#define CONFIG_DEFAULT_HOST "localhost"
#define CONFIG_DEFAULT_PORT 9090

// Default file system name
#define CONFIG_DEFAULT_NAME "default"

// Default umasks
#define CONFIG_DEFAULT_UMASK 022
#define CONFIG_DEFAULT_UMASK_CACHE 022

// Default file attribute caching timeout in seconds
#define CONFIG_DEFAULT_ATTR_TIMEOUT 5.0
// Default non-existent inode caching timeout in seconds
#define CONFIG_DEFAULT_NO_INODE_TIMEOUT 1.0

// Index configuration for millisecond precision

// Multiplier to convert from seconds
#define CONFIG_INDEX_SECS_MULTIPLIER 1000

// Search key bounds
#define CONFIG_ADD_SEARCH_KEY_MIN 0LL
#define CONFIG_ADD_SEARCH_KEY_MAX 34359738368LL

// Default time to scan back looking for directory diffs
#define CONFIG_DIR_DIFFS_RANGE_DELTA (1 * CONFIG_INDEX_SECS_MULTIPLIER)

struct config {
    int singlethread;
    int foreground;
    char* mountpoint;
    char* dht_host;
    int dht_port;
    char* fs_name;
    char* cache_path;
    int umask;
    int umask_cache;
    double attr_timeout;
    double no_inode_timeout;
    u_int64_t snap_time;
    unsigned int snap_period;
};

int fs_config_read(struct config* config, struct fuse_args* args);
void fs_config_free_fields(struct config* config);
