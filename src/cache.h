#pragma once

#include <sys/statfs.h>

#include <linux/btrfs.h>

#include <glib.h>

// We don't use access time for performance reasons and as we don't have
// control over how the caching file system is mounted, include O_NOATIME
// on every open to reduce disk I/O pointlessly updaing access time on
// every read
#define CACHE_FD_FLAGS O_NOATIME

struct cache {
    struct btrfs_ioctl_fs_info_args fs_info;
    struct statfs statfs;
    char* volume;
    char* volume_data;
    char* volume_snapshots;
    time_t last_data_snapshot;

    // Private fields
    int fd_data;
    int fd_data_inode;
    int fd_snapshots;
    int umask;
    gatomicrefcount ref_count;
};

// Custom error type
#define CACHE_ERROR cache_error_quark()
enum {
    CACHE_ERROR_BTRFS,
    CACHE_ERROR_CHMOD
};

struct cache* fs_cache_new(const gchar* volume, int umask, GError** err);
struct cache* fs_cache_ref(struct cache* cache);
void fs_cache_unref(struct cache* cache);

gboolean fs_cache_create_snapshot_data(struct cache* cache, int64_t dst_ident,
    GError** err);
gboolean fs_cache_create_snapshot_ident(struct cache* cache, int64_t src_ident,
    int64_t dst_ident, GError** err);
gboolean fs_cache_create_subvolume_ident(struct cache* cache, int64_t ident,
    GError** err);

gboolean fs_cache_delete_snapshot(struct cache* cache, int64_t ident, GError** err);

int64_t fs_cache_find_closest_snapshot(struct cache* cache, int64_t ident,
    GError** err);

gboolean fs_cache_set_data_snapshot(struct cache* cache, int64_t ident, GError** err);

int fs_cache_open_file(struct cache* cache, int64_t inumber, int flags, GError** err);
int fs_cache_open_inode_file(struct cache* cache, int64_t inumber, int flags,
    GError** err);

void fs_cache_unlink_file(struct cache* cache, int64_t inumber);
void fs_cache_unlink_inode_file(struct cache* cache, int64_t inumber);

int fs_cache_store_bytes(int fd, GByteArray* bytes, off_t offset, GError** err);
