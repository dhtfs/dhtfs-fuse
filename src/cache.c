#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <btrfsutil.h>
#include <glib.h>

#include "cache.h"
#include "utils.h"

#define CACHE_DIR_DATA "data"
#define CACHE_DIR_DATA_INODE "inode"
#define CACHE_DIR_SNAPSHOTS "snapshots"

GQuark cache_error_quark(void)
{
    return g_quark_from_static_string("cache-error-quark");
}

// Make sure the given path is a BTRFS subvolume, creating one if needed
static gboolean ensure_btrfs_subvolume(struct cache* cache, const char* path,
    GError** err)
{
    enum btrfs_util_error btrfs_err;

    btrfs_err = btrfs_util_is_subvolume(path);
    if (btrfs_err != BTRFS_UTIL_OK) {
        if (g_file_test(path, G_FILE_TEST_EXISTS)) {
            g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
                "%s already exists and is not a btrfs subvolume",
                path);
            return FALSE;
        }
        btrfs_err = btrfs_util_create_subvolume(path, 0, NULL, NULL);
        if (btrfs_err != BTRFS_UTIL_OK) {
            g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
                "failed to create btrfs subvolume %s: %s",
                path,
                btrfs_util_strerror(btrfs_err));
            return FALSE;
        }
    }
    if (chmod(path, 0777 & ~cache->umask) != 0) {
        g_set_error(err, CACHE_ERROR, CACHE_ERROR_CHMOD,
            "failed to change permissions of %s: %s",
            path,
            g_strerror(errno));
        return FALSE;
    }
    return TRUE;
}

// Open a directory and return the file descriptor
static int open_directory_fd(const gchar* dir, GError** err)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOATIME);
    if (fd == -1) {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
        errno = save_errno;
    }
    return fd;
}

static int open_directory_fd_at(int parent_fd, const gchar* name, GError** err)
{
    int fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOATIME);
    if (fd == -1) {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
        errno = save_errno;
    }
    return fd;
}

// Initialize file descriptors for the data folder
static gboolean initialize_data(struct cache* cache, GError** err)
{
    // Prepare a folder for storing big inodes
    if (mkdirat(cache->fd_data, CACHE_DIR_DATA_INODE, 0777 & ~cache->umask) != 0) {
        if (errno != EEXIST) {
            int save_errno = errno;
            g_set_error_literal(err,
                G_FILE_ERROR,
                g_file_error_from_errno(save_errno),
                g_strerror(save_errno));
            return FALSE;
        }
    }
    if (cache->fd_data_inode > 0)
        close(cache->fd_data_inode);

    cache->fd_data_inode = open_directory_fd_at(cache->fd_data,
        CACHE_DIR_DATA_INODE, err);
    if (cache->fd_data_inode == -1)
        return FALSE;

    return TRUE;
}

// Create required BTRFS subvolumes, directories and fill internal data structures
static gboolean initialize_cache(struct cache* cache, GError** err)
{
    // Create subvolumes
    if (!ensure_btrfs_subvolume(cache, cache->volume, err))
        return FALSE;
    if (!ensure_btrfs_subvolume(cache, cache->volume_data, err))
        return FALSE;
    if (!ensure_btrfs_subvolume(cache, cache->volume_snapshots, err))
        return FALSE;

    // Maintain an open file descriptor to the data folder
    cache->fd_data = open_directory_fd(cache->volume_data, err);
    if (cache->fd_data == -1)
        return FALSE;
    if (!initialize_data(cache, err))
        return FALSE;

    // Retrieve information about the local storage
    int ret = ioctl(cache->fd_data, BTRFS_IOC_FS_INFO, &cache->fs_info);
    if (ret == -1) {
        g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
            "ioctl failed: %s", g_strerror(errno));
        return FALSE;
    }
    // Maintain an open file descriptor to the snapshot folder
    cache->fd_snapshots = open_directory_fd(cache->volume_snapshots, err);
    if (cache->fd_snapshots == -1)
        return FALSE;

    if (statfs(cache->volume, &cache->statfs) == -1)
        g_warning("Failed to statfs() cache storage: %s", g_strerror(errno));

    return TRUE;
}

// Create a new cache structure and return it
struct cache* fs_cache_new(const gchar* volume, int umask, GError** err)
{
    g_return_val_if_fail(volume != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    struct cache* cache;

    cache = g_slice_new0(struct cache);
    cache->umask = umask;
    cache->volume = g_strdup(volume);
    cache->volume_data = g_build_filename(volume, CACHE_DIR_DATA, NULL);
    cache->volume_snapshots = g_build_filename(volume, CACHE_DIR_SNAPSHOTS, NULL);
    g_atomic_ref_count_init(&cache->ref_count);

    if (!initialize_cache(cache, err)) {
        fs_cache_unref(cache);
        return NULL;
    }
    return cache;
}

// Atomically increase reference count
struct cache* fs_cache_ref(struct cache* cache)
{
    g_return_val_if_fail(cache != NULL, NULL);

    g_atomic_ref_count_inc(&cache->ref_count);

    return cache;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_cache_unref(struct cache* cache)
{
    g_return_if_fail(cache != NULL);

    if (g_atomic_ref_count_dec(&cache->ref_count)) {
        if (cache->fd_data > 0)
            close(cache->fd_data);
        if (cache->fd_data_inode > 0)
            close(cache->fd_data_inode);
        if (cache->fd_snapshots > 0)
            close(cache->fd_snapshots);
        g_free(cache->volume);
        g_free(cache->volume_data);
        g_free(cache->volume_snapshots);

        g_slice_free(struct cache, cache);
    }
}

// Create a snapshot given a file descriptor of the source volume
static gboolean create_snapshot_fd(struct cache* cache, int fd, int64_t dst_ident,
    GError** err)
{
    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", dst_ident);

    enum btrfs_util_error btrfs_err;
    btrfs_err = btrfs_util_create_snapshot_fd2(fd,
        cache->fd_snapshots, name,
        0, NULL, NULL);
    if (btrfs_err != BTRFS_UTIL_OK) {
        g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
            "%s",
            btrfs_util_strerror(btrfs_err));
        return FALSE;
    }
    return TRUE;
}

// Create a snapshot of the data subvolume
gboolean fs_cache_create_snapshot_data(struct cache* cache, int64_t dst_ident,
    GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    g_debug("Creating snapshot current -> %ld", dst_ident);

    gboolean ret = create_snapshot_fd(cache, cache->fd_data, dst_ident, err);
    if (ret)
        cache->last_data_snapshot = fs_current_time();
    return ret;
}

// Create a snapshot of an existing snapshot
gboolean fs_cache_create_snapshot_ident(struct cache* cache, int64_t src_ident,
    int64_t dst_ident, GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    g_debug("Creating snapshot %ld -> %ld", src_ident, dst_ident);

    gchar src_name[32];
    g_snprintf(src_name, sizeof(src_name), "%ld", src_ident);

    int fd = open_directory_fd_at(cache->fd_snapshots, src_name, err);
    if (fd >= 0) {
        gboolean ret = create_snapshot_fd(cache, fd, dst_ident, err);
        close(fd);
        return ret;
    }
    return FALSE;
}

// Create an empty subvolume to store a network snapshot
gboolean fs_cache_create_subvolume_ident(struct cache* cache, int64_t ident,
    GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    g_debug("Creating subvolume %ld", ident);

    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", ident);

    enum btrfs_util_error btrfs_err;
    btrfs_err = btrfs_util_create_subvolume_fd(cache->fd_snapshots,
        name, 0, NULL, NULL);
    if (btrfs_err != BTRFS_UTIL_OK) {
        g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
            "%s",
            btrfs_util_strerror(btrfs_err));
        return FALSE;
    }
    return TRUE;
}

// Delete a snapshot of the data subvolume
gboolean fs_cache_delete_snapshot(struct cache* cache, int64_t ident, GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    g_debug("Deleting snapshot %ld", ident);

    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", ident);
    enum btrfs_util_error btrfs_err;
    // This needs the user_subvol_rm_allowed option on the mount
    btrfs_err = btrfs_util_delete_subvolume_fd(cache->fd_snapshots, name, 0);
    if (btrfs_err != BTRFS_UTIL_OK) {
        g_set_error(err, CACHE_ERROR, CACHE_ERROR_BTRFS,
            "%s",
            btrfs_util_strerror(btrfs_err));
        return FALSE;
    }
    return TRUE;
}

// Find the closest snapshot after the given identifier and return the identifier
// of the found snapshot, or -1 if nothing has been found
int64_t fs_cache_find_closest_snapshot(struct cache* cache, int64_t ident, GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    int64_t closest = -1;

    // File descriptor is no longer usable after fdopendir()
    int newfd = dup(cache->fd_snapshots);
    DIR* dir = fdopendir(newfd);
    if (dir != NULL) {
        struct dirent* dent;
        while ((dent = readdir(dir)) != NULL) {
            if (dent->d_name[0] == '.')
                continue;
            int64_t dent_id = atol(dent->d_name);
            if (dent_id >= ident) {
                if (closest == -1)
                    closest = dent_id;
                else
                    closest = MIN(closest, dent_id);
            }
        }
        closedir(dir);
    } else {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
        errno = save_errno;
    }
    g_debug("Closest snapshot lookup %ld -> %ld", ident, closest);

    return closest;
}

// Set the data folder to point to the given snapshot
gboolean fs_cache_set_data_snapshot(struct cache* cache, int64_t ident, GError** err)
{
    g_return_val_if_fail(cache != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    g_debug("Setting data snapshot %ld", ident);

    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", ident);
    int fd_data = open_directory_fd_at(cache->fd_snapshots, name, err);
    if (fd_data == -1)
        return FALSE;

    int old_fd_data = cache->fd_data;
    int old_fd_data_inode = cache->fd_data_inode;
    // Replace the previous file descriptor
    cache->fd_data = fd_data;
    if (!initialize_data(cache, err)) {
        // Restore the original file descriptors
        close(fd_data);
        cache->fd_data = old_fd_data;
        cache->fd_data_inode = old_fd_data_inode;
        return FALSE;
    }
    // The original big inode descriptor was replaced in initialize_data, but
    // we replaced the data descriptor ourselves
    if (old_fd_data > 0)
        close(old_fd_data);

    return TRUE;
}

static int open_file_at(struct cache* cache, int dirfd, int64_t inumber,
    int flags, GError** err)
{
    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", inumber);
    int fd = openat(dirfd, name, flags | CACHE_FD_FLAGS, 0666 & ~cache->umask);
    if (fd == -1 && err != NULL) {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
        errno = save_errno;
    }
    return fd;
}

// Open a file on the caching storage and return the file descriptor
int fs_cache_open_file(struct cache* cache, int64_t inumber, int flags, GError** err)
{
    g_return_val_if_fail(cache != NULL, -1);
    g_return_val_if_fail(err == NULL || *err == NULL, -1);

    return open_file_at(cache, cache->fd_data, inumber, flags, err);
}

// Open an inode file on the caching storage and return the file descriptor
int fs_cache_open_inode_file(struct cache* cache, int64_t inumber, int flags,
    GError** err)
{
    g_return_val_if_fail(cache != NULL, -1);
    g_return_val_if_fail(err == NULL || *err == NULL, -1);

    return open_file_at(cache, cache->fd_data_inode, inumber, flags, err);
}

static void unlink_file_at(struct cache* cache, int dirfd, int64_t inumber)
{
    gchar name[32];
    g_snprintf(name, sizeof(name), "%ld", inumber);
    unlinkat(dirfd, name, 0);
}

// Remove a file on the caching storage
void fs_cache_unlink_file(struct cache* cache, int64_t inumber)
{
    g_return_if_fail(cache != NULL);

    unlink_file_at(cache, cache->fd_data, inumber);
}

// Remove an inode file on the caching storage
void fs_cache_unlink_inode_file(struct cache* cache, int64_t inumber)
{
    g_return_if_fail(cache != NULL);

    unlink_file_at(cache, cache->fd_data_inode, inumber);
}

// Store the given block in the given file and return the number of bytes written
int fs_cache_store_bytes(int fd, GByteArray* bytes, off_t offset, GError** err)
{
    size_t written = 0;
    while (written < bytes->len) {
        ssize_t ret = pwrite(fd,
            bytes->data + written,
            bytes->len - written, offset);
        if (ret == -1) {
            int save_errno = errno;
            g_set_error_literal(err,
                G_FILE_ERROR,
                g_file_error_from_errno(save_errno),
                g_strerror(save_errno));
            errno = save_errno;
            break;
        }
        written += ret;
    }
    return written;
}
