#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#define FUSE_USE_VERSION 26
#include <fuse/fuse_lowlevel.h>
#include <fuse/fuse_opt.h>

#include "config.h"
#include "dht-utils.h"
#include "dht.h"
#include "dhtfs.h"
#include "metadata.h"
#include "utils.h"

#define TRACE_OPER(fmt, ...) g_debug("OP: " fmt, __VA_ARGS__)

#define FS_NAME "dhtfs"

struct handle {
    struct metadata_item* mi;
    int fd;
    int flags;
};
// clang-format off
#define ACC_MODE(flags) ((flags) & O_ACCMODE)
#define ACC_MODE_HAS_WRITE(flags) (ACC_MODE(flags) == O_WRONLY || \
                                   ACC_MODE(flags) == O_RDWR)
// clang-format on

// Retrieve the dhtfs* from the current request
static inline struct dhtfs* dhtfs(fuse_req_t req)
{
    return (struct dhtfs*)fuse_req_userdata(req);
}

// Initialize the local caching storage, ensuring that it is a valid
// btrfs subvolume.
//
// Populates fs->cache.
static int setup_local_storage(struct dhtfs* fs)
{
    // Figure out the caching storage path and create a subvolume based on
    // the hash of the file system name
    gchar* name_hash = g_compute_checksum_for_string(
        G_CHECKSUM_SHA1,
        fs->config.fs_name, -1);
    gchar name_component[MAXPATHLEN];
    g_snprintf(name_component, sizeof(name_component), FS_NAME "-%s", name_hash);
    g_free(name_hash);

    gchar* cache_volume;
    if (fs->config.cache_path != NULL) {
        gchar* cache_path = g_canonicalize_filename(fs->config.cache_path, NULL);
        cache_volume = g_build_filename(cache_path,
            name_component, NULL);
        g_free(cache_path);
    } else
        cache_volume = g_build_filename(g_get_user_cache_dir(),
            FS_NAME,
            name_component, NULL);

    gchar* dirpath = g_path_get_dirname(cache_volume);
    if (g_mkdir_with_parents(dirpath, 0777 & ~fs->config.umask_cache) != 0) {
        fprintf(stderr, "fuse: failed to create directory `%s': %s\n",
            dirpath,
            g_strerror(errno));
        g_free(dirpath);
        g_free(cache_volume);
        return -1;
    }
    g_free(dirpath);
    g_debug("Using cache subvolume path: %s", cache_volume);

    GError* err = NULL;
    fs->cache = fs_cache_new(cache_volume, fs->config.umask_cache, &err);
    g_free(cache_volume);
    if (fs->cache == NULL) {
        // This can fail e.g. if the subvolume cannot be created or the
        // directory is not accessible
        fprintf(stderr, "fuse: %s\n", err->message);
        g_error_free(err);
        return -1;
    }
    return 0;
}

// Make the local storage point to a snapshot at the chosen time instead of the
// current version of the file system
static int setup_snapshot_storage(struct dhtfs* fs, int64_t snap_time)
{
    GError* err = NULL;
    gboolean local_snapshot = FALSE;

    // Try to use the closest later snapshot as caching storage
    int64_t closest = fs_cache_find_closest_snapshot(fs->cache, snap_time, NULL);
    if (closest != -1) {
        gboolean ret = TRUE;
        if (closest != snap_time) {
            // Create a new snapshot of the closest one as it is not exactly
            // at the requested time
            ret = fs_cache_create_snapshot_ident(fs->cache, closest,
                snap_time, &err);
            if (!ret) {
                g_warning("Failed to create snapshot %ld -> %ld: %s", closest,
                    snap_time, err->message);
                g_error_free(err);
                err = NULL;
            }
        }
        if (ret) {
            if (fs_cache_set_data_snapshot(fs->cache, snap_time, &err))
                local_snapshot = TRUE;
            else {
                g_warning("Failed to use local snapshot %ld: %s", snap_time,
                    err->message);
                g_error_free(err);
                err = NULL;
            }
        }
    }
    if (!local_snapshot) {
        // There is no snapshot we could use, create an empty subvolume
        if (fs_cache_create_subvolume_ident(fs->cache, snap_time, &err)
            && fs_cache_set_data_snapshot(fs->cache, snap_time, &err))
            g_debug("Using empty subvolume for snapshot at time %ld", snap_time);
        else {
            fprintf(stderr, "fuse: failed to create snapshot subvolume %ld: %s\n",
                snap_time, err->message);
            g_error_free(err);
            return -1;
        }
    }
    return 0;
}

// Initialize DHT and metadata structures based on file system configuration
// retrieved from the DHT.
//
// Populates fs->dht and fs->meta.
static int setup_dht_and_metadata(struct dhtfs* fs)
{
    g_debug("Using DHT peer: %s:%d",
        fs->config.dht_host,
        fs->config.dht_port);

    fs->dht = fs_dht_new(fs->config.dht_host, fs->config.dht_port);

    // Retrieve the file system configuration
    GError* err = NULL;
    ThriftFileSystem* fs_desc = fs_dht_get_fs_description(
        fs->dht,
        fs->config.fs_name, &err);
    if (fs_desc == NULL) {
        if (err != NULL) {
            fprintf(stderr, "fuse: file system description: %s\n", err->message);
            g_error_free(err);
        } else {
            // Error is not set and NULL is returned when the item
            // is not in the DHT
            fprintf(stderr, "fuse: file system `%s' not found in DHT\n",
                fs->config.fs_name);
        }
        fs_dht_unref(fs->dht);
        return -1;
    }
    int64_t range_delta = 0;
    if (fs_desc->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT) {
        if (fs->config.snap_period == 0) {
            fprintf(stderr,
                "fuse: snapshot model requires specifying snapshot period\n");
            g_object_unref(fs_desc);
            fs_dht_unref(fs->dht);
            return -1;
        }
        range_delta = fs->config.snap_period * CONFIG_INDEX_SECS_MULTIPLIER;
    }
    fs->inception = fs_desc->inception;
    g_debug("Inception time: %ld; Current time: %ld", fs->inception, fs_current_time());
    // If snapshot time is given, we want to mount a read-only version at
    // the specified time, relative to the file system creation
    int64_t snap_time = -1;
    if (fs->config.snap_time > 0) {
        snap_time = MAX(0, (ssize_t)(fs->config.snap_time - fs->inception));

        g_debug("Requested snapshot time: %ld", snap_time);

        // Pick or create a snapshot to cache to
        if (setup_snapshot_storage(fs, snap_time) != 0) {
            g_object_unref(fs_desc);
            fs_dht_unref(fs->dht);
            return -1;
        }
        fs->read_only = TRUE;
    }
    fs->meta = fs_metadata_new(fs->cache, fs->dht, fs_desc, fs->config.umask,
        snap_time, range_delta);
    // Retrieve the root inode
    if (!fs_metadata_initialize(fs->meta, fs_desc->root, &err)) {
        if (err != NULL) {
            fprintf(stderr, "fuse: root inode: %s\n", err->message);
            g_error_free(err);
        } else
            fprintf(stderr, "fuse: root inode of file system `%s' not found in DHT\n",
                fs->config.fs_name);
        g_object_unref(fs_desc);
        fs_metadata_unref(fs->meta);
        fs_dht_unref(fs->dht);
        return -1;
    }
    g_object_unref(fs_desc);
    return 0;
}

static GRWLock snapshot_lock;

#define LOCK_SNAP_WRITING() g_rw_lock_reader_lock(&snapshot_lock)
#define UNLOCK_SNAP_WRITING() g_rw_lock_reader_unlock(&snapshot_lock)
#define LOCK_SNAP_SNAPSHOTTING() g_rw_lock_writer_lock(&snapshot_lock)
#define UNLOCK_SNAP_SNAPSHOTTING() g_rw_lock_writer_unlock(&snapshot_lock)

// Create a snapshot of the data subvolume for the current time
static gboolean create_snapshot(gpointer data)
{
    struct dhtfs* fs = data;

    GError* err = NULL;
    int64_t ident = fs_current_time() - fs->inception;
    LOCK_SNAP_SNAPSHOTTING();
    if (!fs_cache_create_snapshot_data(fs->cache, ident, &err)) {
        g_warning("Failed to create snapshot %ld: %s", ident, err->message);
        g_error_free(err);
    }
    UNLOCK_SNAP_SNAPSHOTTING();
    if (fs->meta->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT)
        fs_metadata_finalize_flush(fs->meta);

    return TRUE;
}

//
// FUSE operations; descriptions have been taken from fuse/fuse_lowlevel.h:
//

/**
 * Initialize filesystem
 *
 * Called before any other filesystem method
 *
 * There's no reply to this function
 *
 * @param userdata the user data passed to fuse_lowlevel_new()
 */
void oper_init(void* userdata, struct fuse_conn_info* conn)
{
    struct dhtfs* fs = (struct dhtfs*)userdata;

    if (fs->config.snap_period > 0) {
        if (!fs->read_only) {
            // Enable periodic snapshotting
            fs->loop = fs_event_loop_new();
            fs_event_loop_add_timer(
                fs->loop,
                create_snapshot,
                fs->config.snap_period * 1000, fs);
        } else
            fprintf(stderr,
                "fuse: disabling periodic snapshotting on read-only file system\n");
    }
    conn->want |= FUSE_CAP_ASYNC_READ | FUSE_CAP_ATOMIC_O_TRUNC | FUSE_CAP_BIG_WRITES;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit
 *
 * There's no reply to this function
 *
 * @param userdata the user data passed to fuse_lowlevel_new()
 */
void oper_destroy(void* userdata)
{
    struct dhtfs* fs = (struct dhtfs*)userdata;

    if (fs->meta->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT)
        fs_metadata_finalize_flush(fs->meta);

#ifdef BENCHMARK
    g_print("BENCHMARK/DHT/Time/Add %lu\n",
        fs->dht->benchmark.t_add);
    g_print("BENCHMARK/DHT/Time/Get %lu\n",
        fs->dht->benchmark.t_get);
    g_print("BENCHMARK/DHT/Time/GetLatestMax %lu\n",
        fs->dht->benchmark.t_get_latest_max);
    g_print("BENCHMARK/DHT/Time/GetRange %lu\n",
        fs->dht->benchmark.t_get_range);
    g_print("BENCHMARK/DHT/Time/Put %lu\n",
        fs->dht->benchmark.t_put);
    g_print("BENCHMARK/DHT/Time/Total %lu\n",
        fs->dht->benchmark.t_total);
    g_print("BENCHMARK/DHT/Count/Add %lu\n",
        fs->dht->benchmark.c_add);
    g_print("BENCHMARK/DHT/Count/Get %lu\n",
        fs->dht->benchmark.c_get);
    g_print("BENCHMARK/DHT/Count/GetLatestMax %lu\n",
        fs->dht->benchmark.c_get_latest_max);
    g_print("BENCHMARK/DHT/Count/GetRange %lu\n",
        fs->dht->benchmark.c_get_range);
    g_print("BENCHMARK/DHT/Count/Put %lu\n",
        fs->dht->benchmark.c_put);
    g_print("BENCHMARK/DHT/Count/Total %lu\n",
        fs->dht->benchmark.c_total);
#endif
    if (fs->loop != NULL)
        fs_event_loop_unref(fs->loop);

    fs_dht_unref(fs->dht);
    fs_cache_unref(fs->cache);
    fs_metadata_unref(fs->meta);
}

// Fill a fuse_entry_param structure
static void create_fuse_entry_param(struct fuse_entry_param* e,
    struct metadata_item* mi, double timeout)
{
    memset(e, 0, sizeof(*e));

    METADATA_ITEM_LOCK_LOCAL(mi);
    e->attr = mi->local.st;
    METADATA_ITEM_UNLOCK_LOCAL(mi);
    e->ino = e->attr.st_ino;
    e->attr_timeout = timeout;
    e->entry_timeout = timeout;
}

// Fill a fuse_entry_param for the case where we don't have an inode, this
// works the same as returning ENOENT error, but allows the kernel to cache
// the result for the given time
static void create_fuse_entry_param_empty(struct fuse_entry_param* e, double timeout)
{
    memset(e, 0, sizeof(*e));
    e->ino = 0;
    e->attr_timeout = timeout;
    e->entry_timeout = timeout;
}

enum refresh_result {
    REFRESH_OK,
    REFRESH_ERR,
    REFRESH_NOT_FOUND
};

// Refresh an inode
static inline enum refresh_result refresh_inode(struct metadata_item* mi,
    gboolean full_dir_refresh)
{
    GError* err = NULL;
    if (!fs_metadata_item_refresh_inode(mi, full_dir_refresh, &err)) {
        if (err == NULL)
            return REFRESH_NOT_FOUND;
        g_warning("Failed to refresh inode %ld: %s", mi->inumber, err->message);
        g_error_free(err);
        return REFRESH_ERR;
    }
    return REFRESH_OK;
}

// Refresh an inode and satisfy FUSE request in case of error or missing inode
static inline gboolean refresh_inode_for_req(struct metadata_item* mi,
    gboolean full_dir_refresh, fuse_req_t req)
{
    enum refresh_result result = refresh_inode(mi, full_dir_refresh);
    if (result == REFRESH_ERR) {
        // TODO: consider using cached inode? It seems there's not much more
        // we can do and maybe this is a bit strict
        fuse_reply_err(req, EIO);
        return FALSE;
    }
    if (result == REFRESH_NOT_FOUND) {
        // The inode might have disappeared from the DHT, just emit a warning
        // and use a cached inode if we have one
        METADATA_ITEM_LOCK_INODE(mi);
        gboolean have_inode = mi->inode != NULL;
        METADATA_ITEM_UNLOCK_INODE(mi);
        if (!have_inode) {
            fuse_reply_err(req, ENOENT);
            return FALSE;
        }
        g_warning("Inode %ld only exists in cache", mi->inumber);
    }
    return TRUE;
}

/**
 * Look up a directory entry by name and get its attributes.
 *
 * Valid replies:
 *   fuse_reply_entry
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name the name to look up
 */
static void oper_lookup(fuse_req_t req, fuse_ino_t parent_ino, const char* name)
{
    TRACE_OPER("lookup(%ld, %s)", parent_ino, name);

    struct dhtfs* fs = dhtfs(req);
    // Get the latest version of the parent inode and search for the
    // given name in it
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    if (!refresh_inode_for_req(parent, TRUE, req))
        return;
    struct metadata_item* mi = fs_metadata_item_lookup(parent, name);
    if (mi == NULL) {
        struct fuse_entry_param e;
        create_fuse_entry_param_empty(&e, fs->config.no_inode_timeout);
        fuse_reply_entry(req, &e);
        return;
    }
    // Get the latest version of the looked-up inode, we only need the attributes
    // now and not being sure about it's folder content is not a problem
    if (!refresh_inode_for_req(mi, FALSE, req))
        return;
    // fuse_reply_entry() adds a FUSE reference
    fs_metadata_item_fuse_ref(mi);

    struct fuse_entry_param e;
    create_fuse_entry_param(&e, mi, fs->config.attr_timeout);
    fuse_reply_entry(req, &e);
}

// Forget about a single inode
static void forget_inode(struct dhtfs* fs, fuse_ino_t ino, unsigned long nlookup)
{
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);

    fs_metadata_item_fuse_unref(mi, nlookup);
}

/**
 * Forget about an inode
 *
 * This function is called when the kernel removes an inode
 * from its internal caches.
 *
 * The inode's lookup count increases by one for every call to
 * fuse_reply_entry and fuse_reply_create. The nlookup parameter
 * indicates by how much the lookup count should be decreased.
 *
 * Inodes with a non-zero lookup count may receive request from
 * the kernel even after calls to unlink, rmdir or (when
 * overwriting an existing file) rename. Filesystems must handle
 * such requests properly and it is recommended to defer removal
 * of the inode until the lookup count reaches zero. Calls to
 * unlink, remdir or rename will be followed closely by forget
 * unless the file or directory is open, in which case the
 * kernel issues forget only after the release or releasedir
 * calls.
 *
 * Note that if a file system will be exported over NFS the
 * inodes lifetime must extend even beyond forget. See the
 * generation field in struct fuse_entry_param above.
 *
 * On unmount the lookup count for all inodes implicitly drops
 * to zero. It is not guaranteed that the file system will
 * receive corresponding forget messages for the affected
 * inodes.
 *
 * Valid replies:
 *   fuse_reply_none
 *
 * @param req request handle
 * @param ino the inode number
 * @param nlookup the number of lookups to forget
 */
static void oper_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    TRACE_OPER("forget(%ld, %lu)", ino, nlookup);

    forget_inode(dhtfs(req), ino, nlookup);

    fuse_reply_none(req);
}

/**
 * Get file attributes
 *
 * Valid replies:
 *   fuse_reply_attr
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param fi for future use, currently always NULL
 */
static void oper_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    TRACE_OPER("getattr(%ld)", ino);

    struct dhtfs* fs = dhtfs(req);
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
    if (!refresh_inode_for_req(mi, FALSE, req))
        return;

    METADATA_ITEM_LOCK_LOCAL(mi);
    fuse_reply_attr(req, &mi->local.st, fs->config.attr_timeout);
    METADATA_ITEM_UNLOCK_LOCAL(mi);
}

/**
 * Set file attributes
 *
 * In the 'attr' argument only members indicated by the 'to_set'
 * bitmask contain valid values.  Other members contain undefined
 * values.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits if the file
 * size or owner is being changed.
 *
 * If the setattr was invoked from the ftruncate() system call
 * under Linux kernel versions 2.6.15 or later, the fi->fh will
 * contain the value set by the open method or will be undefined
 * if the open method didn't set any value.  Otherwise (not
 * ftruncate call, or kernel version earlier than 2.6.15) the fi
 * parameter will be NULL.
 *
 * Valid replies:
 *   fuse_reply_attr
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param attr the attributes
 * @param to_set bit mask of attributes which should be set
 * @param fi file information, or NULL
 */
static void oper_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
    int to_set, struct fuse_file_info* fi)
{
    TRACE_OPER("setattr(%ld, <attr>, 0x%x)", ino, to_set);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
    if (!refresh_inode_for_req(mi, FALSE, req))
        return;

    // We only support a limited range of operations
    if (to_set & (FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_MTIME_NOW)) {
        GError* err = NULL;
        gboolean updated = FALSE;
        if (to_set & FUSE_SET_ATTR_SIZE) {
            // Handle setting the size first as this is the operation which
            // may fail with an error
            int fd = -1;
            if (fi != NULL) {
                struct handle* handle = (struct handle*)fi->fh;
                fd = handle->fd;
            }
            updated = fs_metadata_item_update_size(mi, attr->st_size, fd, &err);
            if (err != NULL) {
                g_warning("Failed to set size of inode %ld to %lu: %s", mi->inumber,
                    attr->st_size, err->message);
                g_error_free(err);
                fuse_reply_err(req, EIO);
                return;
            }
            // Updated will be false if the file size remained the same, which
            // is not an error
        }
        if (to_set & FUSE_SET_ATTR_MODE)
            updated = fs_metadata_item_update_mode(mi, attr->st_mode)
                || updated;
        if (to_set & FUSE_SET_ATTR_MTIME_NOW)
            updated = fs_metadata_item_update_mtime_now(mi)
                || updated;
        if (updated && !fs_metadata_item_update_finalize(mi, &err)) {
            g_warning("Failed to finalize inode %ld: %s", mi->inumber,
                err->message);
            g_error_free(err);
            fuse_reply_err(req, EIO);
            return;
        }
        // Report success if we have performed an operation which we support
        // even if it hasn't changed the inode
        METADATA_ITEM_LOCK_LOCAL(mi);
        fuse_reply_attr(req, &mi->local.st, fs->config.attr_timeout);
        METADATA_ITEM_UNLOCK_LOCAL(mi);
    } else
        fuse_reply_err(req, ENOTSUP);
}

/**
 * Read symbolic link
 *
 * Valid replies:
 *   fuse_reply_readlink
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 */
static void oper_readlink(fuse_req_t req, fuse_ino_t ino)
{
    TRACE_OPER("readlink(%ld)", ino);

    struct dhtfs* fs = dhtfs(req);
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
    METADATA_ITEM_LOCK_INODE(mi);
    // Symlink target is fixed once it's created, therefore we don't need to
    // refresh the inode if we already have it
    gboolean has_inode = mi->inode != NULL;
    if (!has_inode) {
        METADATA_ITEM_UNLOCK_INODE(mi);
        if (!refresh_inode_for_req(mi, FALSE, req))
            return;
        METADATA_ITEM_LOCK_INODE(mi);
    }
    if (mi->inode->type == THRIFT_INODE_TYPE_SYMLINK)
        fuse_reply_readlink(req, mi->inode->symlink_data->target);
    else
        fuse_reply_err(req, EINVAL);

    METADATA_ITEM_UNLOCK_INODE(mi);
}

// Add an entry to a directory and satisfy FUSE request if there is an error
static gboolean add_inode_link_for_req(struct metadata_item* parent,
    struct metadata_item* mi, const gchar* name, fuse_req_t req)
{
    if (!fs_metadata_item_update_add_link(parent, mi, name)) {
        fuse_reply_err(req, errno);
        return FALSE;
    }
    GError* err = NULL;
    if (fs_metadata_item_update_finalize(mi, &err)) {
        if (fs_metadata_item_update_finalize(parent, &err))
            return TRUE;
        g_warning("Failed to add directory item '%s' to inode %ld: %s",
            name, parent->inumber, err->message);
    } else
        g_warning("Failed to store inode %ld: %s", mi->inumber, err->message);

    fuse_reply_err(req, EIO);
    return FALSE;
}

// Add an entry to a directory and satisfy FUSE entry or error request
static void add_inode_link_for_entry_req(struct metadata_item* parent,
    struct metadata_item* mi, const gchar* name, fuse_req_t req)
{
    if (!add_inode_link_for_req(parent, mi, name, req))
        return;

    struct dhtfs* fs = dhtfs(req);

    // fuse_reply_entry() adds a FUSE reference
    fs_metadata_item_fuse_ref(mi);
    struct fuse_entry_param e;
    create_fuse_entry_param(&e, mi, fs->config.attr_timeout);
    fuse_reply_entry(req, &e);
}

/**
 * Create file node
 *
 * Create a regular file, character device, block device, fifo or
 * socket node.
 *
 * Valid replies:
 *   fuse_reply_entry
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name to create
 * @param mode file type and mode with which to create the new file
 * @param rdev the device number (only valid if created file is a device)
 */
static void oper_mknod(fuse_req_t req, fuse_ino_t parent_ino, const char* name,
    mode_t mode, dev_t rdev)
{
    TRACE_OPER("mknod(%ld, %s, %#o)", parent_ino, name, mode);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    if (!S_ISREG(mode)) {
        fuse_reply_err(req, ENOTSUP);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }

    // Create an item and add it to the directory
    struct metadata_item* mi = fs_metadata_item_new(fs->meta, mode);
    add_inode_link_for_entry_req(parent, mi, name, req);
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);

    fs_metadata_item_unref(mi);
}

/**
 * Create a directory
 *
 * Valid replies:
 *   fuse_reply_entry
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name to create
 * @param mode with which to create the new file
 */
static void oper_mkdir(fuse_req_t req, fuse_ino_t parent_ino, const char* name,
    mode_t mode)
{
    TRACE_OPER("mkdir(%ld, %s, %#o)", parent_ino, name, mode);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);

    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    // Create an item for the new directory; this also adds the item to
    // the global inode table
    struct metadata_item* mi = fs_metadata_item_new(fs->meta, S_IFDIR | S_IRWXU);
    add_inode_link_for_entry_req(parent, mi, name, req);
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);

    fs_metadata_item_unref(mi);
}

// Unlink an entry from the containing directory and satisfy a FUSE request
static void remove_inode_link_for_req(struct metadata_item* parent,
    const gchar* name, fuse_req_t req)
{
    GError* err = NULL;
    if (!fs_metadata_item_update_remove_link(parent, name)) {
        fuse_reply_err(req, errno);
        return;
    }
    if (fs_metadata_item_update_finalize(parent, &err))
        fuse_reply_err(req, 0);
    else {
        g_warning("Failed to remove '%s' from inode %ld: %s", name,
            parent->inumber, err->message);
        g_error_free(err);
        fuse_reply_err(req, EIO);
    }
}

/**
 * Remove a file
 *
 * If the file's inode's lookup count is non-zero, the file
 * system is expected to postpone any removal of the inode
 * until the lookup count reaches zero (see description of the
 * forget function).
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name to remove
 */
static void oper_unlink(fuse_req_t req, fuse_ino_t parent_ino, const char* name)
{
    TRACE_OPER("unlink(%ld, %s)", parent_ino, name);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (refresh_inode_for_req(parent, TRUE, req))
        remove_inode_link_for_req(parent, name, req);

    METADATA_ITEM_UNLOCK_RW_WRITE(parent);
}

/**
 * Remove a directory
 *
 * If the directory's inode's lookup count is non-zero, the
 * file system is expected to postpone any removal of the
 * inode until the lookup count reaches zero (see description
 * of the forget function).
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name to remove
 */
static void oper_rmdir(fuse_req_t req, fuse_ino_t parent_ino, const char* name)
{
    TRACE_OPER("rmdir(%ld, %s)", parent_ino, name);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    // Make sure we have the latest inodes for both the directories
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    struct metadata_item* mi = fs_metadata_item_lookup(parent, name);
    if (mi == NULL) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!refresh_inode_for_req(mi, FALSE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    METADATA_ITEM_LOCK_INODE(mi);
    if (mi->inode->type != THRIFT_INODE_TYPE_DIRECTORY) {
        METADATA_ITEM_UNLOCK_INODE(mi);
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    if (mi->inode->directory_data->count > 0) {
        METADATA_ITEM_UNLOCK_INODE(mi);
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        fuse_reply_err(req, ENOTEMPTY);
        return;
    }
    remove_inode_link_for_req(parent, name, req);
    METADATA_ITEM_UNLOCK_INODE(mi);
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);
}

/**
 * Create a symbolic link
 *
 * Valid replies:
 *   fuse_reply_entry
 *   fuse_reply_err
 *
 * @param req request handle
 * @param link the contents of the symbolic link
 * @param parent inode number of the parent directory
 * @param name to create
 */
static void oper_symlink(fuse_req_t req, const char* link, fuse_ino_t parent_ino,
    const char* name)
{
    TRACE_OPER("symlink(%s, %ld, %s)", link, parent_ino, name);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    // Create an item for the new directory; this also adds the item to
    // the global inode table
    struct metadata_item* mi = fs_metadata_item_new_symlink(fs->meta, link);
    add_inode_link_for_entry_req(parent, mi, name, req);
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);

    fs_metadata_item_unref(mi);
}

/**
 * Rename a file
 *
 * If the target exists it should be atomically replaced. If
 * the target's inode's lookup count is non-zero, the file
 * system is expected to postpone any removal of the inode
 * until the lookup count reaches zero (see description of the
 * forget function).
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the old parent directory
 * @param name old name
 * @param newparent inode number of the new parent directory
 * @param newname new name
 */
static void oper_rename(fuse_req_t req, fuse_ino_t parent_ino, const char* name,
    fuse_ino_t newparent_ino, const char* newname)
{
    TRACE_OPER("rename(%ld, %s, %ld, %s)", parent_ino, name, newparent_ino, newname);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    if (parent_ino == newparent_ino && strcmp(name, newname) == 0) {
        // Moving on the file itself
        fuse_reply_err(req, 0);
        return;
    }
    // Make sure we have the latest inode for the parent directories
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    struct metadata_item* newparent;
    if (parent_ino == newparent_ino) {
        // Destination directory may be the same
        newparent = parent;
    } else {
        newparent = fs_metadata_get_item_from_fuse_ino(
            fs->meta, newparent_ino);
        METADATA_ITEM_LOCK_RW_WRITE(newparent);
        if (!refresh_inode_for_req(newparent, TRUE, req)) {
            METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
            METADATA_ITEM_UNLOCK_RW_WRITE(parent);
            return;
        }
    }
    if (fs_metadata_item_update_rename(parent, name, newparent, newname)) {
        GError* err = NULL;
        if (!fs_metadata_item_update_finalize(parent, &err)) {
            if (parent != newparent)
                METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
            METADATA_ITEM_UNLOCK_RW_WRITE(parent);
            g_warning("Failed to finalize inode %ld: %s", parent->inumber,
                err->message);
            g_error_free(err);
            fuse_reply_err(req, EIO);
            return;
        }
        if (parent != newparent) {
            if (!fs_metadata_item_update_finalize(newparent, &err)) {
                if (parent != newparent)
                    METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
                METADATA_ITEM_UNLOCK_RW_WRITE(parent);
                g_warning("Failed to finalize inode %ld: %s", newparent->inumber,
                    err->message);
                g_error_free(err);
                fuse_reply_err(req, EIO);
                return;
            }
        }
        fuse_reply_err(req, 0);
    } else
        fuse_reply_err(req, ENOENT);

    if (parent != newparent)
        METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);
}

/**
 * Create a hard link
 *
 * Valid replies:
 *   fuse_reply_entry
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the old inode number
 * @param newparent inode number of the new parent directory
 * @param newname new name to create
 */
static void oper_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent_ino,
    const char* newname)
{
    TRACE_OPER("link(%ld, %ld, %s)", ino, newparent_ino, newname);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* newparent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, newparent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(newparent);
    if (!refresh_inode_for_req(newparent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
        return;
    }

    // No need to refresh this inode as the parent will only store the type
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);

    add_inode_link_for_entry_req(newparent, mi, newname, req);
    METADATA_ITEM_UNLOCK_RW_WRITE(newparent);
}

// Open a file and return a handle, satisfy a FUSE request in case of error
static struct handle* open_file_for_req(struct metadata_item* mi, int open_flags,
    int effective_flags, fuse_req_t req)
{
    struct dhtfs* fs = dhtfs(req);

    GError* err = NULL;
    int fd = fs_cache_open_file(fs->cache, mi->inumber, open_flags, &err);
    if (fd == -1) {
        int save_errno = errno;
        g_warning("Failed to open cache file for inode %ld: %s",
            mi->inumber, err->message);
        g_error_free(err);
        fuse_reply_err(req, save_errno);
        return NULL;
    }
    struct handle* handle = g_slice_new(struct handle);
    handle->mi = mi;
    handle->fd = fd;
    handle->flags = effective_flags;
    if (ACC_MODE_HAS_WRITE(effective_flags)) {
        // Increment the number of writers; this has the effect of not allowing
        // further refreshes or finalization of this file until the number of
        // writers drops to zero.
        // It is not a problem if a different thread is refreshing at this moment.
        METADATA_ITEM_INC_USED(mi);
    } else
        METADATA_ITEM_INC_USED_READ_ONLY(mi);
    return handle;
}

/**
 * Open a file
 *
 * Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and
 * O_TRUNC) are available in fi->flags.
 *
 * Filesystem may store an arbitrary file handle (pointer, index,
 * etc) in fi->fh, and use this in other all other file operations
 * (read, write, flush, release, fsync).
 *
 * Filesystem may also implement stateless file I/O and not store
 * anything in fi->fh.
 *
 * There are also some flags (direct_io, keep_cache) which the
 * filesystem may set in fi, to change the way the file is opened.
 * See fuse_file_info structure in <fuse_common.h> for more details.
 *
 * Valid replies:
 *   fuse_reply_open
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param fi file information
 */
static void oper_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    TRACE_OPER("open(%ld, 0x%x)", ino, fi->flags);

    struct dhtfs* fs = dhtfs(req);

    // Error out immediately if the file system is read-only and the file is
    // being opened for writing
    if (fs->read_only && ACC_MODE_HAS_WRITE(fi->flags)) {
        fuse_reply_err(req, EROFS);
        return;
    }
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
    // Refresh the inode; this is a no-op if the file is already open for writing
    if (!refresh_inode_for_req(mi, FALSE, req))
        return;

    if (ACC_MODE_HAS_WRITE(fi->flags)) {
        // Wait in case the file is still being finalized, this will normally
        // be a no-op
        fs_metadata_item_update_finalize(mi, NULL);
    }
    // Always open the file for both reading and writing and ensure it gets created
    // as we may need to cache from/into it
    int open_flags = O_RDWR | O_CREAT | (fi->flags & ~O_ACCMODE);
    struct handle* handle = open_file_for_req(mi, open_flags, fi->flags, req);
    if (handle == NULL)
        return;

    if (ACC_MODE_HAS_WRITE(fi->flags)) {
        if (fi->flags & O_TRUNC)
            fs_metadata_item_update_size(mi, 0UL, handle->fd, NULL);
    }
    fi->fh = (uint64_t)handle;

    fuse_reply_open(req, fi);
}

struct cache_handle {
    struct metadata_item* mi;
    size_t blocks;
    GMutex block_fetch_lock;
    GCond block_fetch_cond;
    gboolean block_fetch_failed;
};

static void cache_block_simple_callback(struct metadata_item* mi, size_t block_idx,
    GByteArray* block, GError* err, gpointer user_data)
{
    struct cache_handle* handle = user_data;
    if (block == NULL) {
        if (err != NULL)
            g_warning("Failed to fetch block of inode %ld: %s",
                handle->mi->inumber, err->message);
        else
            g_warning("Failed to find block of inode %ld",
                handle->mi->inumber);

        handle->block_fetch_failed = TRUE;
    }
    g_mutex_lock(&handle->block_fetch_lock);
    handle->blocks--;
    if (handle->blocks == 0) {
        // Tell the reading thread that we are done downloading
        g_cond_signal(&handle->block_fetch_cond);
    }
    g_mutex_unlock(&handle->block_fetch_lock);
}

/**
 * Read data
 *
 * Read should send exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the file
 * has been opened in 'direct_io' mode, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * fi->fh will contain the value set by the open method, or will
 * be undefined if the open method didn't set any value.
 *
 * Valid replies:
 *   fuse_reply_buf
 *   fuse_reply_iov
 *   fuse_reply_data
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param size number of bytes to read
 * @param off offset to read from
 * @param fi file information
 */
static void oper_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info* fi)
{
    TRACE_OPER("read(%ld, %lu, %lu)", ino, size, off);

    if (size == 0) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    struct handle* handle = (struct handle*)fi->fh;

    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    buf.buf[0].fd = handle->fd;
    buf.buf[0].pos = off;

    METADATA_ITEM_LOCK_INODE(handle->mi);
    if (off < handle->mi->inode->file_data->size) {
        size_t block_count = METADATA_ITEM_COUNT_BLOCKS(handle->mi, off, size);
        struct cache_handle cache_handle;
        cache_handle.blocks = 0;
        cache_handle.block_fetch_failed = FALSE;
        gboolean handle_init = FALSE;
        size_t block_idx_start = METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET(
            handle->mi, off);
        METADATA_ITEM_LOCK_RW_READ(handle->mi);
        for (size_t i = 0; i < block_count; i++) {
            size_t block_idx = block_idx_start + i;
            METADATA_ITEM_LOCK_CACHE(handle->mi);
            if (!fs_metadata_item_is_block_readable_from_cache(handle->mi,
                    block_idx)) {
                if (!handle_init) {
                    cache_handle.mi = handle->mi;
                    g_cond_init(&cache_handle.block_fetch_cond);
                    g_mutex_init(&cache_handle.block_fetch_lock);
                    handle_init = TRUE;
                    LOCK_SNAP_WRITING();
                }
                g_mutex_lock(&cache_handle.block_fetch_lock);
                cache_handle.blocks++;
                g_mutex_unlock(&cache_handle.block_fetch_lock);
                // Start fetching the block, the result will arrive from
                // a different thread in the callback
                g_debug("Fetching block %ld of inode %ld", block_idx,
                    handle->mi->inumber);
                if (!fs_metadata_item_cache_block(handle->mi, block_idx,
                        handle->fd,
                        cache_block_simple_callback, &cache_handle)) {
                    // Probably a hole found in indirect
                    g_mutex_lock(&cache_handle.block_fetch_lock);
                    cache_handle.blocks--;
                    g_mutex_unlock(&cache_handle.block_fetch_lock);
                }
            }
            METADATA_ITEM_UNLOCK_CACHE(handle->mi);
        }
        if (handle_init) {
            // Wait for the blocks to finish downloading
            g_mutex_lock(&cache_handle.block_fetch_lock);
            while (cache_handle.blocks > 0) {
                g_debug("Waiting for %ld blocks", cache_handle.blocks);
                g_cond_wait(&cache_handle.block_fetch_cond,
                    &cache_handle.block_fetch_lock);
            }
            g_mutex_unlock(&cache_handle.block_fetch_lock);
            UNLOCK_SNAP_WRITING();
        }
        METADATA_ITEM_UNLOCK_RW_READ(handle->mi);
        if (handle_init) {
            g_mutex_clear(&cache_handle.block_fetch_lock);
            g_cond_clear(&cache_handle.block_fetch_cond);
        }
        if (cache_handle.block_fetch_failed) {
            fuse_reply_err(req, EIO);
            return;
        }
    }
    METADATA_ITEM_UNLOCK_INODE(handle->mi);

    // Satisfy the request
    fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

/**
 * Write data made available in a buffer
 *
 * This is a more generic version of the ->write() method.  If
 * FUSE_CAP_SPLICE_READ is set in fuse_conn_info.want and the
 * kernel supports splicing from the fuse device, then the
 * data will be made available in pipe for supporting zero
 * copy data transfer.
 *
 * buf->count is guaranteed to be one (and thus buf->idx is
 * always zero). The write_buf handler must ensure that
 * bufv->off is correctly updated (reflecting the number of
 * bytes read from bufv->buf[0]).
 *
 * Introduced in version 2.9
 *
 * Valid replies:
 *   fuse_reply_write
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param bufv buffer containing the data
 * @param off offset to write to
 * @param fi file information
 */
static void oper_write_buf(fuse_req_t req, fuse_ino_t ino,
    struct fuse_bufvec* bufv, off_t off, struct fuse_file_info* fi)
{
    TRACE_OPER("write_buf(%ld, <buffer>, %lu)", ino, off);

    struct handle* handle = (struct handle*)fi->fh;

    size_t buf_size = fuse_buf_size(bufv);
    struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT(buf_size);
    out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    out_buf.buf[0].fd = handle->fd;
    out_buf.buf[0].pos = off;

    gboolean locked = FALSE;
    METADATA_ITEM_LOCK_INODE(handle->mi);
    if (off < handle->mi->inode->file_data->size) {
        // Make sure we have the blocks which are going to be partially
        // overwritten stored in the cache
        int64_t cand_blocks[] = { -1, -1 };
        size_t first_block_idx = METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET(
            handle->mi, off);
        size_t last_block_idx = METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET(
            handle->mi, off + buf_size);

        size_t block_offset = METADATA_ITEM_BLOCK_OFFSET(handle->mi, off);
        // Consider the first block we'll be writing to if it's not aligned
        // at offset boundary
        if (block_offset > 0)
            cand_blocks[0] = first_block_idx;

        block_offset = METADATA_ITEM_BLOCK_OFFSET(handle->mi, off + buf_size);
        // Consider the last block we'll be writing to if it's not aligned and
        // different to the first block
        if (block_offset > 0 && cand_blocks[0] != last_block_idx)
            cand_blocks[1] = last_block_idx;

        if (cand_blocks[0] > -1 || cand_blocks[1] > -1) {
            struct cache_handle cache_handle;
            cache_handle.blocks = 0;
            cache_handle.block_fetch_failed = FALSE;
            gboolean handle_init = FALSE;

            METADATA_ITEM_LOCK_RW_READ(handle->mi);
            for (int i = 0; i < 2; i++) {
                size_t block_idx = cand_blocks[i];
                if (block_idx == -1)
                    continue;

                METADATA_ITEM_LOCK_CACHE(handle->mi);
                if (!fs_metadata_item_is_block_readable_from_cache(
                        handle->mi, block_idx)) {
                    if (!handle_init) {
                        cache_handle.mi = handle->mi;
                        g_cond_init(&cache_handle.block_fetch_cond);
                        g_mutex_init(&cache_handle.block_fetch_lock);
                        handle_init = TRUE;
                        LOCK_SNAP_WRITING();
                        locked = TRUE;
                    }
                    g_mutex_lock(&cache_handle.block_fetch_lock);
                    cache_handle.blocks++;
                    g_mutex_unlock(&cache_handle.block_fetch_lock);
                    // Start fetching the block, the result will arrive from
                    // a different thread in the callback
                    g_debug("Fetching block %ld of inode %ld", block_idx,
                        handle->mi->inumber);
                    if (!fs_metadata_item_cache_block(handle->mi, block_idx,
                            handle->fd,
                            cache_block_simple_callback, &cache_handle)) {
                        // Probably a hole found in indirect
                        g_mutex_lock(&cache_handle.block_fetch_lock);
                        cache_handle.blocks--;
                        g_mutex_unlock(&cache_handle.block_fetch_lock);
                    }
                }
                METADATA_ITEM_UNLOCK_CACHE(handle->mi);
            }
            if (handle_init) {
                // Wait for the blocks to finish downloading
                g_mutex_lock(&cache_handle.block_fetch_lock);
                while (cache_handle.blocks > 0) {
                    g_debug("Waiting for %ld blocks", cache_handle.blocks);
                    g_cond_wait(&cache_handle.block_fetch_cond,
                        &cache_handle.block_fetch_lock);
                }
                g_mutex_unlock(&cache_handle.block_fetch_lock);
            }
            METADATA_ITEM_UNLOCK_RW_READ(handle->mi);
            if (handle_init) {
                g_mutex_clear(&cache_handle.block_fetch_lock);
                g_cond_clear(&cache_handle.block_fetch_cond);
            }
            if (cache_handle.block_fetch_failed) {
                if (locked)
                    UNLOCK_SNAP_WRITING();
                fuse_reply_err(req, EIO);
                return;
            }
        }
    }
    METADATA_ITEM_UNLOCK_INODE(handle->mi);

    if (!locked)
        LOCK_SNAP_WRITING();
    fs_metadata_item_update_before_write(handle->mi);
    // Copy from input to the output file descriptor
    ssize_t ret = fuse_buf_copy(&out_buf, bufv, 0);
    if (ret < 0) {
        UNLOCK_SNAP_WRITING();
        fuse_reply_err(req, -ret);
        return;
    }
    size_t written = ret;
    // Update local metadata
    METADATA_ITEM_LOCK_RW_WRITE(handle->mi);
    fs_metadata_item_update_after_write(handle->mi, off, written);
    METADATA_ITEM_UNLOCK_RW_WRITE(handle->mi);
    UNLOCK_SNAP_WRITING();

    fuse_reply_write(req, written);
}

/**
 * Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open call there will be exactly one release call.
 *
 * The filesystem may reply with an error, but error values are
 * not returned to close() or munmap() which triggered the
 * release.
 *
 * fi->fh will contain the value set by the open method, or will
 * be undefined if the open method didn't set any value.
 * fi->flags will contain the same flags as for open.
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param fi file information
 */
static void oper_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    TRACE_OPER("release(%ld)", ino);

    struct handle* handle = (struct handle*)fi->fh;

    // Close the descriptor and see if we can finalize; finalization is
    // postponed in case the file is still open for writing by another
    // thread and it is a no-op if the file has only been read from
    close(handle->fd);
    if (ACC_MODE_HAS_WRITE(handle->flags))
        METADATA_ITEM_DEC_USED(handle->mi);
    else
        METADATA_ITEM_DEC_USED_READ_ONLY(handle->mi);

    GError* err = NULL;
    if (fs_metadata_item_update_finalize(handle->mi, &err))
        fuse_reply_err(req, 0);
    else {
        g_warning("Failed to finalize inode %ld: %s", handle->mi->inumber,
            err->message);
        g_error_free(err);
        fuse_reply_err(req, EIO);
    }
    g_slice_free(struct handle, handle);
}

struct dir_iter {
    struct metadata_item* mi;
    GHashTableIter iter;
    int64_t offset;
    int64_t inode_id;
    size_t inode_updates;
    gboolean indirect;
};

/**
 * Open a directory
 *
 * Filesystem may store an arbitrary file handle (pointer, index,
 * etc) in fi->fh, and use this in other all other directory
 * stream operations (readdir, releasedir, fsyncdir).
 *
 * Filesystem may also implement stateless directory I/O and not
 * store anything in fi->fh, though that makes it impossible to
 * implement standard conforming directory stream operations in
 * case the contents of the directory can change between opendir
 * and releasedir.
 *
 * Valid replies:
 *   fuse_reply_open
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param fi file information
 */
static void oper_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    TRACE_OPER("opendir(%ld)", ino);

    struct dhtfs* fs = dhtfs(req);
    struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
    // Make sure we have the latest inode for the directory
    if (!refresh_inode_for_req(mi, TRUE, req))
        return;

    struct dir_iter* di = g_slice_new0(struct dir_iter);
    // Set an invalid offset to force initialization in readdir()
    di->offset = -1;
    di->mi = mi;
    fi->fh = (uint64_t)di;

    METADATA_ITEM_INC_USED(mi);
    fuse_reply_open(req, fi);
}

static size_t readdir_from_iter(fuse_req_t req, struct dir_iter* di, char* buf,
    off_t off, off_t off_bytes, size_t size, gboolean* buffer_full)
{
    size_t written = off_bytes;
    gchar* name;
    ThriftDirEntry* entry;
    while (g_hash_table_iter_next(&di->iter,
        (gpointer*)&name,
        (gpointer*)&entry)) {
        if (di->offset < off) {
            di->offset++;
            continue;
        }
        struct metadata_item* mi = fs_metadata_item_get_from_dir_entry(
            di->mi, entry);
        if (G_UNLIKELY(mi == NULL)) {
            g_warn_if_reached();
            di->offset++;
            continue;
        }
        METADATA_ITEM_LOCK_LOCAL(mi);
        // Only the st_ino field and bits 12-15 of the st_mode field are used
        struct stat st = {
            .st_ino = mi->local.st.st_ino,
            .st_mode = mi->local.st.st_mode
        };
        METADATA_ITEM_UNLOCK_LOCAL(mi);
        size_t ent_size = fuse_add_direntry(req,
            buf + written,
            size - written,
            name, &st, ++di->offset);
        if (ent_size > (size - written)) {
            *buffer_full = TRUE;
            break;
        }
        written += ent_size;
    }
    return written;
}

/**
 * Read directory
 *
 * Send a buffer filled using fuse_add_direntry(), with size not
 * exceeding the requested size.  Send an empty buffer on end of
 * stream.
 *
 * fi->fh will contain the value set by the opendir method, or
 * will be undefined if the opendir method didn't set any value.
 *
 * Valid replies:
 *   fuse_reply_buf
 *   fuse_reply_data
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param size maximum number of bytes to send
 * @param off offset to continue reading the directory stream
 * @param fi file information
 */
static void oper_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info* fi)
{
    TRACE_OPER("readdir(%ld, %lu, %lu)", ino, size, off);

    struct dir_iter* di = (struct dir_iter*)fi->fh;

    METADATA_ITEM_LOCK_INODE(di->mi);
    size_t count = di->mi->inode->directory_data->count;
    if (count == 0 || count <= off) {
        METADATA_ITEM_UNLOCK_INODE(di->mi);
        // No entries or at the end of the list
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    char* buf = calloc(1, size);
    if (buf == NULL) {
        METADATA_ITEM_UNLOCK_INODE(di->mi);
        fuse_reply_err(req, errno);
        return;
    }
    // The glib hash table only allows iterating forward from the start and
    // doesn't let us find out whether it has changed the content;
    // the inode id and number of updates should fully describe the table state
    // so we just renew the iterator when we see it no longer matches the
    // table content or the we cannot handle the offset change
    if (di->inode_id != di->mi->inode->id
        || di->inode_updates != di->mi->inode_updates
        || di->offset == -1
        || di->offset > off) {
        g_hash_table_iter_init(&di->iter, di->mi->inode->directory_data->entries);
        di->inode_id = di->mi->inode->id;
        di->inode_updates = di->mi->inode_updates;
        di->offset = 0;
        di->indirect = FALSE;
    }
    gboolean buffer_full = FALSE;
    size_t written = readdir_from_iter(req, di, buf, off, 0, size, &buffer_full);
    // If possible, continue reading from the indirect table
    if (!buffer_full && !di->indirect && di->mi->inode_dir_indirect != NULL) {
        g_hash_table_iter_init(&di->iter, di->mi->inode_dir_indirect->entries);
        written = readdir_from_iter(req, di, buf, off, written, size,
            &buffer_full);
        di->indirect = TRUE;
    }
    METADATA_ITEM_UNLOCK_INODE(di->mi);
    if (written == 0)
        fuse_reply_buf(req, NULL, 0);
    else
        fuse_reply_buf(req, buf, written);

    free(buf);
}

/**
 * Release an open directory
 *
 * For every opendir call there will be exactly one releasedir
 * call.
 *
 * fi->fh will contain the value set by the opendir method, or
 * will be undefined if the opendir method didn't set any value.
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param fi file information
 */
static void oper_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    TRACE_OPER("releasedir(%ld)", ino);

    struct dir_iter* di = (struct dir_iter*)fi->fh;
    METADATA_ITEM_DEC_USED(di->mi);

    GError* err = NULL;
    if (fs_metadata_item_update_finalize(di->mi, &err))
        fuse_reply_err(req, 0);
    else {
        g_warning("Failed to finalize inode %ld: %s", di->mi->inumber,
            err->message);
        g_error_free(err);
        fuse_reply_err(req, EIO);
    }
    g_slice_free(struct dir_iter, di);
}

/**
 * Get file system statistics
 *
 * Valid replies:
 *   fuse_reply_statfs
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number, zero means "undefined"
 */
static void oper_statfs(fuse_req_t req, fuse_ino_t ino)
{
    TRACE_OPER("statfs(%ld)", ino);

    struct dhtfs* fs = dhtfs(req);

    struct statvfs stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.f_namemax = fs->cache->statfs.f_namelen;
    stbuf.f_bsize = fs->cache->statfs.f_bsize;
    stbuf.f_frsize = stbuf.f_bsize;
    stbuf.f_flag = ST_NOATIME | ST_NODIRATIME | ST_NODEV | ST_NOSUID;
    if (fs->read_only)
        stbuf.f_flag |= ST_RDONLY;

    // Inspired by sshfs
    // clang-format off
    stbuf.f_blocks =
        stbuf.f_bfree =
        stbuf.f_bavail = 1000ULL * 1024 * 1024 * 1024 / stbuf.f_frsize;
    stbuf.f_files =
        stbuf.f_ffree = 1000000000;
    // clang-format on

    fuse_reply_statfs(req, &stbuf);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 *
 * Valid replies:
 *   fuse_reply_err
 *
 * @param req request handle
 * @param ino the inode number
 * @param mask requested access mode
 */
static void oper_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    TRACE_OPER("access(%ld, 0x%x)", ino, mask);

    struct dhtfs* fs = dhtfs(req);
    if ((mask & W_OK) && fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    int err = 0;
    // We cannot really check if the file still exists without knowing the
    // parent directory, assume it does as the inode is still cached
    if (ino != FUSE_ROOT_ID && (mask & X_OK)) {
        struct metadata_item* mi = fs_metadata_get_item_from_fuse_ino(fs->meta, ino);
        METADATA_ITEM_LOCK_INODE(mi);
        if (mi->inode->type == THRIFT_INODE_TYPE_FILE) {
            METADATA_ITEM_UNLOCK_INODE(mi);
            if (!refresh_inode_for_req(mi, FALSE, req))
                return;
            METADATA_ITEM_LOCK_INODE(mi);
            if ((mi->inode->flags & THRIFT_INODE_FLAGS_EXECUTABLE) == 0)
                err = EACCES;
        }
        METADATA_ITEM_UNLOCK_INODE(mi);
    }
    fuse_reply_err(req, err);
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * Open flags (with the exception of O_NOCTTY) are available in
 * fi->flags.
 *
 * Filesystem may store an arbitrary file handle (pointer, index,
 * etc) in fi->fh, and use this in other all other file operations
 * (read, write, flush, release, fsync).
 *
 * There are also some flags (direct_io, keep_cache) which the
 * filesystem may set in fi, to change the way the file is opened.
 * See fuse_file_info structure in <fuse_common.h> for more details.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 *
 * Valid replies:
 *   fuse_reply_create
 *   fuse_reply_err
 *
 * @param req request handle
 * @param parent inode number of the parent directory
 * @param name to create
 * @param mode file type and mode with which to create the new file
 * @param fi file information
 */
static void oper_create(fuse_req_t req, fuse_ino_t parent_ino, const char* name,
    mode_t mode, struct fuse_file_info* fi)
{
    TRACE_OPER("create(%ld, %s, %#o)", parent_ino, name, mode);

    struct dhtfs* fs = dhtfs(req);
    if (fs->read_only) {
        fuse_reply_err(req, EROFS);
        return;
    }
    if (!S_ISREG(mode)) {
        fuse_reply_err(req, ENOTSUP);
        return;
    }
    // Make sure we have the latest inode for the parent directory
    struct metadata_item* parent = fs_metadata_get_item_from_fuse_ino(
        fs->meta, parent_ino);
    METADATA_ITEM_LOCK_RW_WRITE(parent);
    if (!refresh_inode_for_req(parent, TRUE, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        return;
    }
    // Create an item for the new file; this also adds the item to
    // the global inode table
    struct metadata_item* mi = fs_metadata_item_new(fs->meta, mode);

    // TODO: we currently don't support O_EXCL
    int open_flags = O_RDWR | O_CREAT | (fi->flags & ~(O_ACCMODE | O_EXCL));

    struct handle* handle = open_file_for_req(mi, open_flags, fi->flags, req);
    if (handle == NULL) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        fs_metadata_item_unref(mi);
        return;
    }
    // Add item to the directory
    if (!add_inode_link_for_req(parent, mi, name, req)) {
        METADATA_ITEM_UNLOCK_RW_WRITE(parent);
        close(handle->fd);
        fs_cache_unlink_file(fs->cache, mi->inumber);
        fs_metadata_item_unref(mi);
        g_slice_free(struct handle, handle);
        return;
    }
    METADATA_ITEM_UNLOCK_RW_WRITE(parent);

    fi->fh = (uint64_t)handle;

    // fuse_reply_create() adds a FUSE reference
    fs_metadata_item_fuse_ref(mi);
    fs_metadata_item_unref(mi);

    struct fuse_entry_param e;
    create_fuse_entry_param(&e, mi, fs->config.attr_timeout);
    fuse_reply_create(req, &e, fi);
}

/**
 * Forget about multiple inodes
 *
 * See description of the forget function for more
 * information.
 *
 * Introduced in version 2.9
 *
 * Valid replies:
 *   fuse_reply_none
 *
 * @param req request handle
 */
static void oper_forget_multi(fuse_req_t req, size_t count,
    struct fuse_forget_data* forgets)
{
    struct dhtfs* fs = dhtfs(req);

    for (size_t i = 0; i < count; i++)
        forget_inode(fs, forgets[i].ino, forgets[i].nlookup);

    fuse_reply_none(req);
}

static struct fuse_lowlevel_ops dhtfs_oper = {
    .init = oper_init,
    .destroy = oper_destroy,
    .lookup = oper_lookup,
    .forget = oper_forget,
    .getattr = oper_getattr,
    .setattr = oper_setattr,
    .readlink = oper_readlink,
    .mknod = oper_mknod,
    .mkdir = oper_mkdir,
    .unlink = oper_unlink,
    .rmdir = oper_rmdir,
    .symlink = oper_symlink,
    .rename = oper_rename,
    .link = oper_link,
    .open = oper_open,
    .read = oper_read,
    .write_buf = oper_write_buf,
    .release = oper_release,
    .opendir = oper_opendir,
    .readdir = oper_readdir,
    .releasedir = oper_releasedir,
    .statfs = oper_statfs,
    .access = oper_access,
    .create = oper_create,
    .forget_multi = oper_forget_multi
};

int main(int argc, char* argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct dhtfs* fs;

    fs = g_slice_new0(struct dhtfs);
    int err = fs_config_read(&fs->config, &args);
    if (err != 0)
        goto out_config;

    // FUSE mount and session creation are done first as they print
    // additional command-line options on --help
    struct fuse_chan* ch = fuse_mount(fs->config.mountpoint, &args);
    if (ch != NULL) {
        struct fuse_session* session = fuse_lowlevel_new(
            &args,
            &dhtfs_oper, sizeof(dhtfs_oper), fs);
        if (session != NULL) {
            err = setup_local_storage(fs);
            if (err == 0)
                err = setup_dht_and_metadata(fs);
            if (err == 0 && !fs->config.foreground) {
                g_debug("Daemonizing the process");
                err = fuse_daemonize(fs->config.foreground);
                if (err != 0)
                    fprintf(stderr, "fuse: failed to daemonize process\n");
            }
            if (err == 0)
                err = fuse_set_signal_handlers(session);
            if (err == 0) {
                g_debug("Mounted dhtfs %s at %s",
                    fs->config.fs_name,
                    fs->config.mountpoint);

                fuse_session_add_chan(session, ch);
                if (fs->config.singlethread)
                    err = fuse_session_loop(session);
                else
                    err = fuse_session_loop_mt(session);
                fuse_remove_signal_handlers(session);
                fuse_session_remove_chan(ch);
            }
            fuse_session_destroy(session);
        }
        fuse_unmount(fs->config.mountpoint, ch);
    }
    fs_config_free_fields(&fs->config);
out_config:
    g_slice_free(struct dhtfs, fs);
    fuse_opt_free_args(&args);
    return err ? 1 : 0;
}
