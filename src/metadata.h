#pragma once

#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuse/fuse_lowlevel.h>
#include <glib.h>

#include "cache.h"
#include "dht.h"

#include "thrift/thrift_metadata_types.h"

// Number of file blocks stored in the inode
#define INODE_BLOCKS 64
// Number of file blocks stored in a single indirect table
#define INODE_INDIRECT_BLOCKS 1024

// Number of directory entries stored in the inode
#define INODE_DIR_ENTRIES 64

// Public macros
#define METADATA_ITEM_LOCK_LOCAL(mi) g_rw_lock_reader_lock(&mi->locks.local)
#define METADATA_ITEM_UNLOCK_LOCAL(mi) g_rw_lock_reader_unlock(&mi->locks.local)
#define METADATA_ITEM_LOCK_INODE(mi) g_rw_lock_reader_lock(&mi->locks.inode)
#define METADATA_ITEM_UNLOCK_INODE(mi) g_rw_lock_reader_unlock(&mi->locks.inode)

#define METADATA_ITEM_LOCK_RW_READ(mi) g_rw_lock_reader_lock(&mi->local.locks.read_write)
#define METADATA_ITEM_LOCK_RW_WRITE(mi) g_rw_lock_writer_lock(&mi->local.locks.read_write)
#define METADATA_ITEM_UNLOCK_RW_READ(mi) g_rw_lock_reader_unlock(&mi->local.locks.read_write)
#define METADATA_ITEM_UNLOCK_RW_WRITE(mi) g_rw_lock_writer_unlock(&mi->local.locks.read_write)

#define METADATA_ITEM_LOCK_CACHE(mi) g_mutex_lock(&mi->local.locks.cache)
#define METADATA_ITEM_UNLOCK_CACHE(mi) g_mutex_unlock(&mi->local.locks.cache)

#define METADATA_ITEM_INC_USED(mi) g_atomic_int_inc(&mi->local.used)
#define METADATA_ITEM_DEC_USED(mi) g_atomic_int_dec_and_test(&mi->local.used)
#define METADATA_ITEM_INC_USED_READ_ONLY(mi) g_atomic_int_inc(&mi->local.used_read_only)
#define METADATA_ITEM_DEC_USED_READ_ONLY(mi) g_atomic_int_dec_and_test(&mi->local.used_read_only)

#define METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET(mi, offset) \
    ((size_t)(ceil((offset) / (mi)->meta->block_size)))

// Count the number of blocks covered by the given size with the given offset
// clang-format off
#define METADATA_ITEM_COUNT_BLOCKS(mi, offset, size) \
    (((size) == 0) ? 0 : METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET((mi), (offset) + (size) - 1) - METADATA_ITEM_BLOCK_INDEX_FROM_OFFSET((mi), (offset)) + 1)
// clang-format on

#define METADATA_ITEM_BLOCK_OFFSET(mi, offset) \
    ((size_t)((offset) % (mi)->meta->block_size))

struct metadata;
struct metadata_item;

struct metadata {
    struct cache* cache;
    struct dht* dht;
    struct metadata_item* root;
    gchar* name;
    ThriftFileSystemModel model;
    int64_t inception_time;
    int64_t snap_time;
    int64_t range_delta;
    int32_t block_size;
    int32_t xattr_size;
    struct {
        blksize_t st_blksize;
        uid_t st_uid;
        gid_t st_gid;
    } stat;

    // Private fields
    GHashTable* inodes;
    GQueue* finalize_queue;
    GRecMutex lock_inodes;
    int umask;
    gatomicrefcount ref_count;
};

struct metadata_item {
    struct metadata* meta;
    // The DHT inode number; this is also present in the inode structure, but
    // the inode structure may not be filled yet
    int64_t inumber;

    // Local information, this may be ahead of the `global' information
    // provided by inode; access must be protected by the local lock
    struct {
        size_t updates;
        struct stat st;
        // Bitmaps maintaining state of blocks
        GArray* cache_bitmap;
        GArray* write_bitmap;
        GArray* pending_bitmap;
        GArray* indirect_pending_bitmap;
        // Set to TRUE after xattr have been initially loaded from the cache
        gboolean xattr_loaded;
        // Set to TRUE when the information stored in xattr match information
        // stored in the cache
        gboolean xattr_valid;
        GList* block_watchers;
        struct {
            GRWLock read_write;
            GMutex cache;
        } locks;
        volatile int cache_changed;
        volatile int used;
        volatile int used_read_only;
    } local;

    struct {
        GRWLock local;
        GRWLock inode;
        GMutex writers;
        GMutex dir_entry;
        GMutex fuse_ref_count;
        GMutex dht_block_watch;
        GMutex refresh_finalize;
    } locks;

    // These fields are protected by the inode lock
    ThriftInode* inode;
    GList* inode_dir_entry_diffs;
    size_t inode_updates;
    int64_t inode_last_dht_id;

    // Indirect tables
    GPtrArray* inode_indirect;
    ThriftDirDataIndirect* inode_dir_indirect;
    gboolean inode_dir_indirect_updated;

    struct {
        gboolean pending;
        GMutex lock;
        GCond cond;
        time_t last_refresh;
        gboolean last_refresh_full_dir;
    } inode_refresh;

    // Protected by the finalization mutex
    gboolean finalize_scheduled;

    gatomicrefcount ref_count;
    // Number of FUSE references, unlike ref_count, this is initialized to 0
    int64_t fuse_ref_count;
};

typedef void (*fs_metadata_item_cache_block_callback)(struct metadata_item* mi,
    size_t block_idx, GByteArray* block, GError* err, gpointer user_data);

// Metadata API
struct metadata* fs_metadata_new(struct cache* cache, struct dht* dht,
    ThriftFileSystem* fs_desc, int umask, int64_t snap_time, int64_t range_delta);
struct metadata* fs_metadata_ref(struct metadata* meta);
void fs_metadata_unref(struct metadata* meta);

gboolean fs_metadata_initialize(struct metadata* meta, int64_t root_inumber,
    GError** err);
struct metadata_item* fs_metadata_get_item_from_fuse_ino(struct metadata* meta,
    fuse_ino_t ino);
gboolean fs_metadata_finalize_flush(struct metadata* meta);

// Metadata item API
struct metadata_item* fs_metadata_item_new(struct metadata* meta, mode_t mode);
struct metadata_item* fs_metadata_item_new_symlink(struct metadata* meta,
    const gchar* target);
struct metadata_item* fs_metadata_item_ref(struct metadata_item* mi);
void fs_metadata_item_unref(struct metadata_item* mi);
struct metadata_item* fs_metadata_item_fuse_ref(struct metadata_item* mi);
void fs_metadata_item_fuse_unref(struct metadata_item* mi, int64_t nlookup);
void fs_metadata_item_fuse_forget(struct metadata_item* mi);

gboolean fs_metadata_item_is_block_readable_from_cache(struct metadata_item* mi,
    size_t block_idx);
gboolean fs_metadata_item_cache_block(struct metadata_item* mi, size_t block_idx,
    int fd, fs_metadata_item_cache_block_callback callback, gpointer user_data);
struct metadata_item* fs_metadata_item_get_from_dir_entry(
    struct metadata_item* parent, ThriftDirEntry* entry);
struct metadata_item* fs_metadata_item_lookup(struct metadata_item* parent,
    const char* name);

gboolean fs_metadata_item_refresh_inode(struct metadata_item* mi,
    gboolean verify_dir_diffs, GError** err);
void fs_metadata_item_set_parent(struct metadata_item* item,
    struct metadata_item* parent);

gboolean fs_metadata_item_update_add_link(struct metadata_item* parent,
    struct metadata_item* mi, const gchar* name);
gboolean fs_metadata_item_update_remove_link(struct metadata_item* parent,
    const gchar* name);
gboolean fs_metadata_item_update_rename(struct metadata_item* parent,
    const gchar* name, struct metadata_item* newparent, const gchar* newname);

void fs_metadata_item_update_before_write(struct metadata_item* mi);
gboolean fs_metadata_item_update_after_write(struct metadata_item* mi, off_t offset,
    size_t written);
gboolean fs_metadata_item_update_mode(struct metadata_item* mi, mode_t mode);
gboolean fs_metadata_item_update_mtime_now(struct metadata_item* mi);
gboolean fs_metadata_item_update_size(struct metadata_item* mi, size_t size, int fd,
    GError** err);
gboolean fs_metadata_item_update_finalize(struct metadata_item* mi, GError** err);
