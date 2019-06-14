#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <fuse/fuse_lowlevel.h>
#include <glib-object.h>
#include <glib.h>

#include "cache.h"
#include "config.h"
#include "dht-utils.h"
#include "dht.h"
#include "metadata.h"
#include "utils.h"

#include "thrift/thrift_metadata_types.h"
#include "thrift/thrift_rpc_types.h"

// Adjust file mode by copying user mode into group and others and apply umask
// For the time being we restrict mode as follows:
//  - User mode is always either rw or rwx
//  - Group and others have permission bits copied from user mode,
//    with umask applied
// clang-format off
#define COPY_AND_MASK_FILE_MODE(mode, umask) ((mode) & S_IFMT) | \
        ((((mode) & S_IRWXU) | \
         (((mode) & S_IRWXU) >> 3) | \
         (((mode) & S_IRWXU) >> 6)) & ~(umask))
// clang-format on

// Bitmap segment size and type
#define BITMAP_SEG_BITS 32

typedef uint32_t bitmap_seg_t;

// Helper macros for working with bitmaps
#define FILE_SIZE_TO_BLOCKS(size, block_size) \
    ((size_t)(ceil((size) / (double)(block_size))))
#define FILE_SIZE_TO_BITMAP_SIZE(size, block_size) \
    ((size_t)(ceil(ceil((size) / (double)(block_size)) / (double)BITMAP_SEG_BITS)))

#define BITMAP_SEGMENT_IDX_FROM_BLOCK_IDX(block_idx) \
    ((size_t)((block_idx) / BITMAP_SEG_BITS))

#define BITMAP_SEGMENT_FROM_IDX(bitmap, segment_idx) \
    g_array_index((bitmap), bitmap_seg_t, (segment_idx))
#define BITMAP_SEGMENT_FROM_BLOCK_IDX(bitmap, block_idx) \
    BITMAP_SEGMENT_FROM_IDX(bitmap, BITMAP_SEGMENT_IDX_FROM_BLOCK_IDX(block_idx))

#define BITMAP_HAS_IDX(bitmap, segment_idx) ((segment_idx) < (bitmap)->len)
// clang-format off
#define BITMAP_HAS_BLOCK_IDX(bitmap, block_idx) \
    (BITMAP_HAS_IDX(bitmap, BITMAP_SEGMENT_IDX_FROM_BLOCK_IDX(block_idx)) && \
     (BITMAP_SEGMENT_FROM_BLOCK_IDX((bitmap), (block_idx)) \
         &  (1ULL << (BITMAP_SEG_BITS - (block_idx) % BITMAP_SEG_BITS - 1))))

#define BITMAP_SET1_BLOCK_IDX(bitmap, block_idx) \
    *(&BITMAP_SEGMENT_FROM_BLOCK_IDX((bitmap), (block_idx))) \
        |=  (1ULL << (BITMAP_SEG_BITS - (block_idx) % BITMAP_SEG_BITS - 1))

#define BITMAP_SET0_BLOCK_IDX(bitmap, block_idx) \
    *(&BITMAP_SEGMENT_FROM_BLOCK_IDX((bitmap), (block_idx))) \
        &= ~(1ULL << (BITMAP_SEG_BITS - (block_idx) % BITMAP_SEG_BITS - 1))
// clang-format on

// Convert local timestamp to an inode timestamp
#define INODE_MTIME(meta, t) ((t) - (meta)->inception_time)
#define INODE_MTIME_NOW(meta) (fs_current_time() - (meta)->inception_time)

// Internal locking macros
#define LOCK_R_LOCAL(mi) METADATA_ITEM_LOCK_LOCAL(mi)
#define LOCK_R_INODE(mi) METADATA_ITEM_LOCK_INODE(mi)
#define LOCK_W_LOCAL(mi) g_rw_lock_writer_lock(&mi->locks.local)
#define LOCK_W_INODE(mi) g_rw_lock_writer_lock(&mi->locks.inode)
#define LOCK_META_INODES(meta) g_rec_mutex_lock(&meta->lock_inodes)

#define UNLOCK_R_LOCAL(mi) METADATA_ITEM_UNLOCK_LOCAL(mi)
#define UNLOCK_R_INODE(mi) METADATA_ITEM_UNLOCK_INODE(mi)
#define UNLOCK_W_LOCAL(mi) g_rw_lock_writer_unlock(&mi->locks.local)
#define UNLOCK_W_INODE(mi) g_rw_lock_writer_unlock(&mi->locks.inode)
#define UNLOCK_META_INODES(meta) g_rec_mutex_unlock(&meta->lock_inodes)

// Keys of extended attributes
#define XATTR_KEY_FLAGS "user.dhtfs.flags"
#define XATTR_KEY_CACHE_BITMAP "user.dhtfs.bitmap.cache"
#define XATTR_KEY_INODE "user.dhtfs.inode"
#define XATTR_KEY_SYMLINK "user.dhtfs.symlink"

enum xattr_flags {
    X_FL_VALID = 1,
    X_FL_INODE_IN_FILE = 1 << 1
};

// Create a metadata item structure with fixed parameters set.
//
// Return NULL in case an inode with the same inumber is already known.
static struct metadata_item* create_item(struct metadata* meta, int64_t inumber)
{
    struct metadata_item* mi;

    mi = g_slice_new(struct metadata_item);
    LOCK_META_INODES(meta);
    if (g_hash_table_contains(meta->inodes, &inumber)) {
        g_debug("Not creating item for inode %ld which already exists", inumber);
        UNLOCK_META_INODES(meta);
        return NULL;
    }
    memset(mi, 0, sizeof(struct metadata_item));
    mi->inumber = inumber;
    // Add item to the inode table as soon as it's created, even though
    // the structure is yet to be completed; the calling code should make
    // sure the inode is not exposed in FUSE until the inode is complete
    g_debug("Adding inode %ld to the inode table", inumber);
    g_hash_table_insert(meta->inodes, &mi->inumber, mi);
    UNLOCK_META_INODES(meta);

    mi->meta = meta;
    mi->local.st.st_ino = (ino_t)mi;
    // We keep nlink fixed at 1 because it's hard to keep track of how
    // many hard links there are in the file system
    mi->local.st.st_nlink = 1;
    mi->local.st.st_blksize = meta->stat.st_blksize;
    mi->local.st.st_uid = meta->stat.st_uid;
    mi->local.st.st_gid = meta->stat.st_gid;

    // Initialize locks
    g_rw_lock_init(&mi->locks.local);
    g_rw_lock_init(&mi->locks.inode);
    g_rw_lock_init(&mi->local.locks.read_write);
    g_mutex_init(&mi->locks.dir_entry);
    g_mutex_init(&mi->locks.fuse_ref_count);
    g_mutex_init(&mi->locks.dht_block_watch);
    g_mutex_init(&mi->locks.refresh_finalize);
    g_mutex_init(&mi->local.locks.cache);
    g_mutex_init(&mi->inode_refresh.lock);
    g_cond_init(&mi->inode_refresh.cond);

    g_atomic_ref_count_init(&mi->ref_count);
    return mi;
}

// Create a metadata item from a ThriftDirEntry
static struct metadata_item* create_item_from_dir_entry(struct metadata* meta,
    ThriftDirEntry* entry)
{
    struct metadata_item* mi;

    mi = create_item(meta, entry->inumber);
    if (G_UNLIKELY(mi == NULL))
        return NULL;

    LOCK_W_LOCAL(mi);
    // Set the initial file permissions
    int mode;
    switch (entry->type) {
    case THRIFT_INODE_TYPE_FILE:
        // File mode may get the execute bit set later when inode is known
        mode = S_IFREG | S_IRUSR | S_IWUSR;
        break;
    case THRIFT_INODE_TYPE_DIRECTORY:
        // Directory mode is fixed, with the execute bit always set
        mode = S_IFDIR | S_IRWXU;
        break;
    case THRIFT_INODE_TYPE_SYMLINK:
        // Symlink permissions are not used, just supply a common default
        mode = S_IFLNK | S_IRWXU;
        break;
    default:
        g_assert_not_reached();
    }
    mi->local.st.st_mode = COPY_AND_MASK_FILE_MODE(mode, meta->umask);
    UNLOCK_W_LOCAL(mi);
    return mi;
}

// Change sizes of bitmaps.
//
// The local write lock must be held.
static inline void set_item_bitmap_size_unlocked(struct metadata_item* mi,
    size_t bitmap_size)
{
    if (mi->local.cache_bitmap == NULL)
        mi->local.cache_bitmap = g_array_sized_new(
            FALSE, TRUE,
            sizeof(bitmap_seg_t), bitmap_size);
    g_array_set_size(mi->local.cache_bitmap, bitmap_size);
    if (mi->local.write_bitmap == NULL)
        mi->local.write_bitmap = g_array_sized_new(
            FALSE, TRUE,
            sizeof(bitmap_seg_t), bitmap_size);
    g_array_set_size(mi->local.write_bitmap, bitmap_size);
    if (mi->local.pending_bitmap == NULL)
        mi->local.pending_bitmap = g_array_sized_new(
            FALSE, TRUE,
            sizeof(bitmap_seg_t), bitmap_size);
    g_array_set_size(mi->local.pending_bitmap, bitmap_size);
}

// Change sizes of bitmaps based on the given file size.
//
// The local write lock must be held.
static inline void set_item_bitmap_size_from_file_size_unlocked(
    struct metadata_item* mi, size_t file_size)
{
    size_t bitmap_size = FILE_SIZE_TO_BITMAP_SIZE(file_size, mi->meta->block_size);

    set_item_bitmap_size_unlocked(mi, bitmap_size);
    if (bitmap_size > 0) {
        size_t blocks = FILE_SIZE_TO_BLOCKS(file_size, mi->meta->block_size);
        bitmap_seg_t* wsegment = &BITMAP_SEGMENT_FROM_BLOCK_IDX(
            mi->local.write_bitmap, blocks);
        bitmap_seg_t* csegment = &BITMAP_SEGMENT_FROM_BLOCK_IDX(
            mi->local.cache_bitmap, blocks);
        bitmap_seg_t* psegment = &BITMAP_SEGMENT_FROM_BLOCK_IDX(
            mi->local.pending_bitmap, blocks);

        // Zero out all blocks after the latest block the file size covers
        int mask = (1ULL << (BITMAP_SEG_BITS - blocks % BITMAP_SEG_BITS)) - 1;
        *csegment &= ~mask;
        *psegment &= ~mask;
        *wsegment &= ~mask;
    }
}

// Mark extended attributes as invalid, this should be done when they
// no longer match the cached file content.
//
// The local write lock must be held.
static void invalidate_item_xattr_unlocked(struct metadata_item* mi, int fd)
{
    if (!mi->local.xattr_valid) {
        // Already invalidated
        return;
    }
    gboolean close_fd = FALSE;
    if (fd == -1) {
        fd = fs_cache_open_file(mi->meta->cache, mi->inumber, O_WRONLY, NULL);
        if (fd == -1) {
            // If xattr is marked as valid, the file should be writable
            g_warn_if_reached();
            return;
        }
        close_fd = TRUE;
    }
    // We could load the xattr and just unset the flag, but if the stored inode
    // is no longer valid, the flags do not matter
    guint8 buffer[] = { 0 };
    int ret = fsetxattr(fd, XATTR_KEY_FLAGS, buffer, sizeof(buffer), 0);
    if (ret == -1)
        g_warning("Failed to invalidate xattr of inode %ld: %s", mi->inumber,
            g_strerror(errno));

    mi->local.xattr_valid = FALSE;
    if (close_fd)
        close(fd);
}

// Set a new file size of the cached file and update stat accordingly.
// Return TRUE if the file size was changed.
//
// The local write lock must be held.
static gboolean set_item_file_size_unlocked(struct metadata_item* mi, size_t size,
    int fd, GError** err)
{
    if (mi->local.st.st_size == size)
        return FALSE;

    gboolean close_fd = FALSE;
    if (fd == -1) {
        GError* tmp_err = NULL;
        fd = fs_cache_open_file(mi->meta->cache, mi->inumber, O_WRONLY, &tmp_err);
        if (fd == -1) {
            if (errno == ENOENT) {
                // We don't forcefully create the file here, the file needs to
                // be updated only if it already exists
                mi->local.st.st_size = size;
                g_error_free(tmp_err);
                return TRUE;
            }
            g_propagate_error(err, tmp_err);
            return FALSE;
        }
        close_fd = TRUE;
    }
    gboolean ret;
    // Truncate the cached file; this reclaims cache space when the file gets
    // smaller, but also makes things simpler when there are holes in files, e.g.
    // pread() is not going to return end of file, but rather read zeroes
    invalidate_item_xattr_unlocked(mi, fd);
    if (ftruncate(fd, size) == 0) {
        mi->local.st.st_size = size;
        ret = TRUE;
    } else {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
        ret = FALSE;
    }
    if (close_fd)
        close(fd);
    return ret;
}

// Update local information of a file item to match a new inode.
//
// The local write lock and inode read or write lock must be held.
static void update_file_item_for_new_inode_unlocked(struct metadata_item* mi,
    ThriftInode* new_inode)
{
    size_t new_size = new_inode->file_data->size;
    // Adjust the bitmaps for the new file size
    set_item_bitmap_size_from_file_size_unlocked(mi, new_size);

    if (mi->inode != NULL) {
        size_t old_size = mi->inode->file_data->size;
        // Invalidate parts of indirect cache
        if (mi->inode_indirect != NULL && mi->inode_indirect->len > 0) {
            size_t indirect_size_old = mi->inode->file_data->indirect->len;
            size_t indirect_size_new = new_inode->file_data->indirect->len;
            size_t indirect_size_common = MIN(indirect_size_old, indirect_size_new);
            for (size_t i = 0; i < indirect_size_common; i++) {
                if (i >= mi->inode_indirect->len)
                    break;
                if (fs_compare_byte_arrays(
                        g_ptr_array_index(mi->inode->file_data->indirect, i),
                        g_ptr_array_index(new_inode->file_data->indirect, i)))
                    continue;

                // The indirect table has changed, invalidate the cached version
                ThriftFileDataIndirect* indirect
                    = (ThriftFileDataIndirect*)g_ptr_array_index(
                        mi->inode_indirect, i);
                if (indirect != NULL)
                    indirect->valid = FALSE;
            }
            if (indirect_size_new < indirect_size_old)
                g_ptr_array_set_size(mi->inode_indirect, indirect_size_new);
        }

        // Check the cache and pending bitmasks and see if their hashes
        // still match, unset the corresponding bits where they don't
        size_t size = MIN(MIN(old_size, new_size), INODE_BLOCKS);
        size_t bitmap_size = FILE_SIZE_TO_BITMAP_SIZE(size,
            mi->meta->block_size);
        size_t bitmap_blocks = FILE_SIZE_TO_BLOCKS(size,
            mi->meta->block_size);

        for (size_t i = 0; i < bitmap_size; i++) {
            bitmap_seg_t* csegment = &BITMAP_SEGMENT_FROM_IDX(
                mi->local.cache_bitmap, i);
            bitmap_seg_t* psegment = &BITMAP_SEGMENT_FROM_IDX(
                mi->local.pending_bitmap, i);
            bitmap_seg_t segment = *csegment | *psegment;
            if (segment == 0) {
                // No cached or pending blocks for this segment
                continue;
            }
            int nth_bit = BITMAP_SEG_BITS;
            while (TRUE) {
                int bit_pos = g_bit_nth_msf(segment, nth_bit);
                if (bit_pos == -1)
                    break;
                size_t block_idx = i * BITMAP_SEG_BITS + BITMAP_SEG_BITS - bit_pos - 1;
                if (block_idx >= bitmap_blocks) {
                    // We are beyond the last block
                    break;
                }
                // Check if the cached block has changed, all blocks must have
                // allocated byte arrays, even empty ones
                gboolean block_changed = !fs_compare_byte_arrays(
                    g_ptr_array_index(mi->inode->file_data->blocks, block_idx),
                    g_ptr_array_index(new_inode->file_data->blocks, block_idx));
                if (block_changed) {
                    *csegment &= ~(1 << bit_pos);
                    *psegment &= ~(1 << bit_pos);
                    g_debug("Block %ld of inode %ld has changed", block_idx,
                        mi->inumber);
                }
                nth_bit = bit_pos;
            }
        }
    }

    // Fix stat size and truncate the cached file
    GError* err = NULL;
    if (!set_item_file_size_unlocked(mi, new_inode->file_data->size, -1, &err)) {
        if (err != NULL) {
            g_warning("Failed to truncate file for inode %ld: %s",
                mi->inumber, err->message);
            g_error_free(err);
        }
        // Size has not changed if no error is reported
    }
}

// Fetch directory diffs stored before the modification time of the given
// inode and update the inode if needed.
//
// The inode write lock must be held.
static void update_directory_item_diffs_unlocked(struct metadata_item* mi,
    ThriftInode* inode)
{
    if (inode->mtime == 0) {
        // Nothing happened before time 0
        return;
    }
    GError* err = NULL;
    GPtrArray* diffs = fs_dht_get_dir_diffs(mi->meta->dht, mi->meta->name,
        mi->inumber, inode->mtime, mi->meta->range_delta, &err);
    if (diffs == NULL) {
        if (err != NULL) {
            g_warning("Failed to fetch directory diffs for inode %ld: %s",
                inode->inumber, err->message);
            g_error_free(err);
        }
        return;
    }
    g_debug("Found %u directory diffs for inode %ld", diffs->len, inode->inumber);
    if (diffs->len > 0) {
        GHashTable* ht = g_hash_table_new_full(g_str_hash, g_str_equal,
            g_free, g_object_unref);
        ThriftDirEntryDiff* diff = g_object_new(THRIFT_TYPE_DIR_ENTRY_DIFF,
            NULL);
        for (size_t i = 0; i < diffs->len; i++) {
            ThriftBucketValue* bv = g_ptr_array_index(diffs, i);
            if (!fs_thrift_unserialize(bv->value,
                    THRIFT_STRUCT(diff), &err)) {
                g_warning("Failed to unserialize directory diff: %s",
                    err->message);
                g_error_free(err);
                err = NULL;
                continue;
            }
            ThriftDirEntryDiff* latest = g_hash_table_lookup(ht,
                diff->name);
            if (latest == NULL || diff->mtime > latest->mtime) {
                g_hash_table_replace(ht, g_strdup(diff->name), diff);
                diff = g_object_new(THRIFT_TYPE_DIR_ENTRY_DIFF, NULL);
            }
        }
        g_object_unref(diff);

        GHashTableIter iter;
        gchar* name;
        g_hash_table_iter_init(&iter, ht);
        while (g_hash_table_iter_next(&iter,
            (gpointer*)&name,
            (gpointer*)&diff)) {
            gboolean in_indirect = FALSE;
            ThriftDirEntry* current = g_hash_table_lookup(
                inode->directory_data->entries,
                name);
            if (current == NULL && mi->inode_dir_indirect != NULL) {
                current = g_hash_table_lookup(mi->inode_dir_indirect->entries, name);
                in_indirect = TRUE;
            }
            switch (diff->diff_type) {
            case THRIFT_DIR_ENTRY_DIFF_TYPE_ADD:
                if (current == NULL) {
                    if (g_hash_table_size(inode->directory_data->entries)
                        < INODE_DIR_ENTRIES)
                        g_hash_table_insert(inode->directory_data->entries,
                            name, g_object_ref(diff->entry));
                    else {
                        if (mi->inode_dir_indirect == NULL)
                            mi->inode_dir_indirect = g_object_new(
                                THRIFT_TYPE_DIR_DATA_INDIRECT, NULL);
                        g_hash_table_insert(mi->inode_dir_indirect->entries,
                            name, g_object_ref(diff->entry));
                        mi->inode_dir_indirect_updated = TRUE;
                    }
                    g_hash_table_iter_steal(&iter);
                    g_object_unref(diff);
                }
                break;
            case THRIFT_DIR_ENTRY_DIFF_TYPE_REMOVE:
                if (current != NULL) {
                    if (in_indirect)
                        g_hash_table_remove(mi->inode_dir_indirect->entries, name);
                    else
                        g_hash_table_remove(inode->directory_data->entries, name);
                }
                break;
            }
        }
        g_hash_table_unref(ht);
    }
    g_ptr_array_unref(diffs);
}

// Read indirect table and diffs of a directory and update the inode if needed.
//
// The inode write lock must be held.
static void update_directory_item_full_refresh_unlocked(struct metadata_item* mi,
    ThriftInode* inode)
{
    gboolean new_inode_has_indirect = inode->directory_data->indirect != NULL
        && inode->directory_data->indirect->len > 0;
    gboolean indirect_changed = new_inode_has_indirect
        && (mi->inode == NULL
               || mi->inode_dir_indirect == NULL
               || mi->inode->directory_data->indirect == NULL
               || !fs_compare_byte_arrays(
                      mi->inode->directory_data->indirect,
                      inode->directory_data->indirect));
    if (indirect_changed) {
        GError* err = NULL;
        GByteArray* indirect_block = fs_dht_rpc_get(mi->meta->dht,
            inode->directory_data->indirect, &err);
        if (indirect_block == NULL) {
            if (err != NULL) {
                g_warning("Failed to fetch indirect block of inode %ld: %s",
                    mi->inumber, err->message);
                g_error_free(err);
            } else
                g_warning("Failed to find indirect block of inode %ld",
                    mi->inumber);
            goto after_fetch;
        }
        ThriftDirDataIndirect* indirect = g_object_new(
            THRIFT_TYPE_DIR_DATA_INDIRECT, NULL);
        if (!fs_thrift_unserialize(indirect_block,
                THRIFT_STRUCT(indirect), &err)) {
            g_warning("Failed to unserialize indirect block of inode %ld: %s",
                mi->inumber, err->message);
            g_object_unref(indirect);
            g_byte_array_unref(indirect_block);
            goto after_fetch;
        }
        mi->inode_dir_indirect = indirect;
    } else if (mi->inode_dir_indirect != NULL && !new_inode_has_indirect)
        g_clear_object(&mi->inode_dir_indirect);
after_fetch:
    if (mi->meta->model != THRIFT_FILE_SYSTEM_MODEL_PASTIS)
        update_directory_item_diffs_unlocked(mi, inode);
}

// Update local information of a directory item to match a new inode.
//
// The local write lock must be held.
static void update_directory_item_for_new_inode_unlocked(struct metadata_item* mi,
    ThriftInode* new_inode, gboolean full_dir_refresh)
{
    if (full_dir_refresh)
        update_directory_item_full_refresh_unlocked(mi, new_inode);

    // Set directory size to the number of entries
    mi->local.st.st_size = new_inode->directory_data->count;
}

// Update local information of a symlink item to match a new inode.
//
// The local write lock must be held.
static void update_symlink_item_for_new_inode_unlocked(struct metadata_item* mi,
    ThriftInode* new_inode)
{
    gchar* basename = g_path_get_basename(new_inode->symlink_data->target);
    // Set symlink size to the target file name length
    mi->local.st.st_size = strlen(basename);
    g_free(basename);
}

// Associate a metadata item with an inode.
//
// The local and inode write locks must be held.
static void set_item_inode_unlocked(struct metadata_item* mi, ThriftInode* inode,
    gboolean full_dir_refresh)
{
    // First update the metadata item to reflect the new inode and determine
    // the file permissions
    int mode;
    switch (inode->type) {
    case THRIFT_INODE_TYPE_FILE:
        update_file_item_for_new_inode_unlocked(mi, inode);
        mode = S_IFREG | S_IRUSR | S_IWUSR;
        if (inode->flags & THRIFT_INODE_FLAGS_EXECUTABLE)
            mode |= S_IXUSR;
        break;
    case THRIFT_INODE_TYPE_DIRECTORY:
        update_directory_item_for_new_inode_unlocked(mi, inode, full_dir_refresh);
        mode = S_IFDIR | S_IRWXU;
        break;
    case THRIFT_INODE_TYPE_SYMLINK:
        update_symlink_item_for_new_inode_unlocked(mi, inode);
        mode = S_IFLNK | S_IRWXU;
        break;
    }
    if (mi->inode == NULL)
        g_debug("Recording initial inode %ld", mi->inumber);
    else {
        g_debug("Replacing inode %ld: %ld -> %ld", mi->inumber,
            mi->inode->id, inode->id);
        g_object_unref(mi->inode);
    }
    // Fix common stat information and replace the inode
    mi->local.st.st_mode = COPY_AND_MASK_FILE_MODE(mode, mi->meta->umask);
    // clang-format off
    mi->local.st.st_atime =
        mi->local.st.st_mtime =
        mi->local.st.st_ctime =
            (mi->meta->inception_time + inode->mtime) / CONFIG_INDEX_SECS_MULTIPLIER;
    // clang-format on
    mi->inode = g_object_ref(inode);
}

// Create a metadata item for an inode
static struct metadata_item* create_item_from_inode(struct metadata* meta,
    ThriftInode* inode)
{
    struct metadata_item* mi;

    mi = create_item(meta, inode->inumber);
    if (G_UNLIKELY(mi == NULL))
        return NULL;

    LOCK_W_LOCAL(mi);
    LOCK_W_INODE(mi);
    set_item_inode_unlocked(mi, inode, FALSE);
    mi->inode_last_dht_id = inode->id;
    UNLOCK_W_INODE(mi);
    UNLOCK_W_LOCAL(mi);
    return mi;
}

// Create a new metadata item for the root directory
static struct metadata_item* create_item_root(struct metadata* meta, int64_t inumber)
{
    struct metadata_item* root;

    root = create_item(meta, inumber);
    g_assert(root != NULL);

    // FUSE uses a fixed inode number for the root inode
    LOCK_W_LOCAL(root);
    root->local.st.st_ino = FUSE_ROOT_ID;
    UNLOCK_W_LOCAL(root);
    return root;
}

// Create a new metadata structure and return it
struct metadata* fs_metadata_new(struct cache* cache, struct dht* dht,
    ThriftFileSystem* fs_desc, int umask, int64_t snap_time, int64_t range_delta)
{
    g_return_val_if_fail(cache != NULL, NULL);
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(THRIFT_IS_FILE_SYSTEM(fs_desc), NULL);

    struct metadata* meta;
    meta = g_slice_new0(struct metadata);
    meta->cache = fs_cache_ref(cache);
    meta->dht = fs_dht_ref(dht);
    meta->name = g_strdup(fs_desc->name);
    meta->umask = umask;
    // Create a hash table to map DHT inumbers to local inumbers, this is needed
    // to support hard links
    meta->inodes = g_hash_table_new(g_int64_hash, g_int64_equal);
    meta->finalize_queue = g_queue_new();
    meta->model = fs_desc->model;
    meta->inception_time = fs_desc->inception;
    meta->snap_time = snap_time;
    meta->range_delta = range_delta;
    meta->block_size = fs_desc->block_size;
    meta->xattr_size = cache->fs_info.nodesize;
    // Determine the uid, gid and block size from the caching storage
    struct stat st;
    if (stat(cache->volume, &st) == 0) {
        meta->stat.st_blksize = st.st_blksize;
        meta->stat.st_uid = st.st_uid;
        meta->stat.st_gid = st.st_gid;
    } else
        g_warning("Failed to stat caching volume %s: %s", cache->volume,
            g_strerror(errno));

    g_rec_mutex_init(&meta->lock_inodes);
    g_atomic_ref_count_init(&meta->ref_count);
    return meta;
}

// Initialize the metadata by reading and refreshing the root inode.
//
// Return FALSE on error. If err is not set, the root inode has not been found.
gboolean fs_metadata_initialize(struct metadata* meta, int64_t root_inumber,
    GError** err)
{
    g_return_val_if_fail(meta != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    meta->root = create_item_root(meta, root_inumber);
    // Initially the inode table only contains the root inode and we make sure
    // it doesn't get evicted by FUSE forgets
    fs_metadata_item_fuse_ref(meta->root);

    return fs_metadata_item_refresh_inode(meta->root, TRUE, err);
}

// Atomically increase reference count
struct metadata* fs_metadata_ref(struct metadata* meta)
{
    g_return_val_if_fail(meta != NULL, NULL);

    g_atomic_ref_count_inc(&meta->ref_count);

    return meta;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_metadata_unref(struct metadata* meta)
{
    g_return_if_fail(meta != NULL);

    if (g_atomic_ref_count_dec(&meta->ref_count)) {
        g_queue_free_full(meta->finalize_queue,
            (GDestroyNotify)fs_metadata_item_unref);
        if (meta->root) {
            fs_metadata_item_fuse_forget(meta->root);
            fs_metadata_item_unref(meta->root);
        }
        fs_cache_unref(meta->cache);
        fs_dht_unref(meta->dht);
        g_free(meta->name);
        g_hash_table_unref(meta->inodes);
        g_rec_mutex_clear(&meta->lock_inodes);

        g_slice_free(struct metadata, meta);
    }
}

// Retrieve metadata item by the given FUSE inode number.
//
// The inode number must be valid and the metadata item must exist.
struct metadata_item* fs_metadata_get_item_from_fuse_ino(struct metadata* meta,
    fuse_ino_t ino)
{
    g_return_val_if_fail(meta != NULL, NULL);

    if (ino == 0)
        return NULL;
    else if (ino == FUSE_ROOT_ID)
        return meta->root;
    else
        return (struct metadata_item*)ino;
}

// Create an inode for a locally created metadata item
static ThriftInode* create_inode(struct metadata* meta, mode_t mode)
{
    ThriftInodeType type;

    switch (mode & S_IFMT) {
    case S_IFREG:
        type = THRIFT_INODE_TYPE_FILE;
        break;
    case S_IFDIR:
        type = THRIFT_INODE_TYPE_DIRECTORY;
        break;
    case S_IFLNK:
        type = THRIFT_INODE_TYPE_SYMLINK;
        break;
    default:
        g_assert_not_reached();
    }
    ThriftInode* inode = g_object_new(THRIFT_TYPE_INODE,
        "id", fs_random_int64(),
        "inumber", fs_random_int64(),
        "type", type,
        "mtime", INODE_MTIME_NOW(meta),
        NULL);
    switch (type) {
    case THRIFT_INODE_TYPE_FILE:
        // Thrift creates the data objects by itself but doesn't set
        // this flag to TRUE unless we replace the object; here let's just
        // set the flag manually and use the object it created
        inode->__isset_file_data = TRUE;
        if (mode & S_IXUSR)
            g_object_set(inode, "flags", THRIFT_INODE_FLAGS_EXECUTABLE, NULL);
        break;
    case THRIFT_INODE_TYPE_DIRECTORY:
        inode->__isset_directory_data = TRUE;
        break;
    case THRIFT_INODE_TYPE_SYMLINK:
        inode->__isset_symlink_data = TRUE;
        break;
    }
    return inode;
}

// Create a new metadata item structure and return it
struct metadata_item* fs_metadata_item_new(struct metadata* meta, mode_t mode)
{
    g_return_val_if_fail(meta != NULL, NULL);

    struct metadata_item* mi = NULL;
    while (mi == NULL) {
        ThriftInode* inode = create_inode(meta, mode);
        mi = create_item_from_inode(meta, inode);
        if (mi != NULL) {
            LOCK_W_LOCAL(mi);
            // This is a new item, so prevent attempts to load it from cache
            mi->local.xattr_loaded = TRUE;
            mi->local.updates++;
            UNLOCK_W_LOCAL(mi);
        }
        g_object_unref(inode);
    }
    return mi;
}

// Create a new metadata item structure for a symbolic link and return it
struct metadata_item* fs_metadata_item_new_symlink(struct metadata* meta,
    const gchar* target)
{
    g_return_val_if_fail(meta != NULL, NULL);
    g_return_val_if_fail(target != NULL, NULL);

    struct metadata_item* mi = NULL;
    while (mi == NULL) {
        ThriftInode* inode = create_inode(meta, S_IFLNK);
        inode->symlink_data->target = g_strdup(target);
        mi = create_item_from_inode(meta, inode);
        if (mi != NULL) {
            LOCK_W_LOCAL(mi);
            // This is a new item, so prevent attempts to load it from cache
            mi->local.xattr_loaded = TRUE;
            mi->local.updates++;
            UNLOCK_W_LOCAL(mi);
        }
        g_object_unref(inode);
    }
    return mi;
}

// Atomically increase reference count
struct metadata_item* fs_metadata_item_ref(struct metadata_item* mi)
{
    g_return_val_if_fail(mi != NULL, NULL);

    g_atomic_ref_count_inc(&mi->ref_count);

    return mi;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_metadata_item_unref(struct metadata_item* mi)
{
    g_return_if_fail(mi != NULL);

    if (g_atomic_ref_count_dec(&mi->ref_count)) {
        LOCK_META_INODES(mi->meta);
        g_debug("Removing inode %ld from inode table", mi->inumber);
        g_hash_table_remove(mi->meta->inodes, &mi->inumber);
        UNLOCK_META_INODES(mi->meta);

        if (mi->local.cache_bitmap != NULL)
            g_array_free(mi->local.cache_bitmap, TRUE);
        if (mi->local.write_bitmap != NULL)
            g_array_free(mi->local.write_bitmap, TRUE);
        if (mi->local.pending_bitmap != NULL)
            g_array_free(mi->local.pending_bitmap, TRUE);
        if (mi->inode_indirect != NULL)
            g_ptr_array_unref(mi->inode_indirect);
        if (mi->inode != NULL)
            g_object_unref(mi->inode);

        // Clear mutexes and conditions
        g_rw_lock_clear(&mi->locks.local);
        g_rw_lock_clear(&mi->locks.inode);
        g_rw_lock_clear(&mi->local.locks.read_write);
        g_mutex_clear(&mi->locks.dir_entry);
        g_mutex_clear(&mi->locks.fuse_ref_count);
        g_mutex_clear(&mi->locks.dht_block_watch);
        g_mutex_clear(&mi->locks.refresh_finalize);
        g_mutex_clear(&mi->local.locks.cache);
        g_mutex_clear(&mi->inode_refresh.lock);
        g_cond_clear(&mi->inode_refresh.cond);

        g_slice_free(struct metadata_item, mi);
    }
}

//
// FUSE reference counting is handled as follows:
//  - initial reference count is 0
//  - adding the first FUSE reference adds an item reference
//  - dropping the last FUSE reference drops the item reference
//

#define LOCK_FUSE_REF(mi) g_mutex_lock(&mi->locks.fuse_ref_count)
#define UNLOCK_FUSE_REF(mi) g_mutex_unlock(&mi->locks.fuse_ref_count)

// Atomically increase FUSE reference count
struct metadata_item* fs_metadata_item_fuse_ref(struct metadata_item* mi)
{
    g_return_val_if_fail(mi != NULL, NULL);

    LOCK_FUSE_REF(mi);
    mi->fuse_ref_count++;
    if (mi->fuse_ref_count == 1)
        fs_metadata_item_ref(mi);
    UNLOCK_FUSE_REF(mi);
    return mi;
}

// Atomically decrease FUSE reference count
void fs_metadata_item_fuse_unref(struct metadata_item* mi, int64_t nlookup)
{
    g_return_if_fail(mi != NULL);
    g_return_if_fail(nlookup > 0);

    LOCK_FUSE_REF(mi);
    mi->fuse_ref_count -= nlookup;
    if (mi->fuse_ref_count <= 0) {
        if (mi->fuse_ref_count < 0) {
            g_warn_if_reached();
            mi->fuse_ref_count = 0;
        }
        // Unlock before unreffing and this might deallocate the item
        UNLOCK_FUSE_REF(mi);
        fs_metadata_item_unref(mi);
    } else
        UNLOCK_FUSE_REF(mi);
}

// Atomically set FUSE reference count to 0
void fs_metadata_item_fuse_forget(struct metadata_item* mi)
{
    LOCK_FUSE_REF(mi);
    if (mi->fuse_ref_count > 0) {
        mi->fuse_ref_count = 0;
        fs_metadata_item_unref(mi);
    }
    UNLOCK_FUSE_REF(mi);
}

#define INDIRECT_IDX_FROM_BLOCK_IDX(block_idx) \
    (((block_idx)-INODE_BLOCKS) / INODE_INDIRECT_BLOCKS)

#define INDIRECT_OFFSET_FROM_BLOCK_IDX(block_idx) ((block_idx - INODE_BLOCKS) % INODE_INDIRECT_BLOCKS)

#define INDIRECT_PTRS_FROM_BLOCKS(blocks) \
    ceil(MAX((ssize_t)((blocks)-INODE_BLOCKS), 0) / (double)INODE_INDIRECT_BLOCKS)

#define INDIRECT_PTRS_FROM_FILE_SIZE(size, block_size) \
    ceil(MAX(((ssize_t)(FILE_SIZE_TO_BLOCKS(size, block_size)) - INODE_BLOCKS), 0) / (double)INODE_INDIRECT_BLOCKS)

// Return TRUE if the given block can be served from the cache and a DHT
// lookup is not necessary.
//
// This case also applies to holes and blocks outside the file range.
gboolean fs_metadata_item_is_block_readable_from_cache(struct metadata_item* mi,
    size_t block_idx)
{
    g_return_val_if_fail(mi != NULL, FALSE);

    LOCK_R_LOCAL(mi);
    if (block_idx >= FILE_SIZE_TO_BLOCKS(mi->local.st.st_size, mi->meta->block_size)) {
        // Block is beyond the current end of file, the cache can give this answer
        UNLOCK_R_LOCAL(mi);
        return TRUE;
    }
    LOCK_R_INODE(mi);
    // Consider the block as readable from the cache if it has been stored,
    // overwritten, or if there's a hole
    gboolean ret = FALSE;
    if (block_idx < INODE_BLOCKS) {
        if (block_idx < mi->inode->file_data->blocks->len) {
            if (BITMAP_HAS_BLOCK_IDX(mi->local.cache_bitmap, block_idx)
                || BITMAP_HAS_BLOCK_IDX(mi->local.write_bitmap, block_idx))
                ret = TRUE;
            else {
                // Block pointer is in the inode
                GByteArray* block = g_ptr_array_index(mi->inode->file_data->blocks,
                    block_idx);
                if (block == NULL || block->len == 0)
                    ret = TRUE;
            }
        } else
            ret = TRUE; // only known locally
        goto out;
    }
    // Check the indirect tables
    size_t indirect_idx = INDIRECT_IDX_FROM_BLOCK_IDX(block_idx);
    ThriftFileDataIndirect* indirect = NULL;
    if (mi->inode_indirect != NULL && indirect_idx < mi->inode_indirect->len)
        indirect = (ThriftFileDataIndirect*)g_ptr_array_index(
            mi->inode_indirect,
            indirect_idx);
    if (indirect != NULL && indirect->valid) {
        // We can use bitmap to give the answer, but only when we have the
        // indirect table downloaded
        size_t indirect_offset = INDIRECT_OFFSET_FROM_BLOCK_IDX(block_idx);
        if (indirect_offset < indirect->blocks->len) {
            if (BITMAP_HAS_BLOCK_IDX(mi->local.cache_bitmap, block_idx)
                || BITMAP_HAS_BLOCK_IDX(mi->local.write_bitmap, block_idx))
                ret = TRUE;
            else {
                // Block pointer is in the indirect table
                GByteArray* block = g_ptr_array_index(indirect->blocks,
                    indirect_offset);
                if (block == NULL || block->len == 0)
                    ret = TRUE;
            }
            goto out;
        } else
            ret = TRUE; // only known locally
    } else {
        // We'll need to fetch the indirect table to answer, but first see if it's
        // actually there
        if (indirect_idx >= mi->inode->file_data->indirect->len) {
            ret = TRUE;
            goto out;
        }
        // The indirect hash might be empty indicating a hole
        GByteArray* indirect_digest = g_ptr_array_index(mi->inode->file_data->indirect,
            indirect_idx);
        if (indirect_digest == NULL || indirect_digest->len == 0) {
            ret = TRUE;
            goto out;
        }
        // The table exists but we don't have it yet
        goto out;
    }
out:
    UNLOCK_R_INODE(mi);
    UNLOCK_R_LOCAL(mi);
    return ret;
}

struct get_dht_block_data {
    struct metadata_item* mi;
    GByteArray* digest;
    int fd;
    gboolean close_fd;
    off_t offset;
    size_t block_idx;
};

struct block_watch {
    GByteArray* digest;
    size_t block_idx;
    fs_metadata_item_cache_block_callback callback;
    gpointer callback_data;
};

#define LOCK_DHT_BLOCK_WATCH(mi) g_mutex_lock(&mi->locks.dht_block_watch)
#define UNLOCK_DHT_BLOCK_WATCH(mi) g_mutex_unlock(&mi->locks.dht_block_watch)

// Finish retrieving a block from DHT, write it to the local cache and execute
// user-specified callback with the result and block data
static void get_dht_block_callback(struct dht_task* task, gpointer user_data)
{
    struct get_dht_block_data* data = user_data;

    GError* err = NULL;
    GByteArray* block = fs_dht_task_join(task, &err);
    size_t written = 0;
    if (block != NULL) {
        g_debug("Fetched block %lu of inode %ld", data->block_idx,
            data->mi->inumber);
        LOCK_R_INODE(data->mi);
        written = fs_cache_store_bytes(data->fd, block, data->offset, &err);
        // TODO: this error should be propagated, but we can still give the data
        // to the user, it's just not cached
        if (err != NULL) {
            g_warning("Failed to cache block %ld of inode %ld: %s",
                data->block_idx, data->mi->inumber,
                err->message);
            g_error_free(err);
            err = NULL;
        }
        if (written == block->len) {
            LOCK_W_LOCAL(data->mi);
            // Mark the block as cached in the cache bitmap
            BITMAP_SET1_BLOCK_IDX(data->mi->local.cache_bitmap, data->block_idx);
            g_atomic_int_set(&data->mi->local.cache_changed, TRUE);
            UNLOCK_W_LOCAL(data->mi);
        }
        UNLOCK_R_INODE(data->mi);
    }
    // Lock the cache lock, this is done as the code that requested the block
    // download might have locked this to prevent the callbacks from firing
    // too early
    METADATA_ITEM_LOCK_CACHE(data->mi);
    LOCK_DHT_BLOCK_WATCH(data->mi);
    gboolean block_leftovers = FALSE;
    // Execute callbacks for watchers of the downloaded block
    GList* link = data->mi->local.block_watchers;
    while (link != NULL) {
        GList* next = link->next;
        struct block_watch* watch = link->data;
        if (watch->block_idx == data->block_idx) {
            if (fs_compare_byte_arrays(watch->digest, data->digest)) {
                watch->callback(data->mi, data->block_idx, block, err,
                    watch->callback_data);
                g_byte_array_unref(watch->digest);
                g_slice_free(struct block_watch, watch);
                data->mi->local.block_watchers = g_list_delete_link(
                    data->mi->local.block_watchers, link);
            } else {
                // Not likely, but there might be a request for the same block
                // with a different digest
                block_leftovers = TRUE;
            }
        }
        link = next;
    }
    if (!block_leftovers) {
        LOCK_W_LOCAL(data->mi);
        BITMAP_SET0_BLOCK_IDX(data->mi->local.pending_bitmap, data->block_idx);
        UNLOCK_W_LOCAL(data->mi);
    }
    UNLOCK_DHT_BLOCK_WATCH(data->mi);
    METADATA_ITEM_UNLOCK_CACHE(data->mi);

    if (block != NULL)
        g_byte_array_unref(block);
    if (err != NULL)
        g_error_free(err);
    if (data->close_fd)
        close(data->fd);
    g_byte_array_unref(data->digest);
    fs_metadata_item_unref(data->mi);

    g_slice_free(struct get_dht_block_data, data);
}

// Fetch the given block from DHT into local cache. This function may be called
// even if the block is already being downloaded. The calling code may
// lock the cache lock before calling this function to ensure the callbacks
// don't fire while this function is running.
//
// Return FALSE if the block index is invalid or if the file descriptor is not
// supplied and the file couldn't be opened for writing.
//
// The callback will be called once the block is downloaded.
gboolean fs_metadata_item_cache_block(struct metadata_item* mi, size_t block_idx,
    int fd, fs_metadata_item_cache_block_callback callback, gpointer user_data)
{
    g_return_val_if_fail(mi != NULL, FALSE);

    // Create a watcher for this block which extends the user-supplied callback
    // with auxiliary information
    struct block_watch* watch;
    watch = g_slice_new(struct block_watch);
    watch->block_idx = block_idx;
    watch->callback = callback;
    watch->callback_data = user_data;

    LOCK_DHT_BLOCK_WATCH(mi);
    LOCK_W_LOCAL(mi);
    mi->local.block_watchers = g_list_prepend(mi->local.block_watchers, watch);
    UNLOCK_DHT_BLOCK_WATCH(mi);
    // Ensure the block is only downloaded once by setting the pending bit
    gboolean is_pending = BITMAP_HAS_BLOCK_IDX(mi->local.pending_bitmap, block_idx);
    if (!is_pending)
        BITMAP_SET1_BLOCK_IDX(mi->local.pending_bitmap, block_idx);
    UNLOCK_W_LOCAL(mi);

    LOCK_R_INODE(mi);
    GByteArray* digest = NULL;
    if (block_idx < INODE_BLOCKS) {
        if (block_idx >= mi->inode->file_data->blocks->len) {
            // Inode has shrunk
            UNLOCK_R_INODE(mi);
            g_slice_free(struct block_watch, watch);
            return FALSE;
        }
        digest = g_ptr_array_index(mi->inode->file_data->blocks, block_idx);
    } else {
        size_t indirect_idx = INDIRECT_IDX_FROM_BLOCK_IDX(block_idx);
        ThriftFileDataIndirect* indirect = NULL;
        if (mi->inode_indirect != NULL && indirect_idx < mi->inode_indirect->len)
            indirect = (ThriftFileDataIndirect*)g_ptr_array_index(
                mi->inode_indirect,
                indirect_idx);
        if (indirect == NULL || !indirect->valid) {
            digest = g_ptr_array_index(mi->inode->file_data->indirect, indirect_idx);
            if (digest == NULL || digest->len == 0) {
                // Whole indirect block is missing
                UNLOCK_R_INODE(mi);
                g_slice_free(struct block_watch, watch);
                return FALSE;
            }
            g_debug("Fetching indirect table %lu of inode %ld",
                indirect_idx, mi->inumber);
            GError* err = NULL;
            GByteArray* indirect_block = fs_dht_rpc_get(mi->meta->dht, digest, &err);
            if (indirect_block == NULL) {
                if (err != NULL) {
                    g_warning("Failed to fetch indirect block %lu of inode %ld: %s",
                        indirect_idx, mi->inumber, err->message);
                    g_error_free(err);
                } else
                    g_warning("Failed to find indirect block %lu of inode %ld",
                        indirect_idx, mi->inumber);
                UNLOCK_R_INODE(mi);
                g_slice_free(struct block_watch, watch);
                return FALSE;
            }
            ThriftFileDataIndirect* new_indirect = g_object_new(
                THRIFT_TYPE_FILE_DATA_INDIRECT, NULL);
            if (!fs_thrift_unserialize(indirect_block,
                    THRIFT_STRUCT(new_indirect), &err)) {
                g_warning("Failed to unserialize indirect block %lu of inode %ld: %s",
                    indirect_idx, mi->inumber, err->message);
                UNLOCK_R_INODE(mi);
                g_object_unref(new_indirect);
                g_byte_array_unref(indirect_block);
                g_slice_free(struct block_watch, watch);
                return FALSE;
            }
            g_byte_array_unref(indirect_block);
            if (mi->inode_indirect == NULL || indirect_idx >= mi->inode_indirect->len) {
                if (mi->inode_indirect == NULL)
                    mi->inode_indirect = g_ptr_array_new_full(
                        mi->inode->file_data->indirect->len,
                        g_object_unref);
                g_ptr_array_set_size(mi->inode_indirect, indirect_idx + 1);
            }

            if (indirect != NULL) {
                GPtrArray* old_blocks = indirect->blocks;
                GPtrArray* new_blocks = new_indirect->blocks;

                for (size_t i = 0; i < MIN(old_blocks->len, new_blocks->len); i++) {
                    gboolean block_changed = !fs_compare_byte_arrays(
                        g_ptr_array_index(old_blocks, i),
                        g_ptr_array_index(new_blocks, i));
                    if (block_changed) {
                        g_debug("Block %lu/%ld of inode %ld has changed",
                            indirect_idx, block_idx, mi->inumber);
                    }
                }
            }

            ThriftFileDataIndirect** indirect_ptr
                = (ThriftFileDataIndirect**)&g_ptr_array_index(
                    mi->inode_indirect,
                    indirect_idx);

            if (indirect != NULL)
                g_object_unref(indirect);

            *indirect_ptr = indirect = new_indirect;
        }

        size_t indirect_offset = INDIRECT_OFFSET_FROM_BLOCK_IDX(block_idx);
        if (indirect_offset < indirect->blocks->len)
            digest = g_ptr_array_index(indirect->blocks, indirect_offset);
    }
    if (digest == NULL || digest->len == 0) {
        // There's a hole at this block, this function should not be
        // called in this case
        g_warn_if_reached();
        UNLOCK_R_INODE(mi);
        g_slice_free(struct block_watch, watch);
        return FALSE;
    }
    watch->digest = g_byte_array_ref(digest);
    UNLOCK_R_INODE(mi);

    if (!is_pending) {
        // Create a local structure which will handle the result, unlike the
        // watchers, this one corresponds to a block download
        struct get_dht_block_data* data;
        data = g_slice_new(struct get_dht_block_data);
        if (fd != -1) {
            data->fd = fd;
            data->close_fd = FALSE;
        } else {
            // Make sure the file is created as it might not exist yet
            data->fd = fs_cache_open_file(mi->meta->cache, mi->inumber,
                O_WRONLY | O_CREAT, NULL);
            if (data->fd == -1) {
                g_byte_array_unref(watch->digest);
                g_slice_free(struct block_watch, watch);
                g_slice_free(struct get_dht_block_data, data);
                return FALSE;
            }
            data->close_fd = TRUE;
        }
        data->digest = g_byte_array_ref(digest);
        data->mi = fs_metadata_item_ref(mi);
        data->offset = block_idx * mi->meta->block_size;
        data->block_idx = block_idx;

        // Create a non-blocking DHT task for the request
        struct dht_task* task;
        task = fs_dht_create_task_get(digest);
        fs_dht_task_set_callback(task, get_dht_block_callback, data);
        fs_dht_add_task(mi->meta->dht, task, FALSE, FALSE, NULL);
    }
    return TRUE;
}

#define LOCK_DIR_ENTRY(mi) g_mutex_lock(&mi->locks.dir_entry)
#define UNLOCK_DIR_ENTRY(mi) g_mutex_unlock(&mi->locks.dir_entry)

// Get a metadata item from a ThriftDirEntry, first creating it if necessary
struct metadata_item* fs_metadata_item_get_from_dir_entry(
    struct metadata_item* parent, ThriftDirEntry* entry)
{
    g_return_val_if_fail(parent != NULL, NULL);
    g_return_val_if_fail(THRIFT_IS_DIR_ENTRY(entry), NULL);

    LOCK_DIR_ENTRY(parent);
    LOCK_META_INODES(parent->meta);
    struct metadata_item* mi = g_hash_table_lookup(parent->meta->inodes,
        &entry->inumber);
    if (mi == NULL) {
        // The item is not in the inode table if we haven't used the ThriftDirEntry
        // yet; create it and consume an item reference through a weakref
        //(using qdata would be better, but thrift doesn't chain finalization)
        mi = create_item_from_dir_entry(parent->meta, entry);
        if (G_UNLIKELY(mi == NULL)) {
            UNLOCK_META_INODES(parent->meta);
            UNLOCK_DIR_ENTRY(parent);
            g_warn_if_reached();
            return NULL;
        }
        g_object_weak_ref(G_OBJECT(entry), (GWeakNotify)fs_metadata_item_unref, mi);
    }
    UNLOCK_META_INODES(parent->meta);
    UNLOCK_DIR_ENTRY(parent);
    return mi;
}

// Lookup a child metadata item by name
struct metadata_item* fs_metadata_item_lookup(struct metadata_item* parent,
    const char* name)
{
    g_return_val_if_fail(parent != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    // It is an error to call this function before parent inode is downloaded
    g_return_val_if_fail(parent->inode != NULL, NULL);

    struct metadata_item* item = NULL;

    LOCK_R_INODE(parent);
    ThriftDirEntry* entry = g_hash_table_lookup(
        parent->inode->directory_data->entries, name);
    if (entry == NULL && parent->inode_dir_indirect != NULL)
        entry = g_hash_table_lookup(parent->inode_dir_indirect->entries, name);
    if (entry != NULL)
        item = fs_metadata_item_get_from_dir_entry(parent, entry);
    UNLOCK_R_INODE(parent);
    return item;
}

// Load cached metadata from extended attributes. This must be done before
// an inode has been downloaded.
//
// The local and inode write locks must be held.
static void read_item_xattr_unlocked(struct metadata_item* mi, int fd)
{
    g_return_if_fail(mi->inode == NULL);
    g_return_if_fail(mi->local.cache_bitmap == NULL);
    g_return_if_fail(mi->local.write_bitmap == NULL);
    g_return_if_fail(mi->local.pending_bitmap == NULL);

    gboolean close_fd = FALSE;
    if (fd == -1) {
        fd = fs_cache_open_file(mi->meta->cache, mi->inumber, O_RDONLY, NULL);
        if (fd == -1)
            return;
        close_fd = TRUE;
    }
    ssize_t size;
    guint8 buffer[mi->meta->xattr_size];
    size = fgetxattr(fd, XATTR_KEY_FLAGS, buffer, sizeof(buffer));
    if (size < 1 || (buffer[0] & X_FL_VALID) == 0) {
        g_debug("Skipping invalid xattr for inode %ld", mi->inumber);
        if (close_fd)
            close(fd);
        return;
    }
    guint8 flags = buffer[0];

    // Retrieve the stored inode
    ThriftInode* inode = NULL;
    if (flags & X_FL_INODE_IN_FILE) {
        g_debug("Reading inode %ld from file", mi->inumber);
        int inode_fd = fs_cache_open_inode_file(mi->meta->cache, mi->inumber,
            O_RDONLY, NULL);
        if (inode_fd == -1) {
            g_debug("Failed to open inode file for inode %ld: %s", mi->inumber,
                g_strerror(errno));
            return;
        }
        inode = g_object_new(THRIFT_TYPE_INODE, NULL);
        // Unserialize the inode from the file storing it
        if (!fs_thrift_unserialize_fd(inode_fd, THRIFT_STRUCT(inode), NULL))
            g_clear_object(&inode);
        close(inode_fd);
    } else {
        size = fgetxattr(fd, XATTR_KEY_INODE, buffer, sizeof(buffer));
        if (size > 0) {
            GByteArray* array = g_byte_array_sized_new(size);
            g_byte_array_append(array, buffer, size);
            inode = g_object_new(THRIFT_TYPE_INODE, NULL);
            // Unserialize the inode from bytes
            if (!fs_thrift_unserialize(array, THRIFT_STRUCT(inode), NULL))
                g_clear_object(&inode);
            g_byte_array_unref(array);
        }
    }
    if (inode != NULL) {
        // We cannot use the cached inode if we are reading a snapshot and the
        // inode is newer than the time of the snapshot
        if (mi->meta->snap_time >= 0 && inode->mtime > mi->meta->snap_time)
            g_debug("Not using cached inode %ld (time %ld) in snapshot for time %ld",
                inode->id, inode->mtime, mi->meta->snap_time);
        else {
            if (inode->type == THRIFT_INODE_TYPE_FILE) {
                // Retrieve the cache bitmap, this only makes sense if we've
                // retrieved the inode
                size = fgetxattr(fd, XATTR_KEY_CACHE_BITMAP, buffer, sizeof(buffer));
                if (size > 0) {
                    // Convert from size in bytes to size in bitmap segments
                    size_t bitmap_size = ceil(size / (double)sizeof(bitmap_seg_t));
                    mi->local.cache_bitmap = g_array_sized_new(
                        FALSE, TRUE,
                        sizeof(bitmap_seg_t), bitmap_size);
                    g_array_append_vals(mi->local.cache_bitmap, buffer, bitmap_size);
                    // Make write and pending bitmaps the same size and zeroed out
                    set_item_bitmap_size_unlocked(mi, bitmap_size);
                }
            }
            g_debug("Restoring inode %ld from cache", mi->inumber);
            set_item_inode_unlocked(mi, inode, FALSE);
            mi->inode_last_dht_id = inode->id;
        }
    }
    if (close_fd)
        close(fd);
}

#define LOCK_REFRESH_FINALIZE(mi) g_mutex_lock(&mi->locks.refresh_finalize)
#define TRY_LOCK_REFRESH_FINALIZE(mi) g_mutex_trylock(&mi->locks.refresh_finalize)
#define UNLOCK_REFRESH_FINALIZE(mi) g_mutex_unlock(&mi->locks.refresh_finalize)

// Load the latest inode for the given item from the DHT.
//
// Return FALSE on error. If err is not set, the inode has not been found.
gboolean fs_metadata_item_refresh_inode(struct metadata_item* mi,
    gboolean full_dir_refresh, GError** err)
{
    g_return_val_if_fail(mi != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    if (g_atomic_int_get(&mi->local.used) > 0)
        return TRUE;

    // Skip if we have mounted a snapshot and the inode is already known, this
    // just optimizes such case early, the code below handles possible
    // concurrency issues
    if (mi->meta->snap_time >= 0
        && (!full_dir_refresh || mi->inode_refresh.last_refresh_full_dir)) {
        LOCK_R_INODE(mi);
        gboolean have_inode = mi->inode != NULL;
        UNLOCK_R_INODE(mi);
        if (have_inode)
            return TRUE;
    }
    if (mi->meta->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT
        && (!full_dir_refresh || mi->inode_refresh.last_refresh_full_dir)
        && (mi->inode_refresh.last_refresh == 0
               || mi->meta->cache->last_data_snapshot == 0
               || mi->inode_refresh.last_refresh > mi->meta->cache->last_data_snapshot)) {
        g_debug("Skipping refresh of inode %ld", mi->inumber);
        g_debug("  -- last refresh @ %ld, last snapshot @ %ld",
            mi->inode_refresh.last_refresh,
            mi->meta->cache->last_data_snapshot);
        LOCK_R_INODE(mi);
        gboolean have_inode = mi->inode != NULL;
        UNLOCK_R_INODE(mi);
        if (have_inode)
            return TRUE;
    }
    gboolean ret = TRUE;
    g_mutex_lock(&mi->inode_refresh.lock);
    if (mi->inode_refresh.pending) {
        // Metadata is already being downloaded in a different thread, just
        // wait until the update is available and then return
        while (mi->inode_refresh.pending)
            g_cond_wait(&mi->inode_refresh.cond, &mi->inode_refresh.lock);
    } else {
        // The xattr_loaded flag is only used in this function and it is required
        // that a refresh is done before any changes to an item
        if (!mi->local.xattr_loaded) {
            LOCK_W_LOCAL(mi);
            LOCK_W_INODE(mi);
            g_assert(mi->inode == NULL);
            g_assert(mi->local.updates == 0 && mi->inode_updates == 0);
            // The first refresh starts by loading metadata from the cache
            read_item_xattr_unlocked(mi, -1);
            mi->local.xattr_loaded = TRUE;
            if (mi->inode != NULL) {
                // Allow invalidating the xattr, but only if there is actually
                // something in the xattr
                mi->local.xattr_valid = TRUE;
            }
            UNLOCK_W_INODE(mi);
            UNLOCK_W_LOCAL(mi);
        }
        // Only one refreshing thread reaches this point at a time, if finalize
        // is running in a different thread, just use the cached inode
        if (!TRY_LOCK_REFRESH_FINALIZE(mi)) {
            g_mutex_unlock(&mi->inode_refresh.lock);
            return TRUE;
        }
        // If there are unsaved updates, just use the cached inode
        LOCK_R_LOCAL(mi);
        LOCK_R_INODE(mi);
        if (mi->local.updates > 0 || mi->inode_updates > 0) {
            g_debug("Not refreshing inode %ld due to unfinalized updates",
                mi->inumber);
            UNLOCK_R_INODE(mi);
            UNLOCK_R_LOCAL(mi);
            UNLOCK_REFRESH_FINALIZE(mi);
            g_mutex_unlock(&mi->inode_refresh.lock);
            return TRUE;
        }
        UNLOCK_R_INODE(mi);
        UNLOCK_R_LOCAL(mi);
        mi->inode_refresh.pending = TRUE;
        mi->inode_refresh.last_refresh_full_dir = FALSE;
        g_mutex_unlock(&mi->inode_refresh.lock);

        g_debug("Refreshing metadata for inode %ld", mi->inumber);
        ThriftInode* inode;
        if (mi->meta->snap_time >= 0)
            inode = fs_dht_get_inode_latest_max(mi->meta->dht,
                mi->meta->name, mi->inumber, mi->meta->snap_time, err);
        else
            inode = fs_dht_get_inode(mi->meta->dht,
                mi->meta->name, mi->inumber, err);
        if (inode != NULL) {
            gboolean skip_time_update = FALSE;
            LOCK_R_INODE(mi);
            if (inode->id == mi->inode_last_dht_id) {
                UNLOCK_R_INODE(mi);
                g_debug("Inode %ld has not changed", mi->inumber);
                if (full_dir_refresh
                    && mi->inode->type == THRIFT_INODE_TYPE_DIRECTORY) {
                    LOCK_W_INODE(mi);
                    update_directory_item_full_refresh_unlocked(mi, mi->inode);
                    UNLOCK_W_INODE(mi);
                    mi->inode_refresh.last_refresh_full_dir = TRUE;
                }
            } else if (mi->inode != NULL && mi->inode->mtime > inode->mtime) {
                UNLOCK_R_INODE(mi);
                g_warning("Inode %ld in DHT is older than local inode (%ld < %ld)",
                    mi->inumber, inode->mtime,
                    mi->inode->mtime);
            } else if (mi->inode != NULL && mi->inode->type != inode->type) {
                UNLOCK_R_INODE(mi);
                // TODO: there should be almost zero chance for this
                // to happen, we don't currently handle it
                g_critical("Inode %ld has changed type", mi->inumber);
                ret = FALSE;
            } else {
                UNLOCK_R_INODE(mi);
                LOCK_W_LOCAL(mi);
                // The last DHT id only changes from within this function and
                // we only allow one instance for a single item, so it's
                // not a problem we dropped the read inode lock and acquire
                // a write lock here
                LOCK_W_INODE(mi);
                if (mi->local.updates == 0 && mi->inode_updates == 0) {
                    set_item_inode_unlocked(mi, inode, full_dir_refresh);
                    mi->inode_last_dht_id = inode->id;
                    if (full_dir_refresh)
                        mi->inode_refresh.last_refresh_full_dir = TRUE;
                } else {
                    // The item might have been changed while the update
                    // was being downloaded, just use the cached version
                    g_debug("Inode %ld was updated during refresh", mi->inumber);
                    skip_time_update = TRUE;
                }
                UNLOCK_W_INODE(mi);
                UNLOCK_W_LOCAL(mi);
            }
            g_object_unref(inode);
            if (!skip_time_update)
                mi->inode_refresh.last_refresh = fs_current_time();
        } else
            ret = FALSE;
        UNLOCK_REFRESH_FINALIZE(mi);

        // Notify the waiting threads
        g_mutex_lock(&mi->inode_refresh.lock);
        mi->inode_refresh.pending = FALSE;
        g_cond_broadcast(&mi->inode_refresh.cond);
    }
    g_mutex_unlock(&mi->inode_refresh.lock);
    return ret;
}

static GObject* create_dir_entry_diff(ThriftDirEntryDiffType diff_type,
    GObject* entry, const gchar* name, int64_t mtime)
{
    return g_object_new(THRIFT_TYPE_DIR_ENTRY_DIFF,
        "diff_type", diff_type,
        "entry", entry,
        "name", name,
        "mtime", mtime,
        NULL);
}

// Create a ThriftDirEntry to be inserted into a directory
static GObject* create_dir_entry_for_item(struct metadata_item* mi)
{
    LOCK_R_INODE(mi);
    ThriftInodeType type = mi->inode->type;
    UNLOCK_R_INODE(mi);

    GObject* entry = g_object_new(THRIFT_TYPE_DIR_ENTRY,
        "inumber", mi->inumber,
        "type", type,
        NULL);
    g_object_weak_ref(entry, (GWeakNotify)fs_metadata_item_unref,
        fs_metadata_item_ref(mi));
    return entry;
}

// Add an item to a directory. This modifies the inode of the directory.
//
// Return FALSE and set errno if there already is an item with the same name.
gboolean fs_metadata_item_update_add_link(struct metadata_item* parent,
    struct metadata_item* mi, const gchar* name)
{
    g_return_val_if_fail(parent != NULL, FALSE);
    g_return_val_if_fail(mi != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);

    LOCK_W_INODE(parent);
    gpointer value = g_hash_table_lookup(parent->inode->directory_data->entries,
        name);
    if (value == NULL && parent->inode_dir_indirect != NULL)
        value = g_hash_table_lookup(parent->inode_dir_indirect->entries, name);
    if (value != NULL) {
        UNLOCK_W_INODE(parent);
        errno = ENOENT;
        return FALSE;
    }
    // Create and insert a ThriftDirEntry into the directory inode, this
    // consumes the initial reference
    GObject* entry = create_dir_entry_for_item(mi);
    if (g_hash_table_size(parent->inode->directory_data->entries) < INODE_DIR_ENTRIES)
        g_hash_table_insert(parent->inode->directory_data->entries,
            g_strdup(name), entry);
    else {
        if (parent->inode_dir_indirect == NULL)
            parent->inode_dir_indirect = g_object_new(THRIFT_TYPE_DIR_DATA_INDIRECT,
                NULL);
        g_hash_table_insert(parent->inode_dir_indirect->entries,
            g_strdup(name), entry);
        parent->inode_dir_indirect_updated = TRUE;
    }
    // Add the entry to the directory diff
    parent->inode_dir_entry_diffs = g_list_prepend(
        parent->inode_dir_entry_diffs,
        create_dir_entry_diff(THRIFT_DIR_ENTRY_DIFF_TYPE_ADD, entry, name,
            INODE_MTIME_NOW(mi->meta)));

    // Directory size counts the number of objects inside
    LOCK_W_LOCAL(parent);
    parent->local.st.st_size++;
    UNLOCK_W_LOCAL(parent);
    parent->inode_updates++;
    UNLOCK_W_INODE(parent);
    return TRUE;
}

// Remove a item from a directory. This modifies the inode of the directory.
//
// Return FALSE and set errno if there is no such item or it cannot be removed.
gboolean fs_metadata_item_update_remove_link(struct metadata_item* parent,
    const gchar* name)
{
    g_return_val_if_fail(parent != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);

    gboolean entry_in_indirect = FALSE;
    LOCK_W_INODE(parent);
    GObject* entry = g_hash_table_lookup(parent->inode->directory_data->entries,
        name);
    if (entry == NULL && parent->inode_dir_indirect != NULL) {
        entry = g_hash_table_lookup(parent->inode_dir_indirect->entries, name);
        entry_in_indirect = TRUE;
    }
    if (entry == NULL) {
        UNLOCK_W_INODE(parent);
        errno = ENOENT;
        return FALSE;
    }
    // Add the entry to the directory diff
    parent->inode_dir_entry_diffs = g_list_prepend(
        parent->inode_dir_entry_diffs,
        create_dir_entry_diff(THRIFT_DIR_ENTRY_DIFF_TYPE_REMOVE, entry, name,
            INODE_MTIME_NOW(parent->meta)));

    if (entry_in_indirect) {
        g_hash_table_remove(parent->inode_dir_indirect->entries, name);
        // Remove the indirect table if it's got empty
        if (g_hash_table_size(parent->inode_dir_indirect->entries) == 0)
            g_clear_object(&parent->inode_dir_indirect);
        parent->inode_dir_indirect_updated = TRUE;
    } else
        g_hash_table_remove(parent->inode->directory_data->entries, name);

    LOCK_W_LOCAL(parent);
    parent->local.st.st_size--;
    UNLOCK_W_LOCAL(parent);
    parent->inode_updates++;
    UNLOCK_W_INODE(parent);
    return TRUE;
}

static void rename_add_entry_unlocked(struct metadata_item* parent, const gchar* name,
    GObject* entry)
{
    gpointer current = g_hash_table_lookup(
        parent->inode->directory_data->entries, name);
    if (current != NULL) {
        // Overwriting an entry in the inode
        g_hash_table_insert(parent->inode->directory_data->entries,
            g_strdup(name), g_object_ref(entry));
        return;
    }
    if (parent->inode_dir_indirect != NULL) {
        current = g_hash_table_lookup(
            parent->inode_dir_indirect->entries, name);
        if (current != NULL) {
            // Overwriting an entry in the indirect table
            g_hash_table_insert(parent->inode_dir_indirect->entries,
                g_strdup(name), g_object_ref(entry));
            parent->inode_dir_indirect_updated = TRUE;
            return;
        }
    }
    // Adding a new entry
    if (g_hash_table_size(parent->inode->directory_data->entries) < INODE_DIR_ENTRIES) {
        g_hash_table_insert(parent->inode->directory_data->entries,
            g_strdup(name), entry);
    } else {
        if (parent->inode_dir_indirect == NULL)
            parent->inode_dir_indirect = g_object_new(THRIFT_TYPE_DIR_DATA_INDIRECT,
                NULL);
        g_hash_table_insert(parent->inode_dir_indirect->entries,
            g_strdup(name), entry);
        parent->inode_dir_indirect_updated = TRUE;
    }
    parent->local.st.st_size++;
}

// Move an item. This modifies the inodes of the directories.
//
// Return FALSE if the item is not in the parent directory.
gboolean fs_metadata_item_update_rename(struct metadata_item* parent,
    const gchar* name, struct metadata_item* newparent, const gchar* newname)
{
    g_return_val_if_fail(parent != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(newparent != NULL, FALSE);
    g_return_val_if_fail(newname != NULL, FALSE);

    gboolean entry_in_indirect = FALSE;
    LOCK_W_INODE(parent);
    GObject* entry = g_hash_table_lookup(
        parent->inode->directory_data->entries, name);
    if (entry == NULL && parent->inode_dir_indirect != NULL) {
        entry = g_hash_table_lookup(parent->inode_dir_indirect->entries, name);
        entry_in_indirect = TRUE;
    }
    if (entry == NULL) {
        UNLOCK_W_INODE(parent);
        errno = ENOENT;
        return FALSE;
    }
    g_object_ref(entry);
    if (entry_in_indirect) {
        g_hash_table_remove(parent->inode_dir_indirect->entries, name);
        // Remove the indirect table if it's got empty
        if (g_hash_table_size(parent->inode_dir_indirect->entries) == 0)
            g_clear_object(&parent->inode_dir_indirect);
        parent->inode_dir_indirect_updated = TRUE;
    } else
        g_hash_table_remove(parent->inode->directory_data->entries, name);

    // Add the entry to the directory diff
    parent->inode_dir_entry_diffs = g_list_prepend(
        parent->inode_dir_entry_diffs,
        create_dir_entry_diff(THRIFT_DIR_ENTRY_DIFF_TYPE_REMOVE, entry, name,
            INODE_MTIME_NOW(parent->meta)));

    // The item may have moved within the same directory
    if (parent == newparent) {
        LOCK_W_LOCAL(parent);
        rename_add_entry_unlocked(parent, newname, entry);
        UNLOCK_W_LOCAL(parent);
        // Add the entry to the directory diff
        parent->inode_dir_entry_diffs = g_list_prepend(
            parent->inode_dir_entry_diffs,
            create_dir_entry_diff(THRIFT_DIR_ENTRY_DIFF_TYPE_ADD, entry, newname,
                INODE_MTIME_NOW(parent->meta)));
        parent->inode_updates++;
    } else {
        LOCK_W_INODE(newparent);
        LOCK_W_LOCAL(newparent);
        rename_add_entry_unlocked(newparent, newname, entry);
        UNLOCK_W_LOCAL(newparent);
        LOCK_W_LOCAL(parent);
        parent->local.st.st_size--;
        UNLOCK_W_LOCAL(parent);
        // Add the entry to the directory diff
        newparent->inode_dir_entry_diffs = g_list_prepend(
            newparent->inode_dir_entry_diffs,
            create_dir_entry_diff(THRIFT_DIR_ENTRY_DIFF_TYPE_ADD, entry, newname,
                INODE_MTIME_NOW(parent->meta)));
        parent->inode_updates++;
        newparent->inode_updates++;
        UNLOCK_W_INODE(newparent);
    }
    UNLOCK_W_INODE(parent);
    return TRUE;
}

// Invalid local cache of an object before it is written to
void fs_metadata_item_update_before_write(struct metadata_item* mi)
{
    LOCK_W_LOCAL(mi);
    invalidate_item_xattr_unlocked(mi, -1);
    UNLOCK_W_LOCAL(mi);
}

// Update local information after a file has been written to.
//
// Return TRUE if this caused local metadata to change.
gboolean fs_metadata_item_update_after_write(struct metadata_item* mi, off_t offset,
    size_t written)
{
    g_return_val_if_fail(mi != NULL, FALSE);

    if (written == 0)
        return FALSE;

    // Keep the bitmasks and stat locked the whole time as these have to match
    LOCK_W_LOCAL(mi);
    size_t size = MAX(mi->local.st.st_size, offset + written);
    if (size > mi->local.st.st_size) {
        mi->local.st.st_size = size;
        set_item_bitmap_size_from_file_size_unlocked(mi, size);
    }
    size_t offset_block = offset / mi->meta->block_size;
    size_t segment_idx = offset_block / BITMAP_SEG_BITS;
    // Maximal number of bits we can fill in the first segment, this
    // depends on the offset
    int max_bits = BITMAP_SEG_BITS - offset_block % BITMAP_SEG_BITS;

    size_t written_blocks = ceil((double)written / mi->meta->block_size);
    while (written_blocks > 0) {
        size_t write_bits = MIN(max_bits, written_blocks);
        // Set the bits of blocks written to and unset the cache bits as these
        // no longer match the inode information
        bitmap_seg_t* write_segment = &BITMAP_SEGMENT_FROM_IDX(
            mi->local.write_bitmap, segment_idx);
        bitmap_seg_t* cache_segment = &BITMAP_SEGMENT_FROM_IDX(
            mi->local.cache_bitmap, segment_idx);
        bitmap_seg_t mask = ((1ULL << write_bits) - 1) << (max_bits - write_bits);
        *write_segment |= mask;
        *cache_segment &= ~mask;
        written_blocks -= write_bits;
        max_bits = BITMAP_SEG_BITS;
        segment_idx++;
    }
    // clang-format off
    mi->local.st.st_atime =
        mi->local.st.st_mtime =
        mi->local.st.st_ctime = fs_current_time() / CONFIG_INDEX_SECS_MULTIPLIER;
    // clang-format on
    mi->local.updates++;
    UNLOCK_W_LOCAL(mi);
    return TRUE;
}

// Store an inode in the DHT.
//
// The inode read lock must be held.
static gboolean store_item_inode_dht_unlocked(struct metadata_item* mi,
    GByteArray* bytes_inode, GError** err)
{
    struct dht_task_group* group = fs_dht_task_group_new();

    // Store the inode
    // TODO: for now we assume this succeeds
    GByteArray* key = fs_sha1_digest_dht_inode(mi->meta->name, mi->inumber);
    fs_dht_add_task(mi->meta->dht,
        fs_dht_create_task_put(key, mi->inode->mtime, bytes_inode),
        TRUE, TRUE, group);
    g_byte_array_unref(key);

    if (mi->meta->model != THRIFT_FILE_SYSTEM_MODEL_PASTIS) {
        // Add inode to the index if we are using it
        gchar name[255];
        g_snprintf(name, sizeof(name), "X:%s:%ld", mi->meta->name, mi->inumber);
        fs_dht_add_task(mi->meta->dht,
            fs_dht_create_task_add(name, bytes_inode, mi->inode->mtime,
                CONFIG_ADD_SEARCH_KEY_MIN, CONFIG_ADD_SEARCH_KEY_MAX),
            TRUE, TRUE, group);

        if (mi->inode_dir_entry_diffs != NULL) {
            g_assert(mi->inode->type == THRIFT_INODE_TYPE_DIRECTORY);

            gchar name[255];
            g_snprintf(name, sizeof(name), "D:%s:%ld", mi->meta->name, mi->inumber);

            // Serialize, store and locally remove all the diffs
            GError* tmp_err = NULL;
            GList* list = mi->inode_dir_entry_diffs;
            while (list != NULL) {
                ThriftDirEntryDiff* diff = THRIFT_DIR_ENTRY_DIFF(list->data);
                GByteArray* bytes_diff = fs_thrift_serialize(
                    THRIFT_STRUCT(diff), &tmp_err);
                if (bytes_diff != NULL) {
                    fs_dht_add_task(mi->meta->dht,
                        fs_dht_create_task_add(name, bytes_diff, diff->mtime,
                            CONFIG_ADD_SEARCH_KEY_MIN, CONFIG_ADD_SEARCH_KEY_MAX),
                        TRUE, TRUE, group);
                    g_byte_array_unref(bytes_diff);
                } else {
                    g_warning("Failed to serialize directory diff: %s",
                        tmp_err->message);
                    g_error_free(tmp_err);
                    tmp_err = NULL;
                }
                list = list->next;
            }
            g_list_free_full(mi->inode_dir_entry_diffs, g_object_unref);
            mi->inode_dir_entry_diffs = NULL;
        }
    }
    fs_dht_task_group_wait(group);
    fs_dht_task_group_unref(group);
    return TRUE;
}

// Store the local item information in the caching storage.
//
// This stores both the inode and cache bitmask, so they must be in sync and
// the inode read lock and local write lock must be held.
static gboolean store_item_cache_unlocked(struct metadata_item* mi,
    GByteArray* bytes_inode, int fd, GError** err)
{
    gboolean close_fd = FALSE;
    if (fd == -1) {
        fd = fs_cache_open_file(mi->meta->cache, mi->inumber,
            O_WRONLY | O_CREAT, err);
        if (fd == -1)
            return FALSE;
        close_fd = TRUE;
    }
    invalidate_item_xattr_unlocked(mi, fd);

    g_debug("Caching inode %ld", mi->inumber);

    guint8 flags = X_FL_VALID;
    // Store type-specific information for the object
    int ret = 0;
    switch (mi->inode->type) {
    case THRIFT_INODE_TYPE_FILE:
        ret = fsetxattr(fd, XATTR_KEY_CACHE_BITMAP,
            mi->local.cache_bitmap->data,
            mi->local.cache_bitmap->len * sizeof(bitmap_seg_t), 0);
        break;
    case THRIFT_INODE_TYPE_SYMLINK:
        ret = fsetxattr(fd, XATTR_KEY_SYMLINK,
            mi->inode->symlink_data->target,
            strlen(mi->inode->symlink_data->target) + 1, 0);
        break;
    default:
        break;
    }
    if (ret != 0)
        goto out;

    // Store the inode
    gboolean store_inode_in_file = FALSE;
    if (bytes_inode->len < mi->meta->xattr_size) {
        ret = fsetxattr(fd, XATTR_KEY_INODE, bytes_inode->data,
            bytes_inode->len, 0);
        if (ret == -1) {
            if (errno != ENOSPC)
                goto out;
            store_inode_in_file = TRUE;
        }
    } else
        store_inode_in_file = TRUE;
    if (store_inode_in_file) {
        // Not enough space in extended attributes, store it in a file
        g_debug("Caching big inode %ld in a file, size: %u",
            mi->inumber, bytes_inode->len);
        int inode_fd = fs_cache_open_inode_file(mi->meta->cache, mi->inumber,
            O_WRONLY | O_CREAT, err);
        if (inode_fd == -1) {
            if (close_fd)
                close(fd);
            return FALSE;
        }
        int written = fs_cache_store_bytes(inode_fd, bytes_inode, 0, err);
        close(inode_fd);
        if (written != bytes_inode->len) {
            if (close_fd)
                close(fd);
            return FALSE;
        }
        flags |= X_FL_INODE_IN_FILE;
    }
    // Finally, mark the stored inode as valid
    guint8 buffer[] = { flags };
    ret = fsetxattr(fd, XATTR_KEY_FLAGS, buffer, 1UL, 0);
out:
    if (ret == 0) {
        g_atomic_int_set(&mi->local.cache_changed, FALSE);
        mi->local.xattr_valid = TRUE;
    } else {
        int save_errno = errno;
        g_set_error_literal(err,
            G_FILE_ERROR,
            g_file_error_from_errno(save_errno),
            g_strerror(save_errno));
    }
    if (close_fd)
        close(fd);

    g_debug("Done caching inode %ld", mi->inumber);
    return (ret == 0);
}

// Store inode of an item in the DHT. The function may return TRUE and still
// set an error if the error is not fatal.
//
// The inode read lock must be held.
static gboolean store_item_inode_unlocked(struct metadata_item* mi, GError** err)
{
    g_debug("Serializing inode %ld", mi->inumber);

    GByteArray* bytes_inode = fs_thrift_serialize(THRIFT_STRUCT(mi->inode), err);
    if (bytes_inode == NULL)
        return FALSE;
    g_debug("Done serializing inode %ld", mi->inumber);

    gboolean ret = store_item_inode_dht_unlocked(mi, bytes_inode, err);
    if (ret && mi->inode->type != THRIFT_INODE_TYPE_DIRECTORY) {
        // If this fails, the inode will still be in the DHT and the local
        // cache should be invalidated
        LOCK_W_LOCAL(mi);
        store_item_cache_unlocked(mi, bytes_inode, -1, err);
        UNLOCK_W_LOCAL(mi);
    }
    g_byte_array_unref(bytes_inode);
    g_debug("Done storing inode %ld", mi->inumber);
    return TRUE;
}

static void write_digest_into_inode_indirect_unlocked(struct metadata_item* mi,
    GByteArray* digest, size_t indirect_idx)
{
    gpointer* indirect_ptr = NULL;
    // Fill the digest directly into the inode
    if (indirect_idx >= mi->inode->file_data->indirect->len)
        g_ptr_array_set_size(mi->inode->file_data->indirect, indirect_idx + 1);
    indirect_ptr = &g_ptr_array_index(
        mi->inode->file_data->indirect,
        indirect_idx);
    *indirect_ptr = digest;
}

static void write_digest_into_inode_unlocked(struct metadata_item* mi,
    GByteArray* digest, size_t block_idx, int64_t* used_indirect_idx)
{
    gpointer* block_ptr = NULL;
    if (block_idx < INODE_BLOCKS) {
        // Fill the digest directly into the inode
        if (block_idx >= mi->inode->file_data->blocks->len)
            g_ptr_array_set_size(mi->inode->file_data->blocks, block_idx + 1);
        block_ptr = &g_ptr_array_index(
            mi->inode->file_data->blocks,
            block_idx);
        *used_indirect_idx = -1;
    } else {
        // Fill the digest into an indirect table instead
        size_t indirect_idx = INDIRECT_IDX_FROM_BLOCK_IDX(block_idx);
        if (mi->inode_indirect == NULL)
            mi->inode_indirect = g_ptr_array_new_with_free_func(g_object_unref);
        if (mi->inode_indirect->len <= indirect_idx)
            g_ptr_array_set_size(mi->inode_indirect, indirect_idx + 1);

        ThriftFileDataIndirect** indirect_ptr
            = (ThriftFileDataIndirect**)&g_ptr_array_index(
                mi->inode_indirect,
                indirect_idx);
        if (*indirect_ptr == NULL)
            *indirect_ptr = g_object_new(THRIFT_TYPE_FILE_DATA_INDIRECT, NULL);
        size_t indirect_offset = INDIRECT_OFFSET_FROM_BLOCK_IDX(block_idx);
        if ((*indirect_ptr)->blocks->len <= indirect_offset)
            g_ptr_array_set_size((*indirect_ptr)->blocks, indirect_offset + 1);

        block_ptr = &g_ptr_array_index((*indirect_ptr)->blocks, indirect_offset);
        // Indicate that we have updated an indirect index
        *used_indirect_idx = indirect_idx;
    }
    *block_ptr = digest;
}

static GByteArray* store_item_indirect_block(struct metadata_item* mi,
    size_t indirect_idx, struct dht_task_group* task_group)
{
    g_debug("Storing indirect block %lu for inode %ld", indirect_idx, mi->inumber);

    LOCK_R_INODE(mi);
    ThriftFileDataIndirect* indirect = g_ptr_array_index(mi->inode_indirect,
        indirect_idx);
    GError* err = NULL;
    GByteArray* block = fs_thrift_serialize(THRIFT_STRUCT(indirect), &err);
    if (block == NULL) {
        UNLOCK_R_INODE(mi);
        g_critical("Failed to serialize indirect block: %s", err->message);
        g_error_free(err);
        return NULL;
    }
    UNLOCK_R_INODE(mi);
    GByteArray* key = fs_sha1_digest_dht_block(block);
    fs_dht_add_task(mi->meta->dht,
        fs_dht_create_task_put(key, -1, block), TRUE, TRUE,
        task_group);
    g_byte_array_unref(block);
    return key;
}

// =======================

// Store file blocks of an item in the DHT
static gboolean store_item_blocks(struct metadata_item* mi, int fd, GError** err)
{
    g_debug("Storing blocks for inode %ld", mi->inumber);

    gboolean close_fd = FALSE;
    if (fd == -1) {
        fd = fs_cache_open_file(mi->meta->cache, mi->inumber, O_RDONLY, err);
        if (fd == -1)
            return FALSE;
        close_fd = TRUE;
    }
    struct metadata* meta = mi->meta;
    struct dht_task_group* task_group = NULL;
    int64_t latest_indirect_idx = -1;

    // clang-format off
#define STORE_INDIRECT_BLOCK(indirect_idx) {                                                                         \
        GByteArray* key                                                       \
            = store_item_indirect_block(mi, indirect_idx, task_group);        \
        if (key != NULL) {                                                    \
            LOCK_W_INODE(mi);                                                 \
            write_digest_into_inode_indirect_unlocked(mi, key, indirect_idx); \
            UNLOCK_W_INODE(mi);                                               \
        }                                                                     \
    }
    // clang-format on

    LOCK_R_LOCAL(mi);
    // Get the current number of segments in the bitmaps; this number may change
    // due to operations in other threads, this is not a problem since the inode
    // won't be written until the last writer closes the file, but we still must
    // be careful as the bitmaps may shrink while we're not holding the local lock
    size_t segment_count = mi->local.write_bitmap->len;
    UNLOCK_R_LOCAL(mi);
    for (size_t i = 0; i < segment_count; i++) {
        LOCK_R_LOCAL(mi);
        if (!BITMAP_HAS_IDX(mi->local.write_bitmap, i)) {
            // Bitmap has shrunk
            UNLOCK_R_LOCAL(mi);
            break;
        }
        bitmap_seg_t* write_segment = &BITMAP_SEGMENT_FROM_IDX(
            mi->local.write_bitmap, i);
        if (*write_segment == 0) {
            // No blocks to store for this segment
            UNLOCK_R_LOCAL(mi);
            continue;
        }
        bitmap_seg_t* cache_segment = &BITMAP_SEGMENT_FROM_IDX(
            mi->local.cache_bitmap, i);
        UNLOCK_R_LOCAL(mi);

        int nth_bit = BITMAP_SEG_BITS;
        while (TRUE) {
            LOCK_W_LOCAL(mi);
            if (!BITMAP_HAS_IDX(mi->local.write_bitmap, i)) {
                // Bitmap has shrunk
                UNLOCK_W_LOCAL(mi);
                break;
            }
            int bit_pos = g_bit_nth_msf(*write_segment, nth_bit);
            if (bit_pos == -1) {
                UNLOCK_W_LOCAL(mi);
                break;
            }
            guint8* data = g_malloc(meta->block_size);
            // Block index is determined by the index of the 32-bit segment and
            // the bit position, which is counted from 0 from the LSF bit
            size_t block_idx = i * BITMAP_SEG_BITS + BITMAP_SEG_BITS - bit_pos - 1;
            size_t size = 0;
            while (size < meta->block_size) {
                // Read up to block_size bytes or until the end of the file
                ssize_t ret = pread(fd, data,
                    meta->block_size - size,
                    block_idx * meta->block_size + size);
                if (ret == -1) {
                    int save_errno = errno;
                    UNLOCK_W_LOCAL(mi);
                    g_set_error_literal(err,
                        G_FILE_ERROR,
                        g_file_error_from_errno(save_errno),
                        g_strerror(save_errno));
                    if (close_fd)
                        close(fd);
                    g_free(data);
                    if (task_group != NULL)
                        fs_dht_task_group_unref(task_group);
                    return FALSE;
                } else if (ret == 0)
                    break;
                size += ret;
            }
            bitmap_seg_t mask = 1ULL << bit_pos;
            *cache_segment |= mask;
            *write_segment &= ~mask;
            UNLOCK_W_LOCAL(mi);

            GByteArray* block = g_byte_array_new_take(data, size);
            GByteArray* key = fs_sha1_digest_dht_block(block);
            // Store block in the DHT
            // TODO: for now we assume this succeeds
            if (task_group == NULL)
                task_group = fs_dht_task_group_new();
            fs_dht_add_task(mi->meta->dht,
                fs_dht_create_task_put(key, -1, block), TRUE, TRUE,
                task_group);
            g_byte_array_unref(block);

            // Store the hash in the inode
            int64_t current_indirect_idx = -1;
            LOCK_W_INODE(mi);
            write_digest_into_inode_unlocked(mi, key, block_idx,
                &current_indirect_idx);
            UNLOCK_W_INODE(mi);

            if (current_indirect_idx != -1
                && latest_indirect_idx != current_indirect_idx) {
                if (latest_indirect_idx != -1) {
                    // We have switch the indirect index, store the current
                    // indirect table
                    STORE_INDIRECT_BLOCK(latest_indirect_idx);
                }
                latest_indirect_idx = current_indirect_idx;
            }
        }
    }
    if (latest_indirect_idx != -1) {
        // Store the last indirect table
        STORE_INDIRECT_BLOCK(latest_indirect_idx);
    }
#undef STORE_INDIRECT_BLOCK
    if (close_fd)
        close(fd);

    // Wait for the DHT to finish writing the blocks
    if (task_group != NULL) {
        fs_dht_task_group_wait(task_group);
        fs_dht_task_group_unref(task_group);
    }
    g_debug("Done storing blocks for inode %ld", mi->inumber);
    return TRUE;
}

// Store directory indirect table of an item in the DHT
static gboolean store_item_dir_indirect(struct metadata_item* mi, GError** err)
{
    // The indirect table might have changed by being removed
    if (mi->inode_dir_indirect == NULL) {
        g_clear_object(&mi->inode_dir_indirect);
        return TRUE;
    }
    g_debug("Storing directory indirect table for inode %ld", mi->inumber);

    LOCK_R_INODE(mi);
    GByteArray* block = fs_thrift_serialize(THRIFT_STRUCT(mi->inode_dir_indirect),
        err);
    if (block == NULL) {
        UNLOCK_R_INODE(mi);
        return FALSE;
    }
    UNLOCK_R_INODE(mi);
    GByteArray* key = fs_sha1_digest_dht_block(block);
    if (!fs_dht_rpc_put(mi->meta->dht, key, -1, block, err)) {
        g_byte_array_unref(block);
        g_byte_array_unref(key);
        return FALSE;
    }
    g_byte_array_unref(block);

    LOCK_W_INODE(mi);
    mi->inode->directory_data->indirect = key;
    mi->inode_dir_indirect_updated = FALSE;
    UNLOCK_W_INODE(mi);
    return TRUE;
}

// Update mode of a file inode
gboolean fs_metadata_item_update_mode(struct metadata_item* mi, mode_t mode)
{
    g_return_val_if_fail(mi != NULL, FALSE);

    LOCK_R_INODE(mi);
    if (mi->inode->type != THRIFT_INODE_TYPE_FILE) {
        UNLOCK_R_INODE(mi);
        return FALSE;
    }
    UNLOCK_R_INODE(mi);

    gboolean ret = FALSE;
    LOCK_W_LOCAL(mi);
    // Add or remove the execute bit, we don't use other parts of the mode
    if (mode & S_IXUSR) {
        if ((mi->local.st.st_mode & S_IXUSR) == 0) {
            mi->local.st.st_mode = COPY_AND_MASK_FILE_MODE(
                mi->local.st.st_mode | S_IXUSR, mi->meta->umask);
            mi->local.updates++;
            ret = TRUE;
        }
    } else {
        if (mi->local.st.st_mode & S_IXUSR) {
            mi->local.st.st_mode = COPY_AND_MASK_FILE_MODE(
                mi->local.st.st_mode & ~S_IXUSR, mi->meta->umask);
            mi->local.updates++;
            ret = TRUE;
        }
    }
    UNLOCK_W_LOCAL(mi);
    return ret;
}

// Update modification time of an inode to be the current time
gboolean fs_metadata_item_update_mtime_now(struct metadata_item* mi)
{
    g_return_val_if_fail(mi != NULL, FALSE);

    LOCK_W_LOCAL(mi);
    time_t t = fs_current_time() / CONFIG_INDEX_SECS_MULTIPLIER;
    gboolean ret = FALSE;
    if (mi->local.st.st_mtime != t) {
        // clang-format off
        mi->local.st.st_atime =
            mi->local.st.st_mtime =
            mi->local.st.st_ctime = t;
        // clang-format on
        mi->local.updates++;
        ret = TRUE;
    }
    UNLOCK_W_LOCAL(mi);
    return ret;
}

// Update file size.
//
// This will invalidate the extended attributes.
gboolean fs_metadata_item_update_size(struct metadata_item* mi, size_t size, int fd,
    GError** err)
{
    g_return_val_if_fail(mi != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    LOCK_W_LOCAL(mi);
    size_t old_size = mi->local.st.st_size;
    // Adjust the bitmaps
    set_item_bitmap_size_from_file_size_unlocked(mi, size);
    gboolean ret = set_item_file_size_unlocked(mi, size, -1, err);
    if (ret) {
        if (mi->inode != NULL) {
            size_t old_blocks = FILE_SIZE_TO_BLOCKS(old_size, mi->meta->block_size);
            size_t new_blocks = FILE_SIZE_TO_BLOCKS(size, mi->meta->block_size);
            if (old_blocks != new_blocks) {
                LOCK_W_INODE(mi);
                // Adjust the number of indirect pointers, this is only needed
                // if we have decreased the number of blocks
                if (mi->inode_indirect != NULL && new_blocks < old_blocks) {
                    size_t indirect_ptrs = INDIRECT_PTRS_FROM_BLOCKS(new_blocks);
                    g_ptr_array_set_size(mi->inode_indirect, indirect_ptrs);

                    // Adjust the number of blocks in the last indirect table
                    if (indirect_ptrs > 0) {
                        ThriftFileDataIndirect* indirect
                            = (ThriftFileDataIndirect*)g_ptr_array_index(
                                mi->inode_indirect,
                                indirect_ptrs - 1);
                        if (indirect != NULL) {
                            size_t last_ptrs = (new_blocks - INODE_BLOCKS) % INODE_INDIRECT_BLOCKS;
                            g_ptr_array_set_size(indirect->blocks, last_ptrs);
                        }
                    }
                }
                g_ptr_array_set_size(mi->inode->file_data->blocks,
                    MIN(INODE_BLOCKS, new_blocks));
                mi->inode_updates++;
                UNLOCK_W_INODE(mi);
            }
        }
        // TODO: we may need to replace the last block in the DHT if it has
        // lost some data; here we simplify by just changing the file size
        // and always reading up to that size; there's an edge case, where
        // the file shrinks and then extends again - in our case, the extended
        // part may contain old data, while it should read zeroes
        mi->local.updates++;
    }
    UNLOCK_W_LOCAL(mi);
    return ret;
}

// Regenerate the inode ID and set mtime to the current time. This function
// should be called whenever an inode is updated.
//
// The inode write lock must be held.
static void update_inode_id_mtime_unlocked(struct metadata_item* mi)
{
    mi->inode->id = fs_random_int64();
    mi->inode->mtime = INODE_MTIME_NOW(mi->meta);
}

// Update inode fields from local information; this does not include file content.
//
// The inode write lock must be held.
static void update_inode_from_local_unlocked(struct metadata_item* mi)
{
    if (mi->inode->type == THRIFT_INODE_TYPE_FILE) {
        LOCK_R_LOCAL(mi);
        if (mi->local.st.st_mode & S_IXUSR)
            mi->inode->flags |= THRIFT_INODE_FLAGS_EXECUTABLE;
        else
            mi->inode->flags &= ~THRIFT_INODE_FLAGS_EXECUTABLE;
        mi->inode->file_data->size = mi->local.st.st_size;

        UNLOCK_R_LOCAL(mi);

        // If the file got smaller, there may be leftover indirect blocks
        if (mi->inode->file_data->indirect != NULL) {
            size_t indirect_ptrs = INDIRECT_PTRS_FROM_FILE_SIZE(mi->inode->file_data->size, mi->meta->block_size);
            g_ptr_array_set_size(mi->inode->file_data->indirect, indirect_ptrs);
        }
    } else if (mi->inode->type == THRIFT_INODE_TYPE_DIRECTORY)
        mi->inode->directory_data->count = mi->local.st.st_size;
}

static gboolean finalize_item(struct metadata_item* mi, GError** err)
{
    LOCK_R_LOCAL(mi);
    LOCK_R_INODE(mi);
    if (mi->local.updates > 0 || mi->inode_updates > 0) {
        g_debug("Finalizing inode %ld", mi->inumber);
        size_t local_updates = mi->local.updates;
        UNLOCK_R_INODE(mi);
        UNLOCK_R_LOCAL(mi);
        switch (mi->inode->type) {
        case THRIFT_INODE_TYPE_FILE:
            // Don't hold an inode lock while sending blocks, this can take a
            // while and none of the operations we allow simultaneously can
            // mess up the block list or file content
            if (!store_item_blocks(mi, -1, err))
                return FALSE;
            break;
        case THRIFT_INODE_TYPE_DIRECTORY:
            if (mi->inode_dir_indirect_updated)
                if (!store_item_dir_indirect(mi, err))
                    return FALSE;
            break;
        default:
            break;
        }
        // Local metadata is more recent than the inode, update the inode
        LOCK_W_INODE(mi);
        update_inode_from_local_unlocked(mi);
        UNLOCK_W_INODE(mi);
        LOCK_R_INODE(mi);
        size_t inode_updates = mi->inode_updates;
        GError* tmp_err = NULL;
        if (!store_item_inode_unlocked(mi, &tmp_err)) {
            UNLOCK_R_INODE(mi);
            g_propagate_error(err, tmp_err);
            return FALSE;
        } else if (tmp_err != NULL) {
            g_warning("Error storing inode %ld: %s", mi->inumber, tmp_err->message);
            g_error_free(tmp_err);
        }
        UNLOCK_R_INODE(mi);
        LOCK_W_INODE(mi);
        // Last know inode ID is only updated from within finalize and refresh
        // which cannot run at the same time
        mi->inode_last_dht_id = mi->inode->id;
        UNLOCK_W_INODE(mi);

        // We substract only the known amount of changes instead of zeroing
        // the counters as updates might have happened while changing from read
        // to write lock; the counters only decrease in this function and
        // we are holding the finalize lock
        LOCK_W_LOCAL(mi);
        mi->local.updates -= local_updates;
        UNLOCK_W_LOCAL(mi);
        LOCK_W_INODE(mi);
        mi->inode_updates -= inode_updates;
        UNLOCK_W_INODE(mi);
        g_debug("Done finalizing inode %ld", mi->inumber);
    } else {
        UNLOCK_R_LOCAL(mi);
        if (mi->inode->type == THRIFT_INODE_TYPE_FILE
            && g_atomic_int_get(&mi->local.used_read_only) == 0
            && g_atomic_int_get(&mi->local.cache_changed)) {
            // Now it's a good time to write inode to the cache
            GByteArray* bytes_inode = fs_thrift_serialize(
                THRIFT_STRUCT(mi->inode), NULL);
            if (bytes_inode != NULL) {
                LOCK_W_LOCAL(mi);
                store_item_cache_unlocked(mi, bytes_inode, -1, NULL);
                UNLOCK_W_LOCAL(mi);
                g_byte_array_unref(bytes_inode);
            }
        }
        UNLOCK_R_INODE(mi);
    }
    return TRUE;
}

gboolean fs_metadata_finalize_flush(struct metadata* meta)
{
    g_return_val_if_fail(meta != NULL, FALSE);
    g_return_val_if_fail(meta->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT, FALSE);

    while (TRUE) {
        GError* err = NULL;
        struct metadata_item* mi = g_queue_pop_tail(meta->finalize_queue);
        if (mi == NULL)
            break;
        if (g_atomic_int_get(&mi->local.used) == 0) {
            LOCK_REFRESH_FINALIZE(mi);
            if (!finalize_item(mi, &err)) {
                g_warning("Failed to finalize inode %ld: %s", mi->inumber,
                    err->message);
                g_error_free(err);
                err = NULL;
            }
            mi->finalize_scheduled = FALSE;
            UNLOCK_REFRESH_FINALIZE(mi);
        }
        fs_metadata_item_unref(mi);
    }
    return TRUE;
}

gboolean fs_metadata_item_update_finalize(struct metadata_item* mi, GError** err)
{
    g_return_val_if_fail(mi != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    if (g_atomic_int_get(&mi->local.used) > 0)
        return TRUE;

    // Only one instance of finalize can run for an item
    LOCK_REFRESH_FINALIZE(mi);
    LOCK_R_LOCAL(mi);
    LOCK_W_INODE(mi);
    // We want the modification time to not to reflect the time of the
    // last modification
    if (mi->local.updates > 0 || mi->inode_updates > 0)
        update_inode_id_mtime_unlocked(mi);
    UNLOCK_W_INODE(mi);
    UNLOCK_R_LOCAL(mi);
    if (mi->meta->model == THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT) {
        if (!mi->finalize_scheduled) {
            g_queue_push_head(mi->meta->finalize_queue, fs_metadata_item_ref(mi));
            mi->finalize_scheduled = TRUE;
        }
        UNLOCK_REFRESH_FINALIZE(mi);
        return TRUE;
    }
    gboolean ret = finalize_item(mi, err);
    UNLOCK_REFRESH_FINALIZE(mi);
    return ret;
}
