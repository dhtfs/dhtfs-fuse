#include <glib-object.h>
#include <glib.h>

#include "config.h"
#include "dht-utils.h"
#include "dht.h"
#include "utils.h"

#include "thrift/thrift_metadata_types.h"

// Retrieve file system description from the DHT
ThriftFileSystem* fs_dht_get_fs_description(struct dht* dht, const gchar* fs_name,
    GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(fs_name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    ThriftFileSystem* fs = NULL;
    GByteArray* key = fs_sha1_digest("F:%s", fs_name);
    GByteArray* ret = fs_dht_rpc_get(dht, key, err);
    if (ret != NULL) {
        fs = g_object_new(THRIFT_TYPE_FILE_SYSTEM, NULL);
        if (!fs_thrift_unserialize(ret, THRIFT_STRUCT(fs), err))
            g_clear_object(&fs);
        g_byte_array_unref(ret);
    }
    g_byte_array_unref(key);
    return fs;
}

// Retrieve an inode from the DHT
ThriftInode* fs_dht_get_inode(struct dht* dht, const gchar* fs_name,
    int64_t inumber, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(fs_name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    ThriftInode* inode = NULL;
    GByteArray* key = fs_sha1_digest("I:%s:%ld", fs_name, inumber);
    GByteArray* ret = fs_dht_rpc_get(dht, key, err);
    if (ret != NULL) {
        inode = g_object_new(THRIFT_TYPE_INODE, NULL);
        if (!fs_thrift_unserialize(ret, THRIFT_STRUCT(inode), err))
            g_clear_object(&inode);
        g_byte_array_unref(ret);
    }
    g_byte_array_unref(key);
    return inode;
}

// Retrieve the latest version of an inode with an upper-bound on the search key
ThriftInode* fs_dht_get_inode_latest_max(struct dht* dht, const gchar* fs_name,
    int64_t inumber, int64_t timestamp_max, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(fs_name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    gchar name[255];
    g_snprintf(name, sizeof(name), "X:%s:%ld", fs_name, inumber);

    GByteArray* ret = fs_dht_rpc_get_latest_max(dht, name, timestamp_max, err);
    ThriftInode* inode = NULL;
    if (ret != NULL) {
        inode = g_object_new(THRIFT_TYPE_INODE, NULL);
        if (!fs_thrift_unserialize(ret, THRIFT_STRUCT(inode), err))
            g_clear_object(&inode);
        g_byte_array_unref(ret);
    }
    return inode;
}

// Retrieve directory diffs for the given inode and modification time
GPtrArray* fs_dht_get_dir_diffs(struct dht* dht, const gchar* fs_name,
    int64_t inumber, int64_t mtime, int64_t range_delta, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(fs_name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    gchar name[255];
    g_snprintf(name, sizeof(name), "D:%s:%ld", fs_name, inumber);
    if (range_delta <= 0)
        range_delta = CONFIG_DIR_DIFFS_RANGE_DELTA;
    GPtrArray* ret = fs_dht_rpc_get_range(dht, name, mtime - range_delta, mtime, err);
    return ret;
}
