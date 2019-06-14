#pragma once

#include <glib.h>

#include "dht.h"

#include "thrift/thrift_metadata_types.h"

ThriftFileSystem* fs_dht_get_fs_description(struct dht* dht, const gchar* fs_name,
    GError** err);

ThriftInode* fs_dht_get_inode(struct dht* dht, const gchar* fs_name, int64_t inumber,
    GError** err);
ThriftInode* fs_dht_get_inode_latest_max(struct dht* dht, const gchar* fs_name,
    int64_t inumber, int64_t timestamp_max, GError** err);

GPtrArray* fs_dht_get_dir_diffs(struct dht* dht, const gchar* fs_name,
    int64_t inumber, int64_t mtime, int64_t range_delta, GError** err);
