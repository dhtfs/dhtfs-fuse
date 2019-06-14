#pragma once

#include <glib.h>

#include <thrift/c_glib/thrift_struct.h>

gboolean fs_compare_byte_arrays(GByteArray* array1, GByteArray* array2);
u_int64_t fs_current_time();
int64_t fs_random_int64(void);

GByteArray* fs_sha1_digest(const gchar* format, ...);
GByteArray* fs_sha1_digest_dht_block(GByteArray* block);
GByteArray* fs_sha1_digest_dht_inode(const gchar* fs_name, int64_t inumber);

GByteArray* fs_thrift_serialize(ThriftStruct* object, GError** err);
gboolean fs_thrift_serialize_fd(ThriftStruct* object, int fd, GError** err);

gboolean fs_thrift_unserialize(GByteArray* buffer, ThriftStruct* object, GError** err);
gboolean fs_thrift_unserialize_fd(int fd, ThriftStruct* object, GError** err);
