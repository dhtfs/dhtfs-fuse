#define _GNU_SOURCE

#include <time.h>

#include <glib.h>
#include <glib/gprintf.h>

#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/thrift_struct.h>
#include <thrift/c_glib/transport/thrift_fd_transport.h>
#include <thrift/c_glib/transport/thrift_memory_buffer.h>

#define SHA1_DIGEST_LEN 20

// Compare byte arrays and return TRUE if they match
gboolean fs_compare_byte_arrays(GByteArray* array1, GByteArray* array2)
{
    g_return_val_if_fail(array1 != NULL, FALSE);
    g_return_val_if_fail(array2 != NULL, FALSE);

    if (array1 == array2)
        return TRUE;
    if (array1->len != array2->len)
        return FALSE;

    return memcmp(array1->data, array2->data, array1->len) == 0;
}

// Return the current system time in milliseconds
u_int64_t fs_current_time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        return (u_int64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    else
        return 0;
}

// Generate a random 64-bit integer
int64_t fs_random_int64(void)
{
    return ~(1ULL << 63) & (((u_int64_t)g_random_int() << 32) | g_random_int());
}

// Compute SHA1 digest of the given string and return it as byte array
GByteArray* fs_sha1_digest(const gchar* format, ...)
{
    g_return_val_if_fail(format != NULL, NULL);

    va_list args;
    va_start(args, format);

    gchar str[1024];
    if (g_vsnprintf(str, sizeof(str), format, args) >= sizeof(str))
        g_warn_if_reached();

    va_end(args);

    GChecksum* checksum = g_checksum_new(G_CHECKSUM_SHA1);
    g_checksum_update(checksum, (const guchar*)str, -1);

    gsize size = SHA1_DIGEST_LEN;
    guint8* digest = g_malloc(size);
    g_checksum_get_digest(checksum, digest, &size);
    g_checksum_free(checksum);

    return g_byte_array_new_take(digest, size);
}

// Compute SHA1 DHT key for the given byte array
GByteArray* fs_sha1_digest_dht_block(GByteArray* block)
{
    g_return_val_if_fail(block != NULL, NULL);

    gchar* block_cksum = g_compute_checksum_for_data(G_CHECKSUM_SHA1,
        block->data,
        block->len);

    GByteArray* digest = fs_sha1_digest("B:%s", block_cksum);
    g_free(block_cksum);

    return digest;
}

// Compute SHA1 DHT key for the given inode
GByteArray* fs_sha1_digest_dht_inode(const gchar* fs_name, int64_t inumber)
{
    g_return_val_if_fail(fs_name != NULL, NULL);

    return fs_sha1_digest("I:%s:%ld", fs_name, inumber);
}

static gboolean thrift_serialize(ThriftStruct* object, ThriftProtocol* protocol,
    GError** err)
{
    GError* tmp_err = NULL;
    thrift_struct_write(object, protocol, &tmp_err);
    if (tmp_err != NULL) {
        g_propagate_error(err, tmp_err);
        return FALSE;
    }
    return TRUE;
}

// Serialize a Thrift structure into a byte array
GByteArray* fs_thrift_serialize(ThriftStruct* object, GError** err)
{
    g_return_val_if_fail(THRIFT_IS_STRUCT(object), NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    GByteArray* buffer = g_byte_array_new();

    ThriftTransport* transport = g_object_new(THRIFT_TYPE_MEMORY_BUFFER,
        "buf", buffer,
        "owner", FALSE,
        NULL);
    ThriftProtocol* protocol = g_object_new(THRIFT_TYPE_BINARY_PROTOCOL,
        "transport", transport,
        NULL);

    gboolean ret = thrift_serialize(object, protocol, err);
    g_object_unref(protocol);
    g_object_unref(transport);
    if (!ret) {
        g_byte_array_free(buffer, TRUE);
        return NULL;
    }
    return buffer;
}

// Serialize a Thrift structure into an open file
gboolean fs_thrift_serialize_fd(ThriftStruct* object, int fd, GError** err)
{
    g_return_val_if_fail(THRIFT_IS_STRUCT(object), FALSE);
    g_return_val_if_fail(fd >= 0, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    ThriftTransport* transport = g_object_new(THRIFT_TYPE_FD_TRANSPORT,
        "fd", fd,
        NULL);
    ThriftProtocol* protocol = g_object_new(THRIFT_TYPE_BINARY_PROTOCOL,
        "transport", transport,
        NULL);

    gboolean ret = thrift_serialize(object, protocol, err);
    g_object_unref(protocol);
    g_object_unref(transport);
    return ret;
}

static gboolean thrift_unserialize(ThriftStruct* object, ThriftProtocol* protocol,
    GError** err)
{
    GError* tmp_err = NULL;
    thrift_struct_read(object, protocol, &tmp_err);
    if (tmp_err != NULL) {
        g_propagate_error(err, tmp_err);
        return FALSE;
    }
    return TRUE;
}

// Unserialize a Thrift structure from a byte array into the given object
gboolean fs_thrift_unserialize(GByteArray* buffer, ThriftStruct* object, GError** err)
{
    g_return_val_if_fail(buffer != NULL, FALSE);
    g_return_val_if_fail(THRIFT_IS_STRUCT(object), FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    ThriftTransport* transport = g_object_new(THRIFT_TYPE_MEMORY_BUFFER,
        "buf", buffer,
        "owner", FALSE,
        NULL);
    ThriftProtocol* protocol = g_object_new(THRIFT_TYPE_BINARY_PROTOCOL,
        "transport", transport,
        NULL);

    gboolean ret = thrift_unserialize(object, protocol, err);
    g_object_unref(protocol);
    g_object_unref(transport);
    return ret;
}

// Unserialize a Thrift structure from an open file into the given object
gboolean fs_thrift_unserialize_fd(int fd, ThriftStruct* object, GError** err)
{
    g_return_val_if_fail(fd >= 0, FALSE);
    g_return_val_if_fail(THRIFT_IS_STRUCT(object), FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    ThriftTransport* transport = g_object_new(THRIFT_TYPE_FD_TRANSPORT,
        "fd", fd,
        NULL);
    ThriftProtocol* protocol = g_object_new(THRIFT_TYPE_BINARY_PROTOCOL,
        "transport", transport,
        NULL);

    gboolean ret = thrift_unserialize(object, protocol, err);
    g_object_unref(protocol);
    g_object_unref(transport);
    return ret;
}
