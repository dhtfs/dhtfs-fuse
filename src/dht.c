#include <glib.h>

#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/protocol/thrift_compact_protocol.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_framed_transport.h>
#include <thrift/c_glib/transport/thrift_socket.h>

#include "config.h"
#include "dht.h"
#include "utils.h"

#include "thrift/thrift_rpc.h"
#include "thrift/thrift_rpc_types.h"

// Number of threads in the thread pool
#define POOL_THREAD_COUNT 20
// Maximal number of tasks added to the thread pool queue
#define POOL_MAX_PENDING 15

#define CONN_STASH_SIZE 5
#define CONN_STASH_SIZE_LOCAL 2

// After how many seconds we remove unused connections
#define CONN_STASH_STALE_TIMEOUT 2

#define SHA1_DIGEST_LEN 20

static GQuark _dht_peer_quark = 0;
static GQuark _dht_time_quark = 0;
static GQuark _dht_socket_quark = 0;
static GQuark _dht_transport_quark = 0;
static GQuark _dht_protocol_quark = 0;

GQuark dht_error_quark(void)
{
    return g_quark_from_static_string("dht-error-quark");
}

static void task_runner(gpointer data, gpointer user_data);

// Remove stale clients from the given stash
static int remove_stale_clients_stash(GQueue* stash)
{
    int removed = 0;

    GList* list = stash->head;
    if (list != NULL) {
        gint64 curr_time = g_get_monotonic_time() / G_USEC_PER_SEC;
        while (list != NULL) {
            GList* next = g_list_next(list);
            GObject* client = G_OBJECT(list->data);
            gint64 client_time = (gint64)g_object_get_qdata(
                client,
                _dht_time_quark);
            if ((curr_time - client_time) > CONN_STASH_STALE_TIMEOUT) {
                g_object_unref(client);
                g_queue_delete_link(stash, list);
                removed++;
            }
            list = next;
        }
    }
    return removed;
}

// GSourceFunc to remove stale clients
static gboolean remove_stale_clients_source(gpointer data)
{
    int removed = 0;

    struct dht* dht = data;
    g_mutex_lock(&dht->conn_stash_lock);
    removed += remove_stale_clients_stash(dht->conn_stash);
    g_mutex_unlock(&dht->conn_stash_lock);

    g_mutex_lock(&dht->conn_stash_local_lock);
    removed += remove_stale_clients_stash(dht->conn_stash_local);
    g_mutex_unlock(&dht->conn_stash_local_lock);

    if (removed > 0)
        g_debug("Removed %d stale clients", removed);

    return TRUE;
}

// Create a new DHT structure with the given entry peer and return it
struct dht* fs_dht_new(const gchar* host, int port)
{
    g_return_val_if_fail(host != NULL, NULL);

    if (_dht_peer_quark == 0)
        _dht_peer_quark = g_quark_from_static_string("dht-peer");
    if (_dht_time_quark == 0)
        _dht_time_quark = g_quark_from_static_string("dht-time");
    if (_dht_socket_quark == 0)
        _dht_socket_quark = g_quark_from_static_string("dht-socket");
    if (_dht_transport_quark == 0)
        _dht_transport_quark = g_quark_from_static_string("dht-transport");
    if (_dht_protocol_quark == 0)
        _dht_protocol_quark = g_quark_from_static_string("dht-protocol");

    struct dht* dht;

    dht = g_slice_new0(struct dht);
    dht->host = g_strdup(host);
    dht->port = port;
    dht->pool = g_thread_pool_new(
        task_runner,
        dht,
        POOL_THREAD_COUNT, FALSE, NULL);
    dht->key_map = g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
        (GDestroyNotify)g_bytes_unref,
        (GDestroyNotify)g_ptr_array_unref);
    dht->loop = fs_event_loop_new();

    dht->conn_stash = g_queue_new();
    dht->conn_stash_local = g_queue_new();

    g_cond_init(&dht->cond);
    g_mutex_init(&dht->lock);
    g_mutex_init(&dht->key_map_lock);
    g_mutex_init(&dht->conn_stash_lock);
    g_mutex_init(&dht->conn_stash_local_lock);
#ifdef BENCHMARK
    g_mutex_init(&dht->benchmark.lock);
#endif
    fs_event_loop_add_timer(dht->loop,
        remove_stale_clients_source,
        1000, dht);

    g_atomic_ref_count_init(&dht->ref_count);
    return dht;
}

// Atomically increase reference count
struct dht* fs_dht_ref(struct dht* dht)
{
    g_return_val_if_fail(dht != NULL, NULL);

    g_atomic_ref_count_inc(&dht->ref_count);

    return dht;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_dht_unref(struct dht* dht)
{
    g_return_if_fail(dht != NULL);

    if (g_atomic_ref_count_dec(&dht->ref_count)) {
        fs_event_loop_unref(dht->loop);
        g_thread_pool_free(dht->pool, TRUE, TRUE);
        g_free(dht->host);
        g_cond_clear(&dht->cond);
        g_mutex_clear(&dht->lock);
        g_mutex_clear(&dht->key_map_lock);
        g_mutex_clear(&dht->conn_stash_lock);
        g_mutex_clear(&dht->conn_stash_local_lock);
#ifdef BENCHMARK
        g_mutex_clear(&dht->benchmark.lock);
#endif
        g_queue_free_full(dht->conn_stash, g_object_unref);
        g_queue_free_full(dht->conn_stash_local, g_object_unref);
        g_hash_table_unref(dht->key_map);

        g_slice_free(struct dht, dht);
    }
}

// Set a user-specified callback which will be called when the DHT task
// is finished.
//
// The callback must call fs_dht_task_join() to retrieve the result of
// the operation and free the task data.
void fs_dht_task_set_callback(struct dht_task* task, fs_dht_task_callback callback,
    gpointer user_data)
{
    g_return_if_fail(task != NULL);

    task->callback = callback;
    task->callback_data = user_data;
}

// Run the given task in the DHT's thread pool.
//
// When the task is finished, it will call the user-specified callback. If no
// callback has been specified, the task will be joined implicitly. Implicit
// join will however leak memory if the task result is heap-allocated.
void fs_dht_add_task(struct dht* dht, struct dht_task* task, gboolean wait_if_full,
    gboolean implicit_join, struct dht_task_group* group)
{
    g_return_if_fail(task != NULL);
    g_return_if_fail(task->state.done == FALSE);

    dht = fs_dht_ref(dht);
    if (!g_atomic_pointer_compare_and_exchange(&task->dht, NULL, dht)) {
        // Already added to pool
        fs_dht_unref(dht);
        g_return_if_reached();
    }
    g_mutex_lock(&dht->lock);
    if (wait_if_full) {
        while (dht->pending_tasks > POOL_MAX_PENDING)
            g_cond_wait(&dht->cond, &dht->lock);
    }
    dht->pending_tasks++;
    g_mutex_unlock(&dht->lock);

    if (group != NULL) {
        task->group = fs_dht_task_group_ref(group);
        g_mutex_lock(&group->lock);
        group->tasks++;
        g_mutex_unlock(&group->lock);
    }
    task->implicit_join = implicit_join;
    GError* err = NULL;
    if (!g_thread_pool_push(dht->pool, task, &err)) {
        // From glib: An error can only occur when a new thread couldn't be
        // created. In that case data is simply appended to the queue of work
        // to do.
        g_warning("Error while adding DHT task to pool: %s", err->message);
        g_error_free(err);
    }
}

// Retrieve the result of the task, setting the given error if the operation
// resulted in an error.
//
// This function can be called from the user-specified callback in which case
// in returns immediately; if called before the operation is finished, it
// blocks until the operation completes.
//
// The task must not be used after calling this function.
gpointer fs_dht_task_join(struct dht_task* task, GError** err)
{
    g_return_val_if_fail(task != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    g_mutex_lock(&task->lock);
    while (!task->state.done)
        g_cond_wait(&task->cond, &task->lock);
    g_mutex_unlock(&task->lock);

    g_assert(task->state.done == TRUE);

    if (task->state.err != NULL)
        g_propagate_error(err, task->state.err);

    return task->state.result;
}

// Create a new task group structure and return it
struct dht_task_group* fs_dht_task_group_new(void)
{
    struct dht_task_group* group;

    group = g_slice_new(struct dht_task_group);
    group->tasks = 0;

    g_cond_init(&group->cond);
    g_mutex_init(&group->lock);

    g_atomic_ref_count_init(&group->ref_count);
    return group;
}

// Atomically increase reference count
struct dht_task_group* fs_dht_task_group_ref(struct dht_task_group* group)
{
    g_return_val_if_fail(group != NULL, NULL);

    g_atomic_ref_count_inc(&group->ref_count);

    return group;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_dht_task_group_unref(struct dht_task_group* group)
{
    g_return_if_fail(group != NULL);

    if (g_atomic_ref_count_dec(&group->ref_count)) {
        g_cond_clear(&group->cond);
        g_mutex_clear(&group->lock);

        g_slice_free(struct dht_task_group, group);
    }
}

// Wait until all tasks in the group are joined
void fs_dht_task_group_wait(struct dht_task_group* group)
{
    g_return_if_fail(group != NULL);

    g_mutex_lock(&group->lock);
    while (group->tasks > 0)
        g_cond_wait(&group->cond, &group->lock);
    g_mutex_unlock(&group->lock);
}

static void clear_client_qdata(GObject* client)
{
    g_object_set_qdata(client, _dht_peer_quark, NULL);
    g_object_set_qdata(client, _dht_socket_quark, NULL);
    g_object_set_qdata(client, _dht_transport_quark, NULL);
    g_object_set_qdata(client, _dht_protocol_quark, NULL);
}

static ThriftRpcIf*
conn_pool_create_client(struct dht* dht, const gchar* host, int port, GError** err)
{
    GObject* socket = g_object_new(THRIFT_TYPE_SOCKET,
        "hostname", host,
        "port", port,
        NULL);
    ThriftTransport* transport = g_object_new(THRIFT_TYPE_FRAMED_TRANSPORT,
        "transport", socket,
        NULL);

    // Connect to the server
    if (!thrift_transport_open(transport, err)) {
        g_object_unref(socket);
        g_object_unref(transport);
        return NULL;
    }
    GObject* protocol = g_object_new(THRIFT_TYPE_COMPACT_PROTOCOL,
        "transport", transport,
        NULL);
    GObject* client = g_object_new(THRIFT_TYPE_RPC_CLIENT,
        "input_protocol", protocol,
        "output_protocol", protocol,
        NULL);

    // Associate the address of the peer and connection time with the object
    g_object_set_qdata_full(client,
        _dht_peer_quark,
        g_strdup_printf("%s:%d", host, port),
        g_free);
    g_object_set_qdata_full(client,
        _dht_socket_quark,
        socket,
        g_object_unref);
    g_object_set_qdata_full(client,
        _dht_transport_quark,
        transport,
        g_object_unref);
    g_object_set_qdata_full(client,
        _dht_protocol_quark,
        protocol,
        g_object_unref);
    // Thrift doesn't call the parent finalize function and so we need to free
    // the qdata manually
    g_object_weak_ref(client, (GWeakNotify)clear_client_qdata, client);

    return THRIFT_RPC_IF(client);
}

static ThriftRpcIf*
conn_pool_get_client(struct dht* dht, const gchar* host, int port, GError** err)
{
    gchar client_peer[64];
    g_snprintf(client_peer, sizeof(client_peer), "%s:%d", host, port);

    ThriftRpcIf* client = NULL;

    g_mutex_lock(&dht->conn_stash_lock);
    GList* item = dht->conn_stash->tail;
    while (item != NULL) {
        // Pick the first peer from the tail which matches the host and port
        const gchar* peer = g_object_get_qdata(G_OBJECT(item->data), _dht_peer_quark);
        if (g_strcmp0(peer, client_peer) == 0) {
            client = item->data;
            g_queue_delete_link(dht->conn_stash, item);
            break;
        }
        item = item->prev;
    }
    g_mutex_unlock(&dht->conn_stash_lock);

    if (client == NULL) {
        // Create a new connection if there isn't one in the stash
        client = conn_pool_create_client(dht, host, port, err);
    }
    return client;
}

static ThriftRpcIf* conn_pool_get_local_client(struct dht* dht, GError** err)
{
    g_mutex_lock(&dht->conn_stash_local_lock);
    // This queue only includes connections to the local peer
    ThriftRpcIf* client = g_queue_pop_tail(dht->conn_stash_local);
    g_mutex_unlock(&dht->conn_stash_local_lock);

    if (client == NULL) {
        // Create a new connection if there isn't one in the stash
        client = conn_pool_create_client(dht, dht->host, dht->port, err);
    }
    return client;
}

static void stash_client(GQueue* stash, ThriftRpcIf* client)
{
    while (g_queue_get_length(stash) >= CONN_STASH_SIZE) {
        GObject* old_client = g_queue_pop_tail(stash);
        g_object_unref(old_client);
    }
    g_object_set_qdata(G_OBJECT(client),
        _dht_time_quark,
        (gpointer)(g_get_monotonic_time() / G_USEC_PER_SEC));

    g_queue_push_head(stash, client);
}

static void conn_pool_stash_client(struct dht* dht, ThriftRpcIf* client)
{
    g_mutex_lock(&dht->conn_stash_lock);
    stash_client(dht->conn_stash, client);
    g_mutex_unlock(&dht->conn_stash_lock);
}

static void conn_pool_stash_local_client(struct dht* dht, ThriftRpcIf* client)
{
    g_mutex_lock(&dht->conn_stash_local_lock);
    stash_client(dht->conn_stash_local, client);
    g_mutex_unlock(&dht->conn_stash_local_lock);
}

static struct dht_task* task_new(fs_dht_task_func func, gpointer data)
{
    struct dht_task* task;

    task = g_slice_new0(struct dht_task);
    task->func = func;
    task->data = data;

    g_mutex_init(&task->lock);
    g_cond_init(&task->cond);
    return task;
}

static void task_free(struct dht_task* task)
{
    g_mutex_clear(&task->lock);
    g_cond_clear(&task->cond);

    // Error is propagated and therefore freed in join
    // if (task->state.err != NULL)
    //     g_error_free(task->state.err);

    if (task->dht != NULL)
        fs_dht_unref(task->dht);
    if (task->group != NULL)
        fs_dht_task_group_unref(task->group);

    g_slice_free(struct dht_task, task);
}

static void task_runner(gpointer data, gpointer user_data)
{
    struct dht_task* task = data;

    task->func(task);

    g_mutex_lock(&task->lock);
    // Mark the task as done, the fs_dht_task_join() function might be
    // waiting for this
    task->state.done = TRUE;
    g_cond_signal(&task->cond);
    g_mutex_unlock(&task->lock);

    if (task->callback != NULL)
        task->callback(task, task->callback_data);
    else if (task->implicit_join)
        fs_dht_task_join(task, NULL);

    struct dht* dht = user_data;

    g_mutex_lock(&dht->lock);
    // Decrease the number of tasks and resume the potential waits
    // in fs_dht_add_task()
    dht->pending_tasks--;
    g_cond_broadcast(&dht->cond);
    g_mutex_unlock(&dht->lock);

    if (task->group != NULL) {
        g_mutex_lock(&task->group->lock);
        // Decrease the number of tasks and resume the potential waits
        // in fs_dht_task_group_wait()
        task->group->tasks--;
        g_cond_broadcast(&task->group->cond);
        g_mutex_unlock(&task->group->lock);
    }
    task_free(task);
}

#define KEY_MAP_LIMIT 1000
#define KEY_MAP_REMOVE_OVERFLOW 100

// Call the FindClosestPeers(key) RPC and return a list of up to K nodes
GPtrArray* fs_dht_rpc_find_closest_peers(struct dht* dht, GByteArray* key, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(key != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

    if (key->len != SHA1_DIGEST_LEN) {
        g_warning("Invalid length of DHT key: %d", key->len);
        return NULL;
    }
    GBytes* bytes = g_bytes_new(key->data, key->len);
    g_mutex_lock(&dht->key_map_lock);
    GPtrArray* peers = g_hash_table_lookup(dht->key_map, bytes);
    g_mutex_unlock(&dht->key_map_lock);
    if (peers == NULL) {
        ThriftRpcIf* client = conn_pool_get_local_client(dht, err);
        if (client == NULL) {
            g_bytes_unref(bytes);
            return NULL;
        }
        peers = g_ptr_array_new_with_free_func(g_object_unref);
        if (thrift_rpc_client_find_closest_peers(client, &peers, key, err)) {
            g_mutex_lock(&dht->key_map_lock);
            if (g_hash_table_size(dht->key_map) >= KEY_MAP_LIMIT) {
                GHashTableIter iter;
                int removed = 0;
                g_hash_table_iter_init(&iter, dht->key_map);
                while (g_hash_table_iter_next(&iter, NULL, NULL)) {
                    g_hash_table_iter_remove(&iter);
                    if (++removed == KEY_MAP_REMOVE_OVERFLOW)
                        break;
                }
            }
            g_hash_table_insert(dht->key_map, bytes, peers);
            g_mutex_unlock(&dht->key_map_lock);
        } else {
            g_ptr_array_unref(peers);
            peers = NULL;
        }
        conn_pool_stash_local_client(dht, client);
    } else
        g_bytes_unref(bytes);
    if (peers != NULL)
        return g_ptr_array_ref(peers);

    return NULL;
}

static GPtrArray* find_closest_peers_checked(struct dht* dht, GByteArray* key,
    GError** err)
{
    GPtrArray* peers = fs_dht_rpc_find_closest_peers(dht, key, err);
    if (peers != NULL && peers->len == 0) {
        // No peers are known, we don't treat this as an error here
        g_ptr_array_unref(peers);
        peers = NULL;
    }
    return peers;
}

// Find DHT key using the FindKey(name, search_key) operation
static GByteArray* find_key(struct dht* dht, const gchar* name, int64_t search_key,
    GPtrArray** peers, GError** err)
{
    ThriftRpcIf* client = conn_pool_get_local_client(dht, err);
    if (client == NULL)
        return NULL;
    GByteArray* key = NULL;
    ThriftStorageException* excp = NULL;
    if (!thrift_rpc_client_find_key(client, &key, name, search_key, &excp, err)) {
        if (excp != NULL) {
            g_warning("FindKey(%s) exception: %s",
                name,
                excp->error_message);
            g_object_unref(excp);
        }
        conn_pool_stash_local_client(dht, client);
        return NULL;
    }
    conn_pool_stash_local_client(dht, client);

    GError* tmp_err = NULL;
    GPtrArray* peers_ = find_closest_peers_checked(dht, key, &tmp_err);
    if (peers_ == NULL) {
        if (tmp_err != NULL)
            g_propagate_error(err, tmp_err);
        else
            g_set_error(err, DHT_ERROR, DHT_ERROR_NO_PEERS, "no peers to contact");
        g_byte_array_unref(key);
        return NULL;
    }
    *peers = peers_;
    return key;
}

// Call the Add(key, value, ...) RPC and return TRUE if the value was successfully
// stored on at least one peer
gboolean fs_dht_rpc_add(struct dht* dht, const gchar* name, GByteArray* value,
    int64_t search_key, int64_t search_key_min, int64_t search_key_max, GError** err)
{
    g_return_val_if_fail(dht != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(value != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

    ThriftBucketValue* bucket_value = g_object_new(THRIFT_TYPE_BUCKET_VALUE,
        "search_key", search_key,
        "value", value,
        NULL);

#define FIND_KEY_TRIES 100

#ifdef BENCHMARK
    u_int64_t b_start = fs_current_time();
#endif
    gboolean stored = FALSE;
    int wrong_key_tries = 0;
    while (TRUE) {
        GPtrArray* peers = NULL;
        GByteArray* key = find_key(dht, name, search_key, &peers, err);
        if (key == NULL)
            break;

        gboolean wrong_key = FALSE;
        for (int i = 0; i < peers->len; i++) {
            ThriftPeer* peer = g_ptr_array_index(peers, i);
            ThriftRpcIf* peer_client = conn_pool_get_client(dht,
                peer->host,
                peer->port, NULL);
            if (peer_client == NULL) {
                // Couldn't connect to one of the peers, this is not fatal
                continue;
            }
            GError* peer_err = NULL;
            ThriftStorageException* peer_excp = NULL;
            g_debug("Add() @ %s:%d", peer->host, peer->port);
            if (thrift_rpc_client_add(peer_client, key, bucket_value, name,
                    search_key_min,
                    search_key_max, &peer_excp, &peer_err))
                stored = TRUE;
            else {
                if (peer_excp != NULL) {
                    g_warning("Peer %s:%d exception: %s",
                        peer->host,
                        peer->port,
                        peer_excp->error_message);
                    if (peer_excp->error_code == DHT_PEER_ERROR_ADD_WRONG_KEY) {
                        wrong_key = TRUE;
                        wrong_key_tries++;
                        g_object_unref(peer_excp);
                        conn_pool_stash_client(dht, peer_client);
                        break;
                    }
                    g_object_unref(peer_excp);
                } else if (peer_err != NULL) {
                    g_warning("Add() @ %s:%d: %s",
                        peer->host,
                        peer->port,
                        peer_err->message);
                    g_error_free(peer_err);
                }
            }
            if (stored)
                g_debug("Done Add() @ %s:%d", peer->host, peer->port);
            conn_pool_stash_client(dht, peer_client);
        }
        g_ptr_array_unref(peers);
        g_byte_array_unref(key);
        if (!wrong_key)
            break;
        if (wrong_key_tries >= FIND_KEY_TRIES) {
            g_critical("Giving up finding a key for %s after %d attempts",
                name, FIND_KEY_TRIES);
            break;
        }
    }
    g_object_unref(bucket_value);
#ifdef BENCHMARK
    u_int64_t b_end = fs_current_time();
    g_mutex_lock(&dht->benchmark.lock);
    dht->benchmark.t_add += b_end - b_start;
    dht->benchmark.c_add++;
    dht->benchmark.t_total += b_end - b_start;
    dht->benchmark.c_total++;
    g_mutex_unlock(&dht->benchmark.lock);
#endif
    return stored;
}

struct task_data_add {
    GByteArray* value;
    gchar* name;
    int64_t search_key;
    int64_t search_key_min;
    int64_t search_key_max;
};

static void task_func_add(struct dht_task* task)
{
    struct task_data_add* task_data = task->data;

    gboolean ret = fs_dht_rpc_add(task->dht,
        task_data->name,
        task_data->value,
        task_data->search_key,
        task_data->search_key_min,
        task_data->search_key_max, &task->state.err);

    task->state.result = GINT_TO_POINTER(ret);

    g_free(task_data->name);
    g_byte_array_unref(task_data->value);
    g_slice_free(struct task_data_add, task_data);
}

// Create an asynchronous task for Add(key, value, ...)
struct dht_task* fs_dht_create_task_add(const gchar* name, GByteArray* value,
    int64_t search_key, int64_t search_key_min, int64_t search_key_max)
{
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(value != NULL, NULL);

    struct task_data_add* data = g_slice_new(struct task_data_add);
    data->name = g_strdup(name);
    data->value = g_byte_array_ref(value);
    data->search_key = search_key;
    data->search_key_min = search_key_min;
    data->search_key_max = search_key_max;

    return task_new(task_func_add, data);
}

// Call the Get(key) RPC and return the value as a byte array.
//
// If the key is not found, the function returns NULL without setting an error.
GByteArray* fs_dht_rpc_get(struct dht* dht, GByteArray* key, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(key != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

#ifdef BENCHMARK
    u_int64_t b_start = fs_current_time();
#endif
    GPtrArray* peers = find_closest_peers_checked(dht, key, err);
    if (peers == NULL)
        return NULL;

    GByteArray* data = NULL;
    for (int i = 0; i < peers->len; i++) {
        ThriftPeer* peer = g_ptr_array_index(peers, i);
        ThriftRpcIf* peer_client = conn_pool_get_client(dht,
            peer->host,
            peer->port, NULL);
        if (peer_client == NULL) {
            // Couldn't connect to one of the peers, this is not fatal
            continue;
        }
        GError* peer_err = NULL;
        ThriftStorageException* peer_excp = NULL;
        if (thrift_rpc_client_get(peer_client, &data, key, &peer_excp, &peer_err)) {
            g_debug("Get() found @ %s:%d", peer->host, peer->port);
            conn_pool_stash_client(dht, peer_client);
            break;
        } else {
            if (peer_excp != NULL) {
                if (peer_excp->error_code == DHT_PEER_ERROR_NOT_FOUND)
                    ;
                else
                    g_warning("Peer %s:%d exception: %s",
                        peer->host,
                        peer->port,
                        peer_excp->error_message);
                g_object_unref(peer_excp);
            } else if (peer_err != NULL) {
                g_warning("Get() from %s:%d: %s",
                    peer->host,
                    peer->port,
                    peer_err->message);
                g_error_free(peer_err);
            }
            conn_pool_stash_client(dht, peer_client);
        }
    }
#ifdef BENCHMARK
    u_int64_t b_end = fs_current_time();
    g_mutex_lock(&dht->benchmark.lock);
    dht->benchmark.t_get += b_end - b_start;
    dht->benchmark.c_get++;
    dht->benchmark.t_total += b_end - b_start;
    dht->benchmark.c_total++;
    g_mutex_unlock(&dht->benchmark.lock);
#endif
    g_ptr_array_unref(peers);
    return data;
}

static void task_func_get(struct dht_task* task)
{
    GByteArray* key = task->data;

    task->state.result = fs_dht_rpc_get(task->dht,
        key,
        &task->state.err);
    g_byte_array_unref(key);
}

// Create an asynchronous task for Get(key)
struct dht_task* fs_dht_create_task_get(GByteArray* key)
{
    g_return_val_if_fail(key != NULL, NULL);

    return task_new(task_func_get, g_byte_array_ref(key));
}

// Call the GetLatestMax(key, search_key) RPC and return the value.
//
// If the key is not found, the function returns NULL without setting an error.
GByteArray* fs_dht_rpc_get_latest_max(struct dht* dht, const gchar* name,
    int64_t search_key_max, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

#ifdef BENCHMARK
    u_int64_t b_start = fs_current_time();
#endif
    ThriftRpcIf* client = conn_pool_get_local_client(dht, err);
    if (client == NULL)
        return NULL;

    // Thrift requires this object preallocated
    ThriftBucketValue* data = g_object_new(THRIFT_TYPE_BUCKET_VALUE, NULL);
    ThriftStorageException* excp = NULL;
    g_debug("GetLatestMax(%s, %ld)", name, search_key_max);
    if (thrift_rpc_client_get_latest_max(client, &data, name,
            search_key_max, &excp, err))
        g_debug("Done GetLatestMax(%s, %ld)", name, search_key_max);
    else {
        if (excp != NULL) {
            g_warning("GetLatestMax(%s, %ld) exception: %s",
                name,
                search_key_max,
                excp->error_message);
            g_object_unref(excp);
        }
        conn_pool_stash_local_client(dht, client);
        g_object_unref(data);
        data = NULL;
        return NULL;
    }
#ifdef BENCHMARK
    u_int64_t b_end = fs_current_time();
    g_mutex_lock(&dht->benchmark.lock);
    dht->benchmark.t_get_latest_max += b_end - b_start;
    dht->benchmark.c_get_latest_max++;
    dht->benchmark.t_total += b_end - b_start;
    dht->benchmark.c_total++;
    g_mutex_unlock(&dht->benchmark.lock);
#endif
    conn_pool_stash_local_client(dht, client);

    GByteArray* result = NULL;
    if (data != NULL && data->value != NULL) {
        result = g_byte_array_ref(data->value);
        g_object_unref(data);
    }
    return result;
}

struct task_data_get_latest_max {
    gchar* name;
    int64_t search_key_max;
};

static void task_func_get_latest_max(struct dht_task* task)
{
    struct task_data_get_latest_max* task_data = task->data;

    task->state.result = fs_dht_rpc_get_latest_max(task->dht,
        task_data->name,
        task_data->search_key_max,
        &task->state.err);

    g_free(task_data->name);
    g_slice_free(struct task_data_get_latest_max, task_data);
}

// Create an asynchronous task for GetLatestMax(key, search_key)
struct dht_task* fs_dht_create_task_get_latest_max(const gchar* name,
    int64_t search_key_max)
{
    g_return_val_if_fail(name != NULL, NULL);

    struct task_data_get_latest_max* data = g_slice_new(struct task_data_get_latest_max);
    data->name = g_strdup(name);
    data->search_key_max = search_key_max;

    return task_new(task_func_get_latest_max, data);
}

// Call the GetRange(name, search_key_min, search_key_max) RPC and return the value.
//
// If the key is not found, the function returns NULL without setting an error.
GPtrArray* fs_dht_rpc_get_range(struct dht* dht, const gchar* name,
    int64_t search_key_min, int64_t search_key_max, GError** err)
{
    g_return_val_if_fail(dht != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(err == NULL || *err == NULL, NULL);

#ifdef BENCHMARK
    u_int64_t b_start = fs_current_time();
#endif
    ThriftRpcIf* client = conn_pool_get_local_client(dht, err);
    if (client == NULL)
        return NULL;

    GPtrArray* data = g_ptr_array_new_with_free_func(g_object_unref);

    g_debug("GetRange(%s, %ld, %ld)", name, search_key_min, search_key_max);
    if (thrift_rpc_client_get_range(client, &data, name, search_key_min,
            search_key_max, err))
        g_debug("Done GetRange(%s, %ld, %ld)", name, search_key_min, search_key_max);
    else {
        g_ptr_array_unref(data);
        data = NULL;
    }
#ifdef BENCHMARK
    u_int64_t b_end = fs_current_time();
    g_mutex_lock(&dht->benchmark.lock);
    dht->benchmark.t_get_range += b_end - b_start;
    dht->benchmark.c_get_range++;
    dht->benchmark.t_total += b_end - b_start;
    dht->benchmark.c_total++;
    g_mutex_unlock(&dht->benchmark.lock);
#endif
    conn_pool_stash_local_client(dht, client);
    return data;
}

struct task_data_get_range {
    gchar* name;
    int64_t search_key_min;
    int64_t search_key_max;
};

static void task_func_get_range(struct dht_task* task)
{
    struct task_data_get_range* task_data = task->data;

    task->state.result = fs_dht_rpc_get_range(task->dht,
        task_data->name,
        task_data->search_key_min,
        task_data->search_key_max, &task->state.err);

    g_free(task_data->name);
    g_slice_free(struct task_data_get_range, task_data);
}

// Create an asynchronous task for GetRange(name, search_key_min, search_key_max)
struct dht_task* fs_dht_create_task_get_range(const gchar* name,
    int64_t search_key_min, int64_t search_key_max)
{
    g_return_val_if_fail(name != NULL, NULL);

    struct task_data_get_range* data = g_slice_new(struct task_data_get_range);
    data->name = g_strdup(name);
    data->search_key_min = search_key_min;
    data->search_key_max = search_key_max;

    return task_new(task_func_get_range, data);
}

// Call the Put(key, value) or PutLatest(key, search_key, value) RPC and return TRUE
// if the value was successfully stored on at least one peer
gboolean fs_dht_rpc_put(struct dht* dht, GByteArray* key, int64_t search_key,
    GByteArray* value, GError** err)
{
    g_return_val_if_fail(dht != NULL, FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(value != NULL, FALSE);
    g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

#ifdef BENCHMARK
    u_int64_t b_start = fs_current_time();
#endif
    GError* tmp_err = NULL;
    GPtrArray* peers = find_closest_peers_checked(dht, key, &tmp_err);
    if (peers == NULL) {
        if (tmp_err != NULL)
            g_propagate_error(err, tmp_err);
        else
            g_set_error(err, DHT_ERROR, DHT_ERROR_NO_PEERS, "no peers to contact");
        return FALSE;
    }
    gboolean stored = FALSE;
    for (int i = 0; i < peers->len; i++) {
        ThriftPeer* peer = g_ptr_array_index(peers, i);
        ThriftRpcIf* peer_client = conn_pool_get_client(dht,
            peer->host,
            peer->port, NULL);
        if (peer_client == NULL) {
            // Couldn't connect to one of the peers, this is not fatal
            continue;
        }
        GError* peer_err = NULL;
        g_debug("Put() @ %s:%d", peer->host, peer->port);
        gboolean ret;
        if (search_key > 0)
            ret = thrift_rpc_client_put_latest(peer_client, key, search_key,
                value, &peer_err);
        else
            ret = thrift_rpc_client_put(peer_client, key, value, &peer_err);
        if (ret)
            stored = TRUE;
        else {
            g_warning("Put() @ %s:%d: %s",
                peer->host,
                peer->port,
                peer_err->message);
            g_error_free(peer_err);
        }
        g_debug("Done Put() @ %s:%d", peer->host, peer->port);
        conn_pool_stash_client(dht, peer_client);
    }
#ifdef BENCHMARK
    u_int64_t b_end = fs_current_time();
    g_mutex_lock(&dht->benchmark.lock);
    dht->benchmark.t_put += b_end - b_start;
    dht->benchmark.c_put++;
    dht->benchmark.t_total += b_end - b_start;
    dht->benchmark.c_total++;
    g_mutex_unlock(&dht->benchmark.lock);
#endif
    g_ptr_array_unref(peers);
    return stored;
}

struct task_data_put {
    GByteArray* key;
    int64_t search_key;
    GByteArray* value;
};

static void task_func_put(struct dht_task* task)
{
    struct task_data_put* task_data = task->data;

    gboolean ret = fs_dht_rpc_put(task->dht,
        task_data->key,
        task_data->search_key,
        task_data->value, &task->state.err);

    task->state.result = GINT_TO_POINTER(ret);

    g_byte_array_unref(task_data->key);
    g_byte_array_unref(task_data->value);
    g_slice_free(struct task_data_put, task_data);
}

// Create an asynchronous task for Put(key, value)
struct dht_task* fs_dht_create_task_put(GByteArray* key, int64_t search_key,
    GByteArray* value)
{
    g_return_val_if_fail(key != NULL, NULL);
    g_return_val_if_fail(value != NULL, NULL);

    struct task_data_put* data = g_slice_new(struct task_data_put);
    data->key = g_byte_array_ref(key);
    data->search_key = search_key;
    data->value = g_byte_array_ref(value);

    return task_new(task_func_put, data);
}
