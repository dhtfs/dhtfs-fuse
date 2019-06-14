#pragma once

#include <glib.h>

#include "config.h"
#include "event-loop.h"

// Error codes used in the RPC by StorageException
enum {
    DHT_PEER_ERROR_NOT_FOUND = 404,
    DHT_PEER_ERROR_ADD_WRONG_KEY = 500
};

struct dht {
    gchar* host;
    int port;

    // Private fields
    struct event_loop* loop;
    int pending_tasks;
    GThreadPool* pool;
    GHashTable* key_map;
    GMutex lock;
    GMutex key_map_lock;
    GCond cond;
    GQueue* conn_stash;
    GQueue* conn_stash_local;
    GMutex conn_stash_lock;
    GMutex conn_stash_local_lock;
    struct {
        u_int64_t c_add;
        u_int64_t c_get;
        u_int64_t c_get_latest_max;
        u_int64_t c_get_range;
        u_int64_t c_put;
        u_int64_t c_total;
        u_int64_t t_add;
        u_int64_t t_get;
        u_int64_t t_get_latest_max;
        u_int64_t t_get_range;
        u_int64_t t_put;
        u_int64_t t_total;
        GMutex lock;
    } benchmark;
    gatomicrefcount ref_count;
};

struct dht_task_group {
    // Private fields
    int tasks;
    GMutex lock;
    GCond cond;
    gatomicrefcount ref_count;
};

struct dht_task;

typedef void (*fs_dht_task_func)(struct dht_task* task);

typedef void (*fs_dht_task_callback)(struct dht_task* task, gpointer user_data);

struct dht_task {
    struct dht* dht;

    // Private fields
    struct dht_task_group* group;
    gboolean implicit_join;
    fs_dht_task_func func;
    gpointer data;
    fs_dht_task_callback callback;
    gpointer callback_data;
    GMutex lock;
    GCond cond;
    struct {
        gboolean done;
        GError* err;
        gpointer result;
    } state;
};

// Custom GError
#define DHT_ERROR dht_error_quark()
enum {
    DHT_ERROR_NO_PEERS
};

// DHT API
struct dht* fs_dht_new(const gchar* host, int port);
struct dht* fs_dht_ref(struct dht* dht);
void fs_dht_unref(struct dht* dht);
void fs_dht_add_task(struct dht* dht, struct dht_task* task, gboolean wait_if_full,
    gboolean implicit_join, struct dht_task_group* group);

// DHT task API
void fs_dht_task_set_callback(struct dht_task* task, fs_dht_task_callback callback,
    gpointer user_data);
gpointer fs_dht_task_join(struct dht_task* task, GError** err);

// DHT task group API
struct dht_task_group* fs_dht_task_group_new(void);
struct dht_task_group* fs_dht_task_group_ref(struct dht_task_group* group);
void fs_dht_task_group_unref(struct dht_task_group* group);
void fs_dht_task_group_wait(struct dht_task_group* group);

// DHT operations
GPtrArray* fs_dht_rpc_find_closest_peers(struct dht* dht, GByteArray* key,
    GError** err);
gboolean fs_dht_rpc_add(struct dht* dht, const gchar* name, GByteArray* value,
    int64_t search_key, int64_t search_key_min, int64_t search_key_max, GError** err);
GByteArray* fs_dht_rpc_get(struct dht* dht, GByteArray* key, GError** err);
GByteArray* fs_dht_rpc_get_latest_max(struct dht* dht, const gchar* name,
    int64_t search_key_max, GError** err);
GPtrArray* fs_dht_rpc_get_range(struct dht* dht, const gchar* name,
    int64_t search_key_min, int64_t search_key_max, GError** err);
gboolean fs_dht_rpc_put(struct dht* dht, GByteArray* key, int64_t search_key,
    GByteArray* value, GError** err);

struct dht_task* fs_dht_create_task_add(const gchar* name, GByteArray* value,
    int64_t search_key, int64_t search_key_min, int64_t search_key_max);
struct dht_task* fs_dht_create_task_get(GByteArray* key);
struct dht_task* fs_dht_create_task_get_latest_max(const gchar* name,
    int64_t search_key_max);
struct dht_task* fs_dht_create_task_get_range(const gchar* name,
    int64_t search_key_min, int64_t search_key_max);
struct dht_task* fs_dht_create_task_put(GByteArray* key, int64_t search_key,
    GByteArray* value);
