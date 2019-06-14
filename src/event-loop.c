#include <glib.h>

#include "event-loop.h"

static gboolean event_loop_queue_watcher(GAsyncQueue* queue)
{
    GSource* source;
    while ((source = g_async_queue_try_pop(queue)) != NULL) {
        g_source_attach(source, g_main_context_get_thread_default());
        g_source_unref(source);
    }
    return G_SOURCE_CONTINUE;
}

static GPrivate context_key;
static GPrivate loop_key;

static gpointer event_loop_thread(gpointer data)
{
    GMainContext* context = g_main_context_new();
    GMainLoop* loop = g_main_loop_new(context, FALSE);

    // Create a source to periodically check whether there is a new request
    // in the queue
    GSource* source = g_timeout_source_new(10);
    g_source_set_callback(source,
        G_SOURCE_FUNC(event_loop_queue_watcher),
        data, NULL);
    g_source_attach(source, context);
    g_source_unref(source);

    g_private_set(&context_key, context);
    g_private_set(&loop_key, loop);
    g_main_context_push_thread_default(context);
    g_main_loop_run(loop);
    // The function will block here until event_loop_stop() is called
    g_main_loop_unref(loop);
    g_main_context_unref(context);
    return NULL;
}

static gboolean event_loop_stop(void)
{
    GMainContext* context = g_private_get(&context_key);
    g_main_context_pop_thread_default(context);

    GMainLoop* loop = g_private_get(&loop_key);
    g_main_loop_quit(loop);
    return FALSE;
}

// Create a new event loop structure and return it
struct event_loop* fs_event_loop_new(void)
{
    struct event_loop* loop;

    loop = g_slice_new(struct event_loop);
    loop->queue = g_async_queue_new();
    loop->thread = g_thread_new("event-loop", event_loop_thread, loop->queue);

    g_atomic_ref_count_init(&loop->ref_count);
    return loop;
}

// Atomically increase reference count
struct event_loop* fs_event_loop_ref(struct event_loop* loop)
{
    g_return_val_if_fail(loop != NULL, NULL);

    g_atomic_ref_count_inc(&loop->ref_count);

    return loop;
}

// Atomically decrease reference count and free the structure once
// the reference count reaches zero
void fs_event_loop_unref(struct event_loop* loop)
{
    g_return_if_fail(loop != NULL);

    if (g_atomic_ref_count_dec(&loop->ref_count)) {
        GSource* source = g_idle_source_new();
        g_source_set_callback(source, G_SOURCE_FUNC(event_loop_stop), NULL, NULL);
        g_async_queue_push(loop->queue, source);
        // Wait for the thread to exit
        g_thread_join(loop->thread);
        g_async_queue_unref(loop->queue);

        g_slice_free(struct event_loop, loop);
    }
}

// Set a function to be called by the event loop loop in the specified interval
// given in milliseconds
void fs_event_loop_add_timer(struct event_loop* loop, GSourceFunc func,
    guint interval, gpointer data)
{
    GSource* source = g_timeout_source_new(interval);

    g_source_set_callback(source, func, data, NULL);
    g_async_queue_push(loop->queue, source);
}
