#pragma once

#include <glib.h>

struct event_loop {
    // Private
    GAsyncQueue* queue;
    GThread* thread;
    gatomicrefcount ref_count;
};

struct event_loop* fs_event_loop_new(void);
struct event_loop* fs_event_loop_ref(struct event_loop* loop);
void fs_event_loop_unref(struct event_loop* loop);

void fs_event_loop_add_timer(struct event_loop* loop, GSourceFunc func,
    guint interval, gpointer data);
