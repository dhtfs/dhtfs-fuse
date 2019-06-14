#pragma once

#include <glib.h>

#include "cache.h"
#include "config.h"
#include "dht.h"
#include "event-loop.h"
#include "metadata.h"

struct dhtfs {
    struct cache* cache;
    struct config config;
    struct dht* dht;
    struct metadata* meta;
    struct event_loop* loop;
    gboolean read_only;
    int64_t inception;
};
