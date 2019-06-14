SUBDIRS = thrift

AM_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -DG_LOG_DOMAIN=\"dhtfs\" \
	$(FUSE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(THRIFT_CFLAGS)

bin_PROGRAMS = dhtfs-fuse

dhtfs_fuse_SOURCES = \
	cache.c \
	cache.h \
	config.c \
	config.h \
	dht.c \
	dht.h \
	event-loop.c \
	event-loop.h \
	dht-utils.c \
	dht-utils.h \
	utils.c \
	utils.h \
	metadata.c \
	metadata.h \
	dhtfs.c \
	dhtfs.h

dhtfs_fuse_LDADD = $(srcdir)/thrift/libdhtfs-thrift.a \
	$(FUSE_LIBS) \
	$(GLIB_LIBS) \
	$(THRIFT_LIBS)
