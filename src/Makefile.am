AM_CFLAGS = $(GLOBAL_CFLAGS) $(libfragmentzip_CFLAGS) $(zlib_CFLAGS) $(libzip_CFLAGS) $(libirecovery_CFLAGS) $(libimobiledevice_CFLAGS) $(libplist_CFLAGS) $(openssl_CFLAGS) $(libcurl_CFLAGS) $(PTHREAD_CFLAGS)

SUBDIRS = exploits/checkm8/payload

noinst_LIBRARIES = libbelladonna.a

idevicerestore = idevicerestore/idevicerestore.c idevicerestore/common.c idevicerestore/tss.c idevicerestore/fls.c idevicerestore/mbn.c idevicerestore/img3.c idevicerestore/img4.c idevicerestore/ftab.c idevicerestore/ipsw.c idevicerestore/normal.c idevicerestore/dfu.c idevicerestore/recovery.c idevicerestore/restore.c idevicerestore/asr.c idevicerestore/fdr.c idevicerestore/limera1n.c idevicerestore/download.c idevicerestore/locking.c idevicerestore/socket.c idevicerestore/thread.c idevicerestore/jsmn.c idevicerestore/json_plist.c
exploits = exploits/exploits.c exploits/checkm8/checkm8.c exploits/checkm8/payload_gen.c

libbelladonna_INCLUDES = -I./idevicerestore -I./exploits -I./exploits/checkm8 -I./exploits/checkm8/payload

libbelladonna_a_CFLAGS = $(libbelladonna_INCLUDES) $(AM_CFLAGS) -DIDEVICERESTORE_NOMAIN=1

libbelladonna_a_SOURCES = $(idevicerestore) $(exploits) libbelladonna.c