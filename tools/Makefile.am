AM_CFLAGS = $(GLOBAL_CFLAGS) $(libfragmentzip_CFLAGS) $(zlib_CFLAGS) $(libzip_CFLAGS) $(libirecovery_CFLAGS) $(libimobiledevice_CFLAGS) $(libplist_CFLAGS) $(openssl_CFLAGS) $(libcurl_CFLAGS) $(PTHREAD_CFLAGS)
AM_LDFLAGS = $(libfragmentzip_LIBS) $(zlib_LIBS) $(libzip_LIBS) $(libirecovery_LIBS) $(libimobiledevice_LIBS) $(libplist_LIBS) $(openssl_LIBS) $(libcurl_LIBS) $(PTHREAD_CLIBS)

if DARWIN
AM_CFLAGS += -mmacosx-version-min=10.10
endif 

noinst_PROGRAMS = belladonna
belladonna_CFLAGS = -I../src $(AM_CFLAGS)
belladonna_LDADD = ../src/libbelladonna.a $(AM_LDFLAGS)
belladonna_SOURCES = belladonna.c
