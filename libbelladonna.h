#ifndef LIBBELLADONNA_H
#define LIBBELLADONNA_H

#include <libirecovery.h>

typedef void(*belladonna_log_cb)(char* msg);
typedef void(*belladonna_error_cb)(char* error);
typedef void(*belladonna_prog_cb)(unsigned int progress);

void belladonna_error(int line, char* file, char* error);
void belladonna_log(char* msg, ...);
void belladonna_prog(unsigned int progress);

#define BELLADONNA_ERROR(x) belladonna_error(__LINE__, __FILE__, x)



int belladonna_enter_recovery();
void belladonna_set_log_cb(belladonna_log_cb new_cb);
void belladonna_set_error_cb(belladonna_error_cb new_cb);
void belladonna_set_prog_cb(belladonna_prog_cb new_cb);
void belladonna_init();
int belladonna_get_device();
int belladonna_exploit();
int belladonna_boot_tethered();
int belladonna_boot_ramdisk();
int belladonna_restore_ipsw(char* path);
void belladonna_exit();

#endif
