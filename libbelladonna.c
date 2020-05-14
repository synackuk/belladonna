#include <libbelladonna.h>
#include <libirecovery.h>
#include <device_loaders.h>
#include <libfragmentzip/libfragmentzip.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <idevicerestore/idevicerestore.h>
#include <exploits/exploits.h>

#ifdef WIN32
#include <windows.h>
#endif

#ifdef __APPLE__
#include <limits.h>
#include <sysdir.h>
#include <wordexp.h>
#endif

static irecv_client_t dev = NULL;
static belladonna_log_cb belladonna_log_handler = NULL;
static belladonna_error_cb belladonna_error_handler = NULL;
static belladonna_prog_cb belladonna_prog_handler = NULL;

static unsigned char* hooker = NULL;
static unsigned char* atropine = NULL;
static size_t hooker_length = 0;
static size_t atropine_length = 0;

static void default_log_cb(char* msg) {
	printf("%s", msg);
}

static void default_error_cb(char* msg) {
	fprintf(stderr, "Error: %s\n", msg);
}

static void default_prog_cb(unsigned int progress) {

	if(progress < 0) {
		return;
	}

	if(progress > 100) {
		progress = 100;
	}

	printf("\r[");

	for(unsigned int i = 0; i < 50; i++) {
		if(i < progress / 2) {
			printf("=");
		} else {
			printf(" ");
		}
	}

	printf("] %3.1d%%", progress);

	fflush(stdout);

	if(progress == 100) {
		printf("\n");
	}
}

static char* get_application_directory() {
#ifdef __APPLE__
	struct stat status;
	char path[PATH_MAX];
	sysdir_search_path_enumeration_state state = sysdir_start_search_path_enumeration(SYSDIR_DIRECTORY_APPLICATION_SUPPORT, SYSDIR_DOMAIN_MASK_USER);
	state = sysdir_get_next_search_path_enumeration(state, path);
	wordexp_t exp_result;
	wordexp(path, &exp_result, 0);
	bzero(path, PATH_MAX);
	for(size_t i = 0; i < exp_result.we_wordc; i += 1) {
		strncat(path, exp_result.we_wordv[i], PATH_MAX);
		if(i + 1 != exp_result.we_wordc) {
			strncat(path, " ", PATH_MAX);
		}
	}
	wordfree(&exp_result);
	strncat(path, "/n1ghtshade/", PATH_MAX);
	if (stat(path, &status) != 0) { 
		mkdir(path, 0700);
	}

	return strdup(path);
#elif
	return NULL;
#endif
}
static int read_file_into_buffer(char* path, char** buf, size_t* len) {
	FILE* f = fopen(path, "rb");
	if(!f) {
		return -1;
	}
	fseek(f, 0, SEEK_END);
	*len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if(!*len) {
		return -1;
	}

	*buf = malloc(*len);
	if(!*buf) {
		return -1;
	}
	fread(*buf, 1, *len, f);
	fclose(f);
	return 0;
}

void belladonna_set_log_cb(belladonna_log_cb new_cb) {
	belladonna_log_handler = new_cb;
}

void belladonna_set_err_cb(belladonna_error_cb new_cb) {
	belladonna_error_handler = new_cb;
}

void belladonna_set_prog_cb(belladonna_prog_cb new_cb) {
	belladonna_prog_handler = new_cb;
}

void belladonna_init() {
#ifdef __APPLE__
	system("killall -9 iTunesHelper 2> /dev/null");
	system("kill -STOP $(pgrep AMPDeviceDiscoveryAgent) 2> /dev/null"); // TY Siguza
#endif
	belladonna_set_log_cb(&default_log_cb);
	belladonna_set_err_cb(&default_error_cb);
	belladonna_set_prog_cb(&default_prog_cb);
	exploits_init();
}

void belladonna_exit() {
	if(dev){
		irecv_close(dev);
		dev = NULL;
	}
	belladonna_set_log_cb(NULL);
	belladonna_set_err_cb(NULL);
	belladonna_set_prog_cb(NULL);
	exploits_exit();
}

void belladonna_log(char* msg, ...) {
	va_list args;
	va_start(args, msg);
	char* log;
	vasprintf(&log, msg, args);
	va_end(args);
	if(!log) { // We're in real trouble...
		belladonna_log_handler("Failed to log message (out of memory).");
		return;
	}
	belladonna_log_handler(log);
	free(log);
}

void belladonna_error(int line, char* file, char* error) {
	char* msg;
	asprintf(&msg, "Error in %s:%d \"%s\"", file, line, error);
	if(!msg) { // We're in real trouble...
		belladonna_error_handler("Failed to log error (out of memory).");
		return;
	}
	belladonna_error_handler(msg);
	free(msg);
}

void belladonna_prog(unsigned int progress) {
	belladonna_prog_handler(progress);
}

int belladonna_get_device() {
	if(dev) {
		irecv_close(dev);
		dev = NULL;
	}
	irecv_open_with_ecid(&dev, 0);
	if(!dev) {
		return -1;
	}
	int mode = 0;
	irecv_get_mode(dev, &mode);
	if(mode != IRECV_K_DFU_MODE) {
		irecv_close(dev);
		dev = NULL;
		return -1;
	}

	return 0;
}

int belladonna_exploit() {
	int ret;
	const struct irecv_device_info* info = irecv_get_device_info(dev);
	char* pwnd_str = strstr(info->serial_string, "PWND:[");
	if(pwnd_str) {
		return 0;
	}
	exploit_list_t* curr = exploits;
	while(curr != NULL) {
		ret = curr->supported(dev);
		if(ret == 0){
			ret = curr->exploit(dev);
			if(ret != 0) {
				dev = NULL;
				BELLADONNA_ERROR("Failed to enter Pwned DFU mode.");
				return -1;
			}
			irecv_open_with_ecid(&dev, 0);
			if(!dev) {
				BELLADONNA_ERROR("Failed to reconnect to device.");
				return -1;
			}
			return 0;
		}
		curr = curr->next;
	}
	BELLADONNA_ERROR("Device not supported.");
	return -1;
}

static int download_firmware_component(char* ipsw_url, char* component_path, char* out_path) {
	int ret;
	fragmentzip_t *ipsw = fragmentzip_open(ipsw_url);
	if (!ipsw) {
		return -1;
	}
	ret = fragmentzip_download_file(ipsw, component_path, out_path, belladonna_prog);
	
	fragmentzip_close(ipsw);
	
	if(ret != 0) {
		return -1;
	}
	return 0;
}

static int load_ibss(char** ibss, size_t* ibss_len) {
	int ret;
	irecv_device_t device_info = NULL;
	irecv_devices_get_device_by_client(dev, &device_info);
	const char* identifier = device_info->product_type;
	char* ipsw_url = NULL;
	char* ibss_path = NULL;
	char ibss_local_path[PATH_MAX];
	struct stat status;
	int i = 0;
	belladonna_log("Finding iBSS for device\n");
	while(device_loaders[i].identifier != NULL) {
		if(!strcmp(device_loaders[i].identifier, identifier)) {
			ipsw_url = device_loaders[i].ipsw_url;
			ibss_path = device_loaders[i].ibss_path;
			break;
		}
		i += 1;
	}
	if(!ipsw_url || !ibss_path) {
		BELLADONNA_ERROR("Failed to find correct loader for your device.");
		return -1;
	}
	char* application_dir = get_application_directory();
	if(!application_dir) {
		BELLADONNA_ERROR("Failed to get local working directory.");
		return -1;
	}
	strncpy(ibss_local_path, application_dir, PATH_MAX);
	free(application_dir);
	strncat(ibss_local_path, identifier, PATH_MAX);
	strncat(ibss_local_path, ".iBSS.img3", PATH_MAX);
	if(stat(ibss_local_path, &status) != 0) {
		belladonna_log("Downloading iBSS\n");
		ret = download_firmware_component(ipsw_url, ibss_path, ibss_local_path);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download iBSS.");
			return -1;
		}
	}
	ret = read_file_into_buffer(ibss_local_path, ibss, ibss_len);
	if(ret != 0) {
		*ibss = 0;
		*ibss_len = 0;
		BELLADONNA_ERROR("Failed to load iBSS.");
		return -1;
	}
	return 0;
}

static int boot_ibss_checkm8(char* ibss, size_t ibss_len) {
	unsigned char buf[16];
	bzero(buf, 16);
	int ret;
	ret = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, buf, 16, 0);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to send blank packet.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, 0, 0, 0);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to send blank packet.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0xA1, 3, 0, 0, buf, 6, 0);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to request status.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0xA1, 3, 0, 0, buf, 6, 0);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to request status.");
		return -1;
	}
	belladonna_log("Uploading iBSS\n");
	size_t len = 0;
	while(len != ibss_len) {
		size_t size = ((ibss_len - len) > 0x800) ? 0x800 : (ibss_len - len);
		size_t sent = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, (unsigned char*)&ibss[len], size, 0);
		if(sent != size) {
			BELLADONNA_ERROR("Failed to upload iBSS.");
			return -1;
		}
		len += size;
	}
	belladonna_log("Executing iBSS\n");
	irecv_usb_control_transfer(dev, 0xA1, 2, 0xFFFF, 0, buf, 0, 0);
	return 0;
}

static int boot_ibss_normal(char* ibss, size_t ibss_len) {
	int ret;
	belladonna_log("Uploading iBSS\n");
	ret = irecv_send_buffer(dev, (unsigned char*)ibss, ibss_len, 0);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload iBSS.");
		return -1;
	}
	belladonna_log("Executing iBSS\n");
	ret = irecv_finish_transfer(dev);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute iBSS.");
		return -1;
	}
	return 0;
}
static int boot_ibss() {
	int ret;
	char* ibss;
	size_t ibss_len;
	ret = load_ibss(&ibss, &ibss_len);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load iBSS.");
		return -1;
	}
	const struct irecv_device_info* info = irecv_get_device_info(dev);
	char* pwnd_checkm8_str = strstr(info->serial_string, "PWND:[checkm8]");
	if(pwnd_checkm8_str) {
		ret = boot_ibss_checkm8(ibss, ibss_len);
	}
	else {
		ret = boot_ibss_normal(ibss, ibss_len);
	}
	free(ibss);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to boot iBSS.");
		return -1;
	}
	return 0;
}

static int load_ibec(char** ibec, size_t* ibec_len) {
	int ret;
	irecv_device_t device_info = NULL;
	irecv_devices_get_device_by_client(dev, &device_info);
	const char* identifier = device_info->product_type;
	char* ipsw_url = NULL;
	char* ibec_path = NULL;
	char ibec_local_path[PATH_MAX];
	struct stat status;
	int i = 0;
	belladonna_log("Finding iBEC for device\n");
	while(device_loaders[i].identifier != NULL) {
		if(!strcmp(device_loaders[i].identifier, identifier)) {
			ipsw_url = device_loaders[i].ipsw_url;
			ibec_path = device_loaders[i].ibec_path;
			break;
		}
		i += 1;
	}
	if(!ipsw_url || !ibec_path) {
		BELLADONNA_ERROR("Failed to find correct loader for your device.");
		return -1;
	}
	char* application_dir = get_application_directory();
	if(!application_dir) {
		BELLADONNA_ERROR("Failed to get local working directory.");
		return -1;
	}
	strncpy(ibec_local_path, application_dir, PATH_MAX);
	free(application_dir);
	strncat(ibec_local_path, identifier, PATH_MAX);
	strncat(ibec_local_path, ".iBEC.img3", PATH_MAX);
	if(stat(ibec_local_path, &status) != 0) {
		belladonna_log("Downloading iBEC\n");
		ret = download_firmware_component(ipsw_url, ibec_path, ibec_local_path);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download iBEC.");
			return -1;
		}
	}
	ret = read_file_into_buffer(ibec_local_path, ibec, ibec_len);
	if(ret != 0) {
		*ibec = 0;
		*ibec_len = 0;
		BELLADONNA_ERROR("Failed to load iBEC.");
		return -1;
	}
	return 0;
}

static int boot_ibec() {
	int ret;
	char* ibec;
	size_t ibec_len;
	ret = load_ibec(&ibec, &ibec_len);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load iBEC.");
		return -1;
	}
	belladonna_log("Uploading iBEC\n");
	ret = irecv_send_buffer(dev, (unsigned char*)ibec, ibec_len, 0);
	free(ibec);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload iBEC.");
		return -1;
	}
	belladonna_log("Executing iBEC\n");
	ret = irecv_finish_transfer(dev);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute iBEC.");
		return -1;
	}
	return 0;
}

static int load_payload() {
	int ret;
	belladonna_log("Uploading hooker\n");
	ret = irecv_send_buffer(dev, (unsigned char*)hooker, hooker_length, 0);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload iBoot payload.");
		return -1;
	}
	belladonna_log("Executing hooker\n");
	ret = irecv_send_command(dev, "ticket");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute iBoot payload.");
		return -1;
	}
	belladonna_log("Uploading payload\n");
	ret = irecv_send_buffer(dev, (unsigned char*)atropine, atropine_length, 0);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload payload.");
		return -1;
	}
	belladonna_log("Loading payload\n");
	ret = irecv_send_command(dev, "atropine load-payload");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load payload.");
		return -1;
	}
	return 0;
}

int belladonna_enter_recovery() {
	int ret;
	ret = boot_ibss();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to boot iBSS.");
		return -1;
	}
	dev = irecv_reconnect(dev, 2);
	if(!dev) {
		BELLADONNA_ERROR("Failed to reconnect to device.");
		return -1;
	}
	ret = boot_ibec();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to boot iBEC.");
		return -1;
	}
	dev = irecv_reconnect(dev, 2);
	if(!dev) {
		BELLADONNA_ERROR("Failed to boot iBEC.");
		return -1;
	}
	ret = load_payload();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load iBoot payload");
		return -1;
	}
	return 0;
}

int belladonna_boot_tethered() {
	irecv_send_command(dev, "atropine load ibot");
	irecv_send_command(dev, "go");
	return 0;
}
/*
static int load_ramdisk() {
	int ret;
	belladonna_log("Uploading ramdisk\n");
	ret = libloader_send_buffer(dev, (unsigned char*)hyoscine, hyoscine_length);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload ramdisk.");
		return -1;
	}
	belladonna_log("Loading ramdisk\n");
	ret = libloader_send_cmd(dev, "ramdisk");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load ramdisk.");
		return -1;
	}
	return 0;
}

int belladonna_boot_ramdisk() {
	int ret;
	ret = libloader_is_dfu(dev);
	if(ret) {
		BELLADONNA_ERROR("Device isn't in recovery mode.");
		return -1;
	}
	belladonna_log("Setting device tree\n");
	ret = libloader_send_cmd(dev, "atropine load dtre");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load devicetree.");
		return -1;
	}
	ret = libloader_send_cmd(dev, "devicetree");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to set devicetree.");
		return -1;
	}
	ret = load_ramdisk();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load ramdisk.");
		return -1;
	}
	belladonna_log("Patching Kernel\n");
	ret = libloader_send_cmd(dev, "atropine patch krnl");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to patch kernelcache.");
		return -1;
	}
	belladonna_log("Booting kernel\n");
	ret = libloader_send_cmd(dev, "atropine load krnl");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load kernel");
		return -1;
	}
	libloader_send_cmd(dev, "bootx");
	return 0;
}
*/
int belladonna_restore_ipsw(char* path) {
	int ret;
	irecv_close(dev);
	dev = NULL;

	belladonna_log("Restoring device\n");
	
	struct idevicerestore_client_t* client = idevicerestore_client_new();
	if (!client) {
		BELLADONNA_ERROR("Failed to create restore client.");
		return -1;
	}
	client->flags |= FLAG_ERASE;
	client->flags |= FLAG_LATEST_SHSH;
	client->flags |= FLAG_NO_IBEC_UPLOAD;
	client->flags |= FLAG_LATEST_BASEBAND;
	client->flags &= ~FLAG_INTERACTIVE;
	client->ipsw = strdup(path);
	ret = idevicerestore_start(client);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to restore device.");
		return -1;
	}
	idevicerestore_client_free(client);
	
	return 0;
}
