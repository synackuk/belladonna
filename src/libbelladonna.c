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
#include <curl/curl.h>
#include <idevicerestore/idevicerestore.h>
#include <exploits/exploits.h>

#include <payloads/hyoscine.h>

#ifdef WIN32
#include <windows.h>
#endif

#ifdef __APPLE__
#include <limits.h>
#include <sysdir.h>
#include <wordexp.h>
#else
#ifdef __linux__

#include <wordexp.h>
#include <limits.h>

#endif
#endif

#define ATROPINE_DOWNLOAD_URL "https://github.com/synackuk/atropine/releases/latest/download/"

static char* hooker = NULL;
static size_t hooker_length = 0;

static char* atropine = NULL;
static size_t atropine_length = 0;

static irecv_client_t dev = NULL;
static belladonna_log_cb belladonna_log_handler = NULL;
static belladonna_error_cb belladonna_error_handler = NULL;
static belladonna_prog_cb belladonna_prog_handler = NULL;


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
	char path[PATH_MAX] = {0};
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
#else
#ifdef __linux__
	char path[PATH_MAX] = {0};
	wordexp_t exp_result;
	wordexp("~/.n1ghtshade/", &exp_result, 0);
	for(size_t i = 0; i < exp_result.we_wordc; i += 1) {
		strncat(path, exp_result.we_wordv[i], PATH_MAX);
		if(i + 1 != exp_result.we_wordc) {
			strncat(path, " ", PATH_MAX);
		}
	}
	wordfree(&exp_result);
	return strdup(path);
#else
	return NULL;
#endif
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

int belladonna_set_hooker(char* path) {
	return read_file_into_buffer(path, &hooker, &hooker_length);
}

int belladonna_set_atropine(char* path) {
	return read_file_into_buffer(path, &atropine, &atropine_length);
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
	if(!dev) {
		ret = belladonna_get_device();
		if(ret != 0) {
			BELLADONNA_ERROR("No device found.");
			return -1;
		}
	}
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

// Borrowed from idevicerestore

typedef struct {
	int length;
	char* content;
} curl_response;

static size_t download_write_buffer_callback(char* data, size_t size, size_t nmemb, curl_response* response) {
	size_t total = size * nmemb;
	if (total == 0) {
		return total;
	}
	response->content = realloc(response->content, response->length + total + 1);
	memcpy(response->content + response->length, data, total);
	response->content[response->length + total] = '\0';
	response->length += total;
	return total;
}

static int download_to_memory(char* url, char** buf, size_t* length) {
	CURL* handle = curl_easy_init();
	if (!handle) {
		return -1;
	}

	curl_response response;
	response.length = 0;
	response.content = malloc(1);
	response.content[0] = '\0';

	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, (curl_write_callback)&download_write_buffer_callback);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(handle, CURLOPT_URL, url);

	curl_easy_perform(handle);
	curl_easy_cleanup(handle);

	if (response.length < 0) {
		return -1;
	}
	*length = response.length;
	*buf = response.content;
	return 0;
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
	ret = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, buf, 16, 5000);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to send blank packet.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, 0, 0, 5000);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to send blank packet.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0xA1, 3, 0, 0, buf, 6, 5000);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to request status.");
		return -1;
	}
	ret = irecv_usb_control_transfer(dev, 0xA1, 3, 0, 0, buf, 6, 5000);
	if(ret < 0) {
		BELLADONNA_ERROR("Failed to request status.");
		return -1;
	}
	belladonna_log("Uploading iBSS\n");
	size_t len = 0;
	while(len < ibss_len) {
		size_t size = ((ibss_len - len) > 0x800) ? 0x800 : (ibss_len - len);
		size_t sent = irecv_usb_control_transfer(dev, 0x21, 1, 0, 0, (unsigned char*)&ibss[len], size, 5000);
		if(sent != size) {
			BELLADONNA_ERROR("Failed to upload iBSS.");
			return -1;
		}
		len += size;
	}
	belladonna_log("Executing iBSS\n");
	irecv_usb_control_transfer(dev, 0xA1, 2, 0xFFFF, 0, buf, 0, 5000);
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
	int mode = 0;
	irecv_get_mode(dev, &mode);
	if(mode == IRECV_K_DFU_MODE) {
		ret = irecv_finish_transfer(dev);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to execute iBEC.");
			return -1;
		}
	}
	else {
		ret = irecv_send_command(dev, "go");
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to execute iBEC.");
			return -1;
		}
	}

	return 0;
}

static int load_payload() {
	int ret;
	if(!hooker) {
		belladonna_log("Downloading atropine hooker\n");
		ret = download_to_memory(ATROPINE_DOWNLOAD_URL "hooker", &hooker, &hooker_length);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download iBoot payload.");
			return -1;
		}
	}
	belladonna_log("Uploading atropine hooker\n");
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
	if(!atropine) {
		belladonna_log("Downloading atropine\n");
		ret = download_to_memory(ATROPINE_DOWNLOAD_URL "atropine", &atropine, &atropine_length);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download iBoot payload.");
			return -1;
		}
	}
	belladonna_log("Uploading atropine\n");
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
	if(!dev) {
		ret = belladonna_get_device();
		if(ret != 0) {
			BELLADONNA_ERROR("No device found.");
			return -1;
		}
	}
	const struct irecv_device_info* info = irecv_get_device_info(dev);
	char* pwnd_str = strstr(info->serial_string, "PWND:[");
	if(!pwnd_str) {
		ret = belladonna_exploit();
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to put device in pwned DFU mode.");
			return -1;
		}
	}
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
	int ret;
	if(!dev) {
		ret = belladonna_get_device();
		if(ret != 0) {
			BELLADONNA_ERROR("No device found.");
			return -1;
		}
	}
	int mode = 0;
	irecv_get_mode(dev, &mode);
	if(mode == IRECV_K_DFU_MODE) {
		ret = belladonna_enter_recovery();
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to put device in pwned DFU mode.");
			return -1;
		}
	}
	belladonna_log("Loading iBoot\n");
	ret = irecv_send_command(dev, "atropine load ibot");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load iBoot.");
		return -1;
	}
	belladonna_log("Executing iBoot\n");
	ret = irecv_send_command(dev, "go");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute iBoot.");
	}
	return 0;
}

static int load_ramdisk() {
	int ret;
	belladonna_log("Uploading ramdisk\n");
	ret = irecv_send_buffer(dev, (unsigned char*)hyoscine, hyoscine_length, 0);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload ramdisk.");
		return -1;
	}
	belladonna_log("Loading ramdisk\n");
	ret = irecv_send_command(dev, "ramdisk");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load ramdisk.");
		return -1;
	}
	return 0;
}

static int load_devicetree(char** devicetree, size_t* devicetree_len) {
	int ret;
	irecv_device_t device_info = NULL;
	irecv_devices_get_device_by_client(dev, &device_info);
	const char* identifier = device_info->product_type;
	char* ipsw_url = NULL;
	char* devicetree_path = NULL;
	char devicetree_local_path[PATH_MAX];
	struct stat status;
	int i = 0;
	belladonna_log("Finding devicetree for device\n");
	while(device_loaders[i].identifier != NULL) {
		if(!strcmp(device_loaders[i].identifier, identifier)) {
			ipsw_url = device_loaders[i].ipsw_url;
			devicetree_path = device_loaders[i].devicetree_path;
			break;
		}
		i += 1;
	}
	if(!ipsw_url || !devicetree_path) {
		BELLADONNA_ERROR("Failed to find correct loader for your device.");
		return -1;
	}
	char* application_dir = get_application_directory();
	if(!application_dir) {
		BELLADONNA_ERROR("Failed to get local working directory.");
		return -1;
	}
	strncpy(devicetree_local_path, application_dir, PATH_MAX);
	free(application_dir);
	strncat(devicetree_local_path, identifier, PATH_MAX);
	strncat(devicetree_local_path, ".devicetree.img3", PATH_MAX);
	if(stat(devicetree_local_path, &status) != 0) {
		belladonna_log("Downloading devicetree\n");
		ret = download_firmware_component(ipsw_url, devicetree_path, devicetree_local_path);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download devicetree.");
			return -1;
		}
	}
	ret = read_file_into_buffer(devicetree_local_path, devicetree, devicetree_len);
	if(ret != 0) {
		*devicetree = 0;
		*devicetree_len = 0;
		BELLADONNA_ERROR("Failed to load devicetree.");
		return -1;
	}
	return 0;
}


static int execute_device_tree() {
	int ret;
	char* devicetree;
	size_t devicetree_len;
	ret = load_devicetree(&devicetree, &devicetree_len);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load devicetree.");
		return -1;
	}
	belladonna_log("Uploading devicetree\n");
	ret = irecv_send_buffer(dev, (unsigned char*)devicetree, devicetree_len, 0);
	free(devicetree);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload devicetree.");
		return -1;
	}
	belladonna_log("Executing devicetree\n");
	ret = irecv_send_command(dev, "devicetree");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute devicetree.");
		return -1;
	}

	return 0;
}

static int load_kernelcache(char** kernelcache, size_t* kernelcache_len) {
	int ret;
	irecv_device_t device_info = NULL;
	irecv_devices_get_device_by_client(dev, &device_info);
	const char* identifier = device_info->product_type;
	char* ipsw_url = NULL;
	char* kernelcache_path = NULL;
	char kernelcache_local_path[PATH_MAX];
	struct stat status;
	int i = 0;
	belladonna_log("Finding kernel for device\n");
	while(device_loaders[i].identifier != NULL) {
		if(!strcmp(device_loaders[i].identifier, identifier)) {
			ipsw_url = device_loaders[i].ipsw_url;
			kernelcache_path = device_loaders[i].kernelcache_path;
			break;
		}
		i += 1;
	}
	if(!ipsw_url || !kernelcache_path) {
		BELLADONNA_ERROR("Failed to find correct loader for your device.");
		return -1;
	}
	char* application_dir = get_application_directory();
	if(!application_dir) {
		BELLADONNA_ERROR("Failed to get local working directory.");
		return -1;
	}
	strncpy(kernelcache_local_path, application_dir, PATH_MAX);
	free(application_dir);
	strncat(kernelcache_local_path, identifier, PATH_MAX);
	strncat(kernelcache_local_path, ".kernelcache.img3", PATH_MAX);
	if(stat(kernelcache_local_path, &status) != 0) {
		belladonna_log("Downloading kernelcache\n");
		ret = download_firmware_component(ipsw_url, kernelcache_path, kernelcache_local_path);
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to download kernel.");
			return -1;
		}
	}
	ret = read_file_into_buffer(kernelcache_local_path, kernelcache, kernelcache_len);
	if(ret != 0) {
		*kernelcache = 0;
		*kernelcache_len = 0;
		BELLADONNA_ERROR("Failed to load kernel.");
		return -1;
	}
	return 0;
}


static int boot_kernel() {
	int ret;
	char* kernelcache;
	size_t kernelcache_len;
	ret = load_kernelcache(&kernelcache, &kernelcache_len);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load kernel.");
		return -1;
	}
	belladonna_log("Uploading kernel\n");
	ret = irecv_send_buffer(dev, (unsigned char*)kernelcache, kernelcache_len, 0);
	free(kernelcache);
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to upload kernelcache.");
		return -1;
	}
	belladonna_log("Executing kernel\n");
	ret = irecv_send_command(dev, "bootx");
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute kernel.");
		return -1;
	}

	return 0;
}

int belladonna_boot_ramdisk() {
	int ret;
	if(!dev) {
		ret = belladonna_get_device();
		if(ret != 0) {
			BELLADONNA_ERROR("No device found.");
			return -1;
		}
	}
	int mode = 0;
	irecv_get_mode(dev, &mode);
	if(mode == IRECV_K_DFU_MODE) {
		ret = belladonna_enter_recovery();
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to put device in pwned DFU mode.");
			return -1;
		}
	}
	ret = boot_ibec();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to reload iBEC.");
		return -1;
	}
	dev = irecv_reconnect(dev, 2);
	if(!dev) {
		BELLADONNA_ERROR("Failed to reload iBEC.");
		return -1;
	}
	ret = execute_device_tree();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to execute devicetree.");
		return -1;
	}
	ret = load_ramdisk();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to load ramdisk.");
		return -1;
	}
	ret = boot_kernel();
	if(ret != 0) {
		BELLADONNA_ERROR("Failed to boot kernel.");
		return -1;
	}
	return 0;
}

int belladonna_restore_ipsw(char* path) {
	int ret;
	if(!dev) {
		ret = belladonna_get_device();
		if(ret != 0) {
			BELLADONNA_ERROR("No device found.");
			return -1;
		}
	}
	int mode = 0;
	irecv_get_mode(dev, &mode);
	if(mode == IRECV_K_DFU_MODE) {
		ret = belladonna_enter_recovery();
		if(ret != 0) {
			BELLADONNA_ERROR("Failed to put device in pwned DFU mode.");
			return -1;
		}
	}
	
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
