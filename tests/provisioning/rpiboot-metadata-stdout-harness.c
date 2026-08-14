#include <libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATH_LEN 256

struct file_message {
	int command;
	char fname[MAX_PATH_LEN];
};

extern int bcm2711;
extern int bcm2712;
extern int metadata;
extern int verbose;
extern char *metadata_path;
extern int file_server(libusb_device_handle *usb_device);
extern void get_options(int argc, char *argv[]);

static const struct file_message scripted_messages[] = {
	{ 0, "*USER_SERIAL_NUM*A7EB274C" },
	{ 0, "*EEPROM_HASH*dfc8ef2c77b8152a5cfa008c2296246413fd580fdc26dfacd431e348571a2137" },
	{ 2, "done" },
};

static size_t next_message;
static unsigned int acknowledgements;

int __wrap_libusb_control_transfer(
	libusb_device_handle *device,
	uint8_t request_type,
	uint8_t request,
	uint16_t value,
	uint16_t index,
	unsigned char *data,
	uint16_t length,
	unsigned int timeout)
{
	(void)device;
	(void)request;
	(void)value;
	(void)index;
	(void)timeout;

	if ((request_type & LIBUSB_ENDPOINT_IN) != 0) {
		if (length != sizeof(struct file_message)
		    || next_message >= sizeof(scripted_messages) / sizeof(scripted_messages[0])) {
			return LIBUSB_ERROR_IO;
		}
		memcpy(data, &scripted_messages[next_message++], length);
		return length;
	}

	if (length != 0 || data != NULL) {
		return LIBUSB_ERROR_IO;
	}
	acknowledgements++;
	return 0;
}

int main(void)
{
	char program[] = "rpiboot";
	char path_option[] = "-p";
	char usb_path[] = "contract-usb-path";
	char directory_option[] = "-d";
	char directory[] = ".";
	char *argv[] = {
		program,
		path_option,
		usb_path,
		directory_option,
		directory,
		NULL,
	};

	bcm2711 = 0;
	bcm2712 = 1;
	verbose = 0;
	get_options(5, argv);
	if (metadata_path != NULL) {
		fprintf(stderr, "no--j invocation selected a metadata file path\n");
		return EXIT_FAILURE;
	}

	if (file_server((libusb_device_handle *)(uintptr_t)1) != 0) {
		fprintf(stderr, "file_server failed\n");
		return EXIT_FAILURE;
	}
	if (next_message != sizeof(scripted_messages) / sizeof(scripted_messages[0])) {
		fprintf(stderr, "file_server did not consume every scripted message\n");
		return EXIT_FAILURE;
	}
	if (acknowledgements != 2) {
		fprintf(stderr, "file_server emitted %u acknowledgements, expected 2\n", acknowledgements);
		return EXIT_FAILURE;
	}
	if (metadata != 1 || metadata_path != NULL) {
		fprintf(stderr, "metadata was not enabled lazily for stdout\n");
		return EXIT_FAILURE;
	}
	if (puts("KAIBA_RPIBOOT_STDOUT_HARNESS_DONE") == EOF || fflush(stdout) != 0) {
		fprintf(stderr, "stdout was closed by metadata finalization\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
