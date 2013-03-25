
// for 102sh(ii), 104sh

#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef bool
#define true  1
#define false 0
typedef long bool;
#endif

#define AF_CAIF					37

#define CAIFPROTO_AT			0
#define CAIFPROTO_UTIL			3

#define SOL_CAIF				278

// for SOL_SOCKET
#define CAIF_PRIO_NORMAL		0x0f

#define CAIFSO_LINK_SELECT		127
#define CAIF_LINK_HIGH_BANDW	0
#define CAIF_LINK_LOW_LATENCY	1

#define CAIFSO_REQ_PARAM		128

#define CAIFSO_RSP_PARAM		129

typedef __u16 __kernel_sa_family_t;
struct sockaddr_caif {
        __kernel_sa_family_t  family;
        union {
                struct {
                        __u8  type;             /* type: enum caif_at_type */
                } at;                           /* CAIFPROTO_AT */
                struct {
                        char      service[16];
                } util;                         /* CAIFPROTO_UTIL */
                union {
                        __u32 connection_id;
                        __u8  nsapi;
                } dgm;                          /* CAIFPROTO_DATAGRAM(_LOOP)*/
                struct {
                        __u32 connection_id;
                        char      volume[16];
                } rfm;                          /* CAIFPROTO_RFM */
                struct {
                        __u8  type;             /* type:enum caif_debug_type */
                        __u8  service;          /* service:caif_debug_service */
                } dbg;                          /* CAIFPROTO_DEBUG */
        } u;
};

#define LBZERO32(x, n) (((x) << (32 - n)) >> (32 - n))
#define RBZERO32(x, n) (((x) >> n) << n)

#define SIM_LOCKED 		0x5a
#define SIM_UNLOCKED	0x28

typedef int (*diag_client_read_one_sector_t)(int, void *);
typedef int (*diag_client_sha1_one_sector_t)(void *, void *);
typedef int (*diag_client_decrypt_one_sector_t)(void *, void *, int);
typedef int (*diag_client_encrypt_one_sector_t)(void *, void *, int);
typedef int (*diag_client_read_sectors_t)(int, int, void *);
typedef int (*diag_client_write_sectors_t)(int, int, void *);

diag_client_read_one_sector_t diag_client_read_one_sector = NULL;
diag_client_sha1_one_sector_t diag_client_sha1_one_sector = NULL;
diag_client_decrypt_one_sector_t diag_client_decrypt_one_sector = NULL;
diag_client_encrypt_one_sector_t diag_client_encrypt_one_sector = NULL;
diag_client_read_sectors_t diag_client_read_sectors = NULL;
diag_client_write_sectors_t diag_client_write_sectors = NULL;

static int FirstBootFlag = 0;

static void memdump(const void *data, size_t size) {
	size_t i;
	unsigned char *p;

	for (i = 0; i < size; i++) {
		p = (unsigned char *) data + i;
		printf("%02x ", *p);
		if (((i + 1) % 16 == 0)) printf("\n");
	}
	if (i % 16) printf("\n");
}

static int diag_client_write_sectors_stub(int sector, int count, void *buffer) {
	return diag_client_write_sectors(sector, count, buffer);
}

static int diag_client_read_sectors_stub(int sector, int count, void *buffer) {
	int status;

	// printf("read offset = %04x, count = %04x\n", sector, count);
	status = diag_client_read_sectors(sector, count, buffer);
	// if (!status)
	//	memdump(buffer, count << 9);
	return status;
}

static int diag_client_decrypt_one_sector_stub(void *data, void *crypted, int sector) {
	int status;

	// printf("%04x before decrypt:\n", sector);
	// memdump(data, 1 << 9);
	status = diag_client_decrypt_one_sector(data, crypted, sector);
	// if (!status) {
	// 	printf("%04x after decrypt:\n", sector);
	// 	memdump(crypted, 1 << 9);
	// }
	return status;
}

// I think there's no need to reverse this
static bool shdiagarea_get_area_encrypt_flg() {
	return true;
}

// android 2.3 = 3, android 4.0 = 7
static bool shdiagarea_GetHardwareRevision(int *version) {
	*version = 7;
	return true;
}

static bool shdiagarea_check_block_encrypt(int block) {
	int version;

	if (block - 2 > 3)
		return false;
	if (!shdiagarea_GetHardwareRevision(&version))
		return false;
	if (version == 3 || version == 7)
		return true;
	return shdiagarea_get_area_encrypt_flg();
}

static int shdiagarea_read_sector_units(int block, int sector, void *buffer, int count) {
	int n, once;

	if (block > 9)
		return 0x4000;
	if (!buffer || (count == 0))
		return 0x4000;
	if (sector + count < 0x100) {
		n = 0;
		while (n < count) {
			once = count - n;
			if (once > 0x20) once = 0x20;
			if (diag_client_read_sectors_stub((block << 8) + sector + n, once, buffer + (n << 9))) {
				return 0x8005;
			}
			n += once;
		}
		return 0;
	}
	return 0x4000;
}

static int shdiagarea_write_sector_units(int block, int sector, void *buffer, int count) {
	int n, once;

	if (block > 9)
		return 0x4000;
	if (!buffer || (count == 0)) {
		return 0x4000;
	}
	if (sector + count < 0x100) {
		n = 0;
		while (n < count) {
			once = count - n;
			if (once > 0x20) once = 0x20;
			if (diag_client_write_sectors_stub((block << 8) + sector + n, once, buffer + (n << 9))) {
				return 0x8007;
			}
			n += once;
		}
		return 0;
	}
	return 0x4000;
}

static int shdiagarea_read_hash(int block, int sector, void *buffer, int count) {
	int status;
	char hash[0xa00];
	int arg0, arg1;

	if (block > 9) {
		return 0x4000;
	}
	if (!buffer || (count == 0)) {
		return 0x4000;
	}
	if (sector + count > 0x7b) {
		return 0x4000;
	}
	memset(hash, 0, sizeof(hash));
	arg0 = (block << 8) + ((sector * 20) >> 9) + 0xfb;
	arg1 = ((((sector * 20) >> 9) & 0x1fc) + 0x1fc + count * 20) >> 9;
	status = diag_client_read_sectors_stub(arg0, arg1, hash);
	if (status) {
		return 0x8005;
	}
	memcpy(buffer, hash + ((sector * 20) & 0x1fc), count * 20);
	return 0;
}

static int shdiagarea_write_hash(int block, int sector, void *buffer, int count) {
	int status;
	char hash[0xa00];
	int arg0, arg1;

	if (block > 9) {
		return 0x4000;
	}
	if (!buffer || (count == 0)) {
		return 0x4000;
	}
	memset(hash, 0, sizeof(hash));
	arg0 = (block << 8) + ((sector * 20) >> 9) + 0xfb;
	arg1 = ((((sector * 20) >> 9) & 0x1fc) + 0x1fc + count * 20) >> 9;
	status = diag_client_read_sectors_stub(arg0, arg1, hash);
	if (status) {
		return 0x8005;
	}
	memcpy(hash + (((sector * 20) >> 9) & 0x1fc), buffer, count * 20);
	status = diag_client_write_sectors_stub(arg0, arg1, hash);
	if (status) {
		return 0x8007;
	}
	return 0;
}

static int shdiagarea_read_sectors(int block, int sector, void *buffer, int count) {
	int status, i, hoff, boff;
	char hash[0xa00];
	char *data;
	char tmp_hash[0x14];

	if (block > 9) {
		return 0x4000;
	}
	if (!buffer || (count == 0)) {
		return 0x4000;
	}
	if (sector + count > 0x100) {
		return 0x4000;
	}
	if (!shdiagarea_check_block_encrypt(block) || (FirstBootFlag == 1)) {
		status = shdiagarea_read_sector_units(block, sector, buffer, count);
		return ((status & 0xf000) != 0) ? status : 0x4000;
	}
	if (sector + count > 0x7b) {
		return 0x4000;
	}
	status = shdiagarea_read_hash(block, sector, hash, count);
	if ((status & 0xf000) != 0) {
		return 0x4002;
	}
	data = (char *) malloc(0x7b * 0x200);
	if (!data) {
		return 0x4000;
	}
	status = shdiagarea_read_sector_units(block, sector + 0x80, data, count);
	if ((status & 0xf000) != 0) {
		free(data);
		return 0x8005;
	}
	for (i = 0, boff = 0, hoff = 0; i < count; i++, boff += 0x200, hoff += 0x14) {
		status = diag_client_sha1_one_sector(data + boff, tmp_hash);
		if (status) {
			free(data);
			return 0x4004;
		}
		if (!memcmp(hash + hoff, tmp_hash, 0x14)) {
			status = diag_client_decrypt_one_sector_stub(data + boff, buffer + boff, (block << 8) + sector + 0x80);
			if (status) {
				free(data);
				return 0x4007;
			}
		} else {
			if (FirstBootFlag == 1) {
				status = diag_client_read_one_sector((block << 8) + sector, buffer + boff);
				if (status) {
					free(data);
					return 0x8005;
				}
			} else {
				free(data);
				return 0x4005;
			}
		}
	}
	free(data);
	return 0;
}

static int shdiaglib_FlsDiagAreaRead(int block, void *buffer, int offset, int size) {
	int status;
	char *data;
	int data_size;
	int block_offset;

	if (block > 9) {
		return 1;
	}
	if (offset + size > 0x20000) {
		return 1;
	}
	if (!buffer || size == 0) {
		return 1;
	}
	block_offset = LBZERO32(offset, 9);
	data_size = RBZERO32(block_offset + size + ((1 << 9) - 1), 9);
	data = (char *) malloc(data_size);
	if (!data) {
		return 1;
	}
	memset(data, 0, data_size);
	status = shdiagarea_read_sectors(block, offset >> 9, data, data_size >> 9);
	if (status & 0xf000) {
		free(data);
		return 1;
	}
	memcpy(buffer, data + block_offset, size);
	free(data);
	return 0;
}

static int shdiaglib_FlsDiagAreaWrite(int block, void *buffer, int offset, int size) {
	int status, i;
	char *data, *crypted;
	int data_size;
	int block_offset;
	char hash[0xa00];

	data = NULL;
	crypted = NULL;
	if (block > 9) {
		return 1;
	}
	if (offset + size > 0x20000) {
		return 1;
	}
	if (!buffer || size == 0) {
		return 1;
	}
	block_offset = LBZERO32(offset, 9);
	data_size = RBZERO32(block_offset + size + ((1 << 9) - 1), 9);
	if ((data_size >> 9) == 0) {
		return 1;
	}
	if ((offset >> 9) + (data_size >> 9) > 0x100) {
		return 1;
	}
	data = (char *) malloc(data_size);
	if (!data) {
		status = 0x4000;
		goto bail;
	}
	memset(data, 0, data_size);
	status = shdiagarea_read_sectors(block, offset >> 9, data, data_size >> 9);
	if (status) {
		goto bail;
	}
	memcpy(data + block_offset, buffer, size);
	if (shdiagarea_check_block_encrypt(block)) {
		if ((offset >> 9) + (data_size >> 9) > 0x7b) {
			status = 0x4000;
			goto bail;
		}
		memset(hash, 0, sizeof(hash));
		crypted = (char *) malloc(0xf600);
		if (!crypted) {
			status = 0x4000;
			goto bail;
		}
		memset(crypted, 0, 0xf600);
		for (i = 0; i < data_size >> 9; i++) {
			status = diag_client_encrypt_one_sector(data + i * 0x200, crypted + i * 0x200, (block << 8) + (offset >> 9) + 0x80 + i);
			if (status) {
				goto bail;
			}
			status = diag_client_sha1_one_sector(crypted + i * 0x200, hash + i * 20);
			if (status) {
				status = 0x4004;
				goto bail;
			}
		}
		status = shdiagarea_write_sector_units(block, (offset >> 8) + 0x80, crypted, data_size >> 9);
		if (status & 0xf000) goto bail;
		status = shdiagarea_write_hash(block, offset >> 8, hash, data_size >> 9);
		if (status & 0xf000) {
			status = 0x4003;
			goto bail;
		}
	} else {
		status = shdiagarea_write_sector_units(block, offset >> 9, data, data_size >> 9);
		if (status) {
			status = 0x4006;
			goto bail;
		}
	}
bail:
	if (crypted) free(crypted);
	if (data) free(data);
	if (status & 0xf000)
		return 1;
	return 0;
}

static bool shdiaglib_ShnvIMEIDataRead(char *out) {
	if (!out) return false;
	if (shdiaglib_FlsDiagAreaRead(2, out, 0x5000, 0xa))
		return false;
	return true;
}

static bool shdiaglib_CheckUimLockFlg(int *out) {
	char flag;
	int status;

	flag = SIM_LOCKED;
	*out = 1;
	status = shdiaglib_FlsDiagAreaRead(3, &flag, 0xc0, 1);
	if (status != 0) return false;
	if (flag == SIM_UNLOCKED) *out = 0;
	return true;
}

static bool shdiaglib_ResetUimLockFlg() {
	char flag;
	int status;

	flag = SIM_UNLOCKED;
	status = shdiaglib_FlsDiagAreaWrite(3, &flag, 0xc0, 1);
	if (status != 0) return false;
	return true;
}

static bool shdiaglib_SetUimLockFlg() {
	char flag;
	int status;

	flag = SIM_LOCKED;
	status = shdiaglib_FlsDiagAreaWrite(3, &flag, 0xc0, 1);
	if (status != 0) return false;
	return true;
}

typedef int (*property_get_t)(char *, char *, char *);
static property_get_t property_get = NULL;

static bool try_get_imei_from_property(char *out) {
	void *h;
	char value[92];
	int rc, i;

	if (!property_get) {
		h = dlopen("libcutils.so", RTLD_NOW);
		if (!h) return false;
		property_get = dlsym(h, "property_get");
	}
	if (!property_get) return false;
	rc = property_get("ro.serialno", value, NULL);
	if (rc != 15) return false;
	memset(out, 0, 10);
	out[0] = 0;
	out[1] = 8;
	out[2] = 0x0a | ((value[0] - '0') << 4);
	out[3] = (value[1] - '0') | ((value[2] - '0') << 4);
	out[4] = (value[3] - '0') | ((value[4] - '0') << 4);
	out[5] = (value[5] - '0') | ((value[6] - '0') << 4);
	out[6] = (value[7] - '0') | ((value[8] - '0') << 4);
	out[7] = (value[9] - '0') | ((value[10] - '0') << 4);
	out[8] = (value[11] - '0') | ((value[12] - '0') << 4);
	out[9] = (value[13] - '0') | ((value[14] - '0') << 4);
	return true;
}

static int atrelay_caif_connect(int protocol, int priority, int link, char *name, int *request, int request_size, struct sockaddr_caif *address) {
	int fd, rc;
	socklen_t len;
	char buffer[0x20];

	fd = socket(AF_CAIF, SOCK_SEQPACKET, protocol);
	if (fd < 0) return -1;
	len = sizeof(priority);
	rc = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, len);
	if (rc < 0) goto bail;
	if (name) {
		memset(buffer, 0, sizeof(buffer));
		strncpy(buffer, name, 0x10);
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, buffer, sizeof(buffer));
	} else {
		len = sizeof(link);
		rc = setsockopt(fd, SOL_CAIF, CAIFSO_LINK_SELECT, &link, len);
	}
	if (rc < 0) goto bail;
	if (protocol == CAIFPROTO_UTIL && request_size) {
		rc = setsockopt(fd, SOL_CAIF, CAIFSO_REQ_PARAM, request, request_size);
		if (rc < 0) goto bail;
	}
	rc = connect(fd, (struct sockaddr *) address, sizeof(*address));
	if (rc < 0) goto bail;
	return fd;
bail:
	close(fd);
	return -1;
}

static int atrelay_write(int fd, char *buffer, int size) {
	int count, t;

	count = 0;
	while (count < size) {
		t = write(fd, buffer, size);
		if (t <= 0) break;
		count += t;
	}

	return count;
}

static int atrelay_send_at_command(int fd, char *at, char *expected) {
	int length, written, count, n;
	char buffer[0x1000];
	struct timeval tv;
	fd_set readfds;

	length = strlen(at);
	written = atrelay_write(fd, at, length);
	if (written != length) return -1;
	count = 0;
	while (count < sizeof(buffer)) {
		tv.tv_sec = 30;
		tv.tv_usec = 0;
		FD_ZERO(&readfds); FD_SET(fd, &readfds);
		n = select(fd + 1, &readfds, NULL, NULL, &tv);
		if (n <= 0) break;
		if (FD_ISSET(fd, &readfds)) {
			n = read(fd, buffer + count, sizeof(buffer) - count);
			if (n <= 0) break;
			count += n;
			buffer[count] = 0;
			if (strstr(buffer, expected)) return 0;
		}
	}

	return -1;
}

static int cf_request = 0x100;
static unsigned char cf_address[] = {
	0x25, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef struct {
	char *head;
	int unknown;
	int wait;
	char *tail;
} at_cmd_t;

static at_cmd_t at_unlock_uim[] = {
	{"ate0", 1, 0, ""},
	{"at*egdfsw", 1, 1, "=891,1,\"01\""},
	{"at*ecpsauth", 1, 1, "=1,5"},
	{"at*ecpsauth", 1, 1, "=2"},
	{"at*ecpsotp2", 1, 1, "=1,1,0,1,201,1,,,"},
	{"at*ecpsotpd", 1, 1, "=\"0B002001F0002001F001200120008801880188001000100000000000003111B0D0C0160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""},
	{"at*ecpsotpd", 1, 1, "=\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""},
	{"at*ecpsotpd", 1, 1, "=\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000C000000000000C000000000300C0F00\""},
//	{"at*ecpsotp2", 10, 1, "=2"},
	{"at*ecpsdomw", 1, 1, "=2"},
	{"at*ecpsbind", 1, 1, "=1,2,25"},
	{"at*ecpsbndauthd", 1, 1, "=4,\"00000000000000000000000000000000\""},
	{"at*ecpsbndauthd", 1, 1, "=1,\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\",\"0000000000\""},
	{"at*ecpsbndpard", 1, 1, "=4,\"03030303\""},
	{"at*ecpsbndpard", 1, 1, "=16,\"100000000000000001000100100020001000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF00FFFFFFFFFFFFFFFF\""},
	{"at*ecpsbndpard", 1, 1, "=17,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=18,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=19,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=20,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=21,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=22,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=23,\"0000000020000000\""},
	{"at*ecpsbndpard", 1, 1, "=32,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=33,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=34,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=35,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=36,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=37,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=38,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=39,\"0000000000000000000000000000000000000000\""},
	{"at*ecpsbndpard", 1, 1, "=48,\"F1000000\""},
	{"at*ecpsbndpard", 1, 1, "=49,\"F7000000\""},
	{"at*ecpsbndpard", 1, 1, "=50,\"F1080000\""},
	{"at*ecpsbndpard", 1, 1, "=51,\"F1081000\""},
	{"at*ecpsbndpard", 1, 1, "=52,\"FFF70000\""},
	{"at*ecpsbndpard", 1, 1, "=53,\"FFFF1000\""},
	{"at*ecpsbndpard", 1, 1, "=54,\"FFFF1000\""},
	{"at*ecpsbndpard", 1, 1, "=55,\"FFFF1000\""},
	{"at*ecpsbind", 10, 1, "=2"},
	{0, -1, -1, 0}
};

static bool atrelay_unlock() {
	int status, fd, i;
	char bIMEI[10], sIMEI[0x20];
	char sCmd[0x2641];
	at_cmd_t *p;

	fd = atrelay_caif_connect(
		CAIFPROTO_AT,
		CAIF_PRIO_NORMAL,
		CAIF_LINK_LOW_LATENCY,
		NULL,
		&cf_request,
		0,
		(struct sockaddr_caif *) cf_address
	);
	if (fd <= 0) {
		perror("connect");
		return false;
	}
	if (!shdiaglib_ShnvIMEIDataRead(bIMEI) && 
		!try_get_imei_from_property(bIMEI)) goto bail;
	sprintf(
		sIMEI,
		"%02x%02x%02x%02x%02x%02x%02x%01x",
		bIMEI[0],
		bIMEI[1],
		bIMEI[2],
		bIMEI[3],
		bIMEI[4],
		bIMEI[5],
		bIMEI[6],
		bIMEI[7] >> 4
	);
	for (i = 0, p = at_unlock_uim; (i < 0x28) && p->head; i++, p++) {
		memset(sCmd, 0, sizeof(sCmd));
		strcat(sCmd, p->head);
		strcat(sCmd, p->tail);
		if (i == 4) {
			strcat(sCmd, "\"");
			strcat(sCmd, sIMEI);
			strcat(sCmd, "\"");
		}
		strcat(sCmd, "\r\n");
		status = atrelay_send_at_command(fd, sCmd, "OK\r\n");
		if (status < 0) goto bail;
		fprintf(stdout, ".");
		fflush(stdout);
		sleep(p->wait);	
	}
	close(fd);
	return true;
bail:
	close(fd);
	return false;
}

#define FIND_SYMBOL_OR_FAIL(h, x) do {\
		x = (x ## _t) dlsym(h, #x); \
		if (!x) { dlclose(h); fprintf(stderr, "dlsym %s: %s\n", #x, strerror(errno)); return -1; } \
	} while (0)

static int load_diag_client() {
	void *h;

	h = dlopen("libdiagclient.so", RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen libdiagclient.so: %s\n", strerror(errno));
		return -1;
	}
	FIND_SYMBOL_OR_FAIL(h, diag_client_read_one_sector);
	FIND_SYMBOL_OR_FAIL(h, diag_client_sha1_one_sector);
	FIND_SYMBOL_OR_FAIL(h, diag_client_decrypt_one_sector);
	FIND_SYMBOL_OR_FAIL(h, diag_client_encrypt_one_sector);
	FIND_SYMBOL_OR_FAIL(h, diag_client_read_sectors);
	FIND_SYMBOL_OR_FAIL(h, diag_client_write_sectors);
	return 0;
}

int main(int argc, char *argv[]) {
	int locked, result;
	char buffer[0x8000];

	if (load_diag_client() < 0) {
		fprintf(stderr, "load libdiagclient.so failed.\n");
		return 1;
	}
#if 0
	if (!shdiaglib_CheckUimLockFlg(&locked)) {
		fprintf(stderr, "read lock state failed.\n");
		return 1;
	}
	printf("SIM lock is %s.\n", locked ? "ON" : "OFF");
#endif
	// if (locked) {
		fprintf(stdout, "Removing lock from modem");
		fflush(stdout);
		result = atrelay_unlock();
		fprintf(stdout, "%s\n", result == true ? "OK" : "failed");
		fflush(stdout);
		if (!result) return 1;
#if 0
		fprintf(stdout, "Saving lock state into shdiag...");
		fflush(stdout);
		result = shdiaglib_ResetUimLockFlg();
		fprintf(stdout, "%s\n", result == true ? "OK" : "failed");
		fflush(stdout);
		if (!result) return 1;
	// }
#endif
	return 0;
}
