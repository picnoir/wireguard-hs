#ifndef _WG_TUN_
#define _WG_TUN_

#include <string.h>

int tun_alloc(const char *dev_name, int threads, int *fds);

int utun_read(int fd, void *buf, size_t len);
int utun_write(int fd, void *buf, size_t len);

#endif // _WG_TUN_
