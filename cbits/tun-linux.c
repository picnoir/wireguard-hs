#include <string.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tun.h"

int tun_alloc(const char *dev_name, int threads, int *fds) {
    struct ifreq ifr;
    int fd, i;

    if (!dev_name)
        return -1;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (threads > 1)
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    for (i = 0; i < threads; i++) {
        if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
            goto err;
        if (ioctl(fd, TUNSETIFF, (void *)&ifr) != 0) {
            close(fd);
            goto err;
        }
        fds[i] = fd;
    }

    return threads;
err:
    for (--i; i >= 0; i--)
        close(fds[i]);
    return -1;
}
