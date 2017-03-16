/**
  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Extracted from ShadowVPN project, with some minor modifications.

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <errno.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

#include "tun.h"

int tun_alloc(const char *dev_name, int threads, int *fds) {
    struct ctl_info ctlInfo;
    struct sockaddr_ctl sc;
    int fd, utun_num;

    if (!dev_name || sscanf(dev_name, "utun%d", &utun_num) != 1) {
        errno = EINVAL;
        return -1;
    }

    memset(&ctlInfo, 0, sizeof(ctlInfo));

    if (strlcpy(ctlInfo.ctl_name,
                UTUN_CONTROL_NAME,
                sizeof(ctlInfo.ctl_name)) >= sizeof(ctlInfo.ctl_name)) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0)
        return -1;

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        close(fd);
        return -1;
    }

    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;

    sc.sc_unit = utun_num + 1;

    if (connect(fd, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
        close(fd);
        return -1;
    }

    *fds = fd;

    return 1;
}

inline int utun_modified_len(int len) {
    if (len > 0)
        return (len > sizeof(u_int32_t)) ? len - sizeof(u_int32_t) : 0;
    else
        return len;
}

int utun_read(int fd, void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    return utun_modified_len(readv(fd, iv, 2));
}

int utun_write(int fd, void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];
    struct ip *iph;

    iph = (struct ip *) buf;

    if (iph->ip_v == 6)
        type = htonl(AF_INET6);
    else
        type = htonl(AF_INET);

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    return utun_modified_len(writev(fd, iv, 2));
}

