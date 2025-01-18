#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int fd;
    struct sockaddr addr;
    socklen_t addr_len;
    unsigned char *buffer;

    buffer = (unsigned char *)malloc(65536);
    addr_len = sizeof(addr);
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        printf("unable to create socket\n");

        return 1;
    }

    printf("server started...\n");

    while (1) {
        int bytes = recvfrom(fd, buffer, 65536, 0, (struct sockaddr *)&addr, &addr_len);
        if (bytes < 0) {
            printf("unable to receive data\n");

            return 1;
        }

        struct iphdr *hdr = (struct iphdr *)buffer;
        struct in_addr ip_addr;
        ip_addr.s_addr = hdr->saddr;
        printf("packet of size %d bytes from %s\n", bytes, inet_ntoa(ip_addr));
    }

    close(fd);
    free(buffer);

    return 0;
}