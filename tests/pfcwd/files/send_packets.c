//send_packets.c

/*
send_packets C code function
gcc -shared -o packet_sender_bit32.so -fPIC -m32 send_packets.c
gcc -shared -o packet_sender_bit64.so -fPIC -m64 send_packets.c
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

void send_packets_c(const char* interface, const unsigned char* packet, int packet_size, int num, int interval) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll socket_address;

    // Open raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("Socket error");
        return;
    }

    // Get the index of the network interface
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl error");
        close(sockfd);
        return;
    }

    // Prepare the sockaddr_ll
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = ifr.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, packet, ETH_ALEN);

    for (int i = 0; i < num; i++) {
        // Send the packet
        if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto error");
        }

        // Sleep for the specified interval
        if (interval > 0) {
            usleep(interval * 1000); // Convert milliseconds to microseconds
        }
    }

    // Close the socket
    close(sockfd);
}
