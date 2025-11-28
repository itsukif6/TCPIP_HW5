#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>

#include "fill_packet.h"
#include "pcap.h"

#define STUDENT_ID "M143040001"

pid_t pid;
u16 icmp_seq = 0;

void print_usage(const char* prog_name)
{
    printf("usage:\n");
    printf("# sudo %s -i [Network Interface Name] -t [timeout(ms)]\n", prog_name);
    exit(1);
}

int get_interface_info(const char* ifname, char* ip_addr, char* netmask)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // Get IP address
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(sin->sin_addr));
    
    // Get netmask
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        close(sockfd);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    strcpy(netmask, inet_ntoa(sin->sin_addr));
    
    close(sockfd);
    return 0;
}

void calculate_subnet_range(const char* ip, const char* mask, 
                           unsigned long* start, unsigned long* end,
                           unsigned long* my_ip)
{
    struct in_addr ip_addr, mask_addr;
    unsigned long network, broadcast;
    
    inet_aton(ip, &ip_addr);
    inet_aton(mask, &mask_addr);
    
    *my_ip = ntohl(ip_addr.s_addr);
    network = ntohl(ip_addr.s_addr & mask_addr.s_addr);
    broadcast = network | (~ntohl(mask_addr.s_addr));
    
    *start = network + 1;
    *end = broadcast - 1;
}

int main(int argc, char* argv[])
{
    int sockfd;
    int on = 1;
    char ifname[IFNAMSIZ] = "";
    int timeout = DEFAULT_TIMEOUT;
    char ip_addr[16], netmask[16];
    unsigned long start_ip, end_ip, my_ip;
    int opt;
    
    pid = getpid();
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:t:")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(ifname, optarg, IFNAMSIZ-1);
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            default:
                print_usage(argv[0]);
        }
    }
    
    if (strlen(ifname) == 0) {
        print_usage(argv[0]);
    }
    
    // Get interface IP and netmask
    if (get_interface_info(ifname, ip_addr, netmask) < 0) {
        fprintf(stderr, "Failed to get interface information\n");
        exit(1);
    }
    
    printf("Interface: %s\n", ifname);
    printf("IP Address: %s\n", ip_addr);
    printf("Netmask: %s\n", netmask);
    
    // Calculate subnet range
    calculate_subnet_range(ip_addr, netmask, &start_ip, &end_ip, &my_ip);
    
    struct in_addr temp;
    temp.s_addr = htonl(start_ip);
    printf("Scanning range: %s", inet_ntoa(temp));
    temp.s_addr = htonl(end_ip);
    printf(" - %s\n\n", inet_ntoa(temp));
    
    // Create raw socket
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(1);
    }
    
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    
    // Initialize pcap once at the beginning
    pcap_init(ifname, timeout);
    
    // Scan all IPs in subnet
    for (unsigned long target = start_ip; target <= end_ip; target++) {
        // Skip our own IP
        if (target == my_ip) {
            continue;
        }
        
        icmp_seq++;
        
        // Prepare target IP
        struct in_addr target_addr;
        target_addr.s_addr = htonl(target);
        char target_ip[16];
        strcpy(target_ip, inet_ntoa(target_addr));
        
        // Allocate and prepare packet
        myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
        memset(packet, 0, PACKET_SIZE);
        
        // Fill IP header
        fill_iphdr(&packet->ip_hdr, target_ip);
        
        // Fill IP options (8 bytes, all zeros for padding)
        memset(packet->ip_option, 0, IP_OPTION_SIZE);
        
        // Fill ICMP header
        fill_icmphdr(&packet->icmp_hdr);
        
        // Fill data with student ID
        strncpy((char*)packet->data, STUDENT_ID, ICMP_DATA_SIZE);
        
        // Calculate ICMP checksum
        packet->icmp_hdr.checksum = fill_cksum(&packet->icmp_hdr);
        
        // Prepare destination
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr(target_ip);
        
        // Send packet
        if(sendto(sockfd, packet, PACKET_SIZE, 0, 
                  (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
        }
        
        // Try to receive reply
        pcap_get_reply();
        
        free(packet);
        
        // Small delay between packets
        usleep(10000); // 10ms
    }
    
    printf("\nScan completed.\n");
    close(sockfd);
    
    return 0;
}