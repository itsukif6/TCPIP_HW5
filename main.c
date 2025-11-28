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

#include "fill_packet.h"
#include "pcap.h"

pid_t pid;

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
    char *interface = NULL;
    int timeout = DEFAULT_TIMEOUT;
	
    // 1. 解析參數 -i [介面] -t [timeout]
    for(int i=0; i<argc; i++){
        if(strcmp(argv[i], "-i") == 0 && i+1 < argc) interface = argv[i+1];
        if(strcmp(argv[i], "-t") == 0 && i+1 < argc) timeout = atoi(argv[i+1]);
    }

    if(interface == NULL) {
        printf("Usage: sudo ./ipscanner -i [interface] -t [timeout]\n");
        exit(1);
    }
	
	pid = getpid();
	struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;

	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
    memset(packet, 0, PACKET_SIZE);

	/* * 初始化 PCAP
	 */
	pcap_init(interface, timeout);

	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
    // 2. 獲取本機 IP 和 Netmask 以計算掃描範圍
    struct ifreq ifr;
    int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    // Get IP
    if(ioctl(tmp_sock, SIOCGIFADDR, &ifr) < 0) { perror("ioctl IP"); exit(1); }
    struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    // Get Mask
    if(ioctl(tmp_sock, SIOCGIFNETMASK, &ifr) < 0) { perror("ioctl Mask"); exit(1); }
    struct in_addr my_mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    close(tmp_sock);

    // 計算 Network Address (e.g., 140.117.171.0)
    u_int32_t start_ip = ntohl(my_ip.s_addr & my_mask.s_addr);
    u_int32_t my_ip_host_order = ntohl(my_ip.s_addr);

    printf("Scanning subnet on %s (My IP: %s)\n", interface, inet_ntoa(my_ip));

    // 3. 掃描迴圈 (假設 Class C /24, 掃描 1~254)
    // 根據題目 [cite: 17]，要掃描除了自己以外的所有主機
    for(int i = 1; i < 255; i++) {
        u_int32_t target_ip_int = start_ip | i;

        // 跳過自己
        if(target_ip_int == my_ip_host_order) continue;

        struct in_addr target_addr;
        target_addr.s_addr = htonl(target_ip_int);
        char *target_ip_str = inet_ntoa(target_addr);

        // 重置 Packet
        memset(packet, 0, PACKET_SIZE);

        // Fill Headers
        fill_iphdr(&packet->ip_hdr, target_ip_str);
        fill_icmphdr(&packet->icmp_hdr);
        
        // 設定 Sequence Number (使用 loop index) [cite: 44]
        packet->icmp_hdr.un.echo.sequence = htons(i);
        // 計算 Checksum (必須在填完資料後)
        packet->icmp_hdr.checksum = fill_cksum(&packet->icmp_hdr);

        dst.sin_addr = target_addr;

        printf("PING %s (data size=%d, id=0x%x, seq=%d, timeout=%d ms)\n", 
               target_ip_str, 10, pid, i, timeout);

        // 發送封包
        if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            continue;
        }

        // 接收回覆
        if(pcap_get_reply() == 0) {
            printf("Destination unreachable\n"); // 或 Timeout 訊息
        }
    }

	free(packet);
	close(sockfd);
	return 0;
}