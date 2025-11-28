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
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-i") == 0 && i+1 < argc) 
            interface = argv[i+1];
        if(strcmp(argv[i], "-t") == 0 && i+1 < argc) 
            timeout = atoi(argv[i+1]);
    }

    // 檢查是否提供介面名稱
    if(interface == NULL) {
        printf("Usage: sudo ./ipscanner -i [interface] -t [timeout]\n");
        exit(1);
    }
    
    // 取得當前程式的 process ID
    pid = getpid();
    
    // 設定目標地址結構
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;

    // 分配封包記憶體空間
    myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
    memset(packet, 0, PACKET_SIZE);

    // 2. 初始化 PCAP（用於接收 ICMP 回應）
    pcap_init(interface, timeout);

    // 3. 建立 RAW socket（用於發送自訂 IP 封包）
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket");
        exit(1);
    }

    // 4. 設定 socket 選項，讓我們自己填寫 IP header
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    
    // 5. 獲取本機 IP 地址和網路遮罩，用於計算掃描範圍
    struct ifreq ifr;
    int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    // 取得 IP 地址
    if(ioctl(tmp_sock, SIOCGIFADDR, &ifr) < 0) { 
        perror("ioctl IP"); 
        exit(1); 
    }
    struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    // 取得網路遮罩
    if(ioctl(tmp_sock, SIOCGIFNETMASK, &ifr) < 0) { 
        perror("ioctl Mask"); 
        exit(1); 
    }
    struct in_addr my_mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    close(tmp_sock);

    // 6. 計算網路位址（Network Address）和廣播位址
    // 例如: IP=140.117.171.148, Mask=255.255.255.0
    // Network = IP & Mask = 140.117.171.0
    u_int32_t network_addr = ntohl(my_ip.s_addr & my_mask.s_addr);
    u_int32_t my_ip_host_order = ntohl(my_ip.s_addr);
    
    // 計算子網的第一個和最後一個可用主機 IP
    u_int32_t first_ip = network_addr + 1;      // 140.117.171.1
    u_int32_t last_ip = network_addr + 254;     // 140.117.171.254

    // 7. 顯示掃描資訊（符合預期輸出格式）
    printf("Interface: %s\n", interface);
    printf("IP Address: %s\n", inet_ntoa(my_ip));
    printf("Netmask: %s\n", inet_ntoa(my_mask));
    
    // 顯示掃描範圍
    struct in_addr temp_addr;
    temp_addr.s_addr = htonl(first_ip);
    printf("Scanning range: %s - ", inet_ntoa(temp_addr));
    temp_addr.s_addr = htonl(last_ip);
    printf("%s\n\n", inet_ntoa(temp_addr));

    // 8. 開始掃描迴圈（掃描 1~254 號主機）
    for(int i = 1; i < 255; i++) {
        // 計算目標 IP
        u_int32_t target_ip_int = network_addr | i;

        // 跳過自己的 IP
        if(target_ip_int == my_ip_host_order) 
            continue;

        // 將目標 IP 轉換為字串格式
        struct in_addr target_addr;
        target_addr.s_addr = htonl(target_ip_int);
        char *target_ip_str = inet_ntoa(target_addr);

        // 9. 重置並填充封包
        memset(packet, 0, PACKET_SIZE);

        // 填充 IP Header（設定目標 IP, TTL=1 等）
        fill_iphdr(&packet->ip_hdr, target_ip_str);
        
        // 填充 ICMP Header（設定 Type=8, ID=PID, Data=學號）
        fill_icmphdr(&packet->icmp_hdr);
        
        // 設定 Sequence Number（使用迴圈索引）
        packet->icmp_hdr.un.echo.sequence = htons(i);
        
        // 計算 ICMP Checksum（必須在填完所有資料後計算）
        packet->icmp_hdr.checksum = fill_cksum(&packet->icmp_hdr);

        // 設定目標地址
        dst.sin_addr = target_addr;

        // 10. 發送 ICMP Echo Request
        if(sendto(sockfd, packet, PACKET_SIZE, 0, 
                  (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            continue;
        }

        // 11. 接收 ICMP Echo Reply（透過 pcap）
        // pcap_get_reply() 會在 timeout 時間內等待回應
        // 如果收到回應，會在函數內部印出 "Host X.X.X.X is alive"
        pcap_get_reply();
    }

    // 12. 顯示掃描完成訊息
    printf("\nScan completed.\n");

    // 13. 清理資源
    free(packet);
    close(sockfd);
    
    return 0;
}