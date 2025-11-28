#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

extern pid_t pid;

void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5; // Header length 20 bytes
    ip_hdr->ip_tos = 0;
    // Total Length: IP Header + ICMP Header + Data
    ip_hdr->ip_len = htons(IP_header_len + ICMP_header_len + IP_option_len + Data_len); 
    ip_hdr->ip_id = 0; 
    ip_hdr->ip_off = htons(IP_DF); // Don't Fragment
    ip_hdr->ip_ttl = 1; // 題目要求 TTL=1 
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_sum = 0; // OS will calculate
    ip_hdr->ip_src.s_addr = INADDR_ANY; // Let OS fill source IP
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
}

void
fill_icmphdr (struct icmphdr *icmp_hdr)
{
    icmp_hdr->type = ICMP_ECHO; // Type 8 (Request)
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(pid); // ID 必須是 PID 
    icmp_hdr->un.echo.sequence = 0; // 在 main loop 中會被覆蓋
    icmp_hdr->checksum = 0;
    
    // 填入學號作為 Data
    // icmp_hdr 結構後面緊接著 data，需要轉型指標
    char *data = (char *)icmp_hdr + sizeof(struct icmphdr);
    // TODO: 請將此處改為你的學號
    strncpy(data, "M143040001", 10); 
}

u16
fill_cksum(struct icmphdr* icmp_hdr)
{
    // 標準 Checksum 演算法
    unsigned short *buf = (unsigned short *)icmp_hdr;
    int len = ICMP_PACKET_SIZE; 
    unsigned long sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}