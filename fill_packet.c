#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

extern pid_t pid;

/**
 * 填充 IP Header
 * @param ip_hdr 指向 IP Header 的指標
 * @param dst_ip 目標 IP 地址字串（例如："140.117.171.1"）
 */
void 
fill_iphdr(struct ip *ip_hdr, const char* dst_ip)
{
    // IP 版本: 4 (IPv4)
    ip_hdr->ip_v = 4;
    
    // Header 長度: 5 (表示 5 * 4 = 20 bytes，不包含選項)
    ip_hdr->ip_hl = 5;
    
    // Type of Service: 0 (一般服務)
    ip_hdr->ip_tos = 0;
    
    // Total Length: IP Header + ICMP Header + IP Options + Data
    // 必須轉換為網路位元組序（Big Endian）
    ip_hdr->ip_len = htons(IP_header_len + ICMP_header_len + IP_option_len + Data_len); 
    
    // Identification: 0 (由作業系統處理)
    ip_hdr->ip_id = 0; 
    
    // Flags and Fragment Offset: Don't Fragment (DF)
    ip_hdr->ip_off = htons(IP_DF);
    
    // Time To Live: 1（確保封包只在子網內傳播，不會路由到其他網路）
    ip_hdr->ip_ttl = 1;
    
    // Protocol: ICMP (值為 1)
    ip_hdr->ip_p = IPPROTO_ICMP;
    
    // Checksum: 0 (讓作業系統自動計算)
    ip_hdr->ip_sum = 0;
    
    // Source IP: INADDR_ANY (讓作業系統自動填入本機 IP)
    ip_hdr->ip_src.s_addr = INADDR_ANY;
    
    // Destination IP: 將字串格式的 IP 轉換為網路位元組序
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
}

/**
 * 填充 ICMP Header 和 Data
 * @param icmp_hdr 指向 ICMP Header 的指標
 */
void
fill_icmphdr(struct icmphdr *icmp_hdr)
{
    // Type: 8 (ICMP Echo Request)
    icmp_hdr->type = ICMP_ECHO;
    
    // Code: 0 (必須為 0)
    icmp_hdr->code = 0;
    
    // ID: 必須是 Process ID（這樣才能識別是我們發送的封包）
    icmp_hdr->un.echo.id = htons(pid);
    
    // Sequence: 0 (在 main loop 中會被覆蓋為實際的序號)
    icmp_hdr->un.echo.sequence = 0;
    
    // Checksum: 0 (稍後會重新計算)
    icmp_hdr->checksum = 0;
    
    // 填入學號作為 ICMP Data
    // icmp_hdr 結構後面緊接著 data 區域
    // 需要透過指標運算來存取
    char *data = (char *)icmp_hdr + sizeof(struct icmphdr);
    
    // TODO: 請將此處改為你的學號（10 個字元）
    strncpy(data, "M143040001", 10); 
}

/**
 * 計算 ICMP Checksum
 * @param icmp_hdr 指向 ICMP Header 的指標
 * @return 計算出的 checksum 值
 * 
 * Checksum 演算法說明:
 * 1. 將資料視為 16-bit 整數陣列
 * 2. 將所有 16-bit 整數相加
 * 3. 如果有進位，將進位加回低 16 位元
 * 4. 取 1's complement（位元反轉）
 */
u16
fill_cksum(struct icmphdr* icmp_hdr)
{
    // 將 ICMP Header 視為 16-bit 整數陣列
    unsigned short *buf = (unsigned short *)icmp_hdr;
    
    // 計算長度：ICMP Header + Data
    int len = ICMP_PACKET_SIZE; 
    
    // 用於累加的變數（使用 unsigned long 避免溢位）
    unsigned long sum = 0;

    // 每次處理 2 bytes（16 bits）
    while (len > 1) {
        sum += *buf++;  // 累加當前的 16-bit 值
        len -= 2;       // 剩餘長度減 2
    }
    
    // 如果長度為奇數，處理最後 1 byte
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    
    // 處理進位：將高 16 位元加到低 16 位元
    // (sum >> 16) 取得高 16 位元
    // (sum & 0xFFFF) 取得低 16 位元
    sum = (sum >> 16) + (sum & 0xFFFF);
    
    // 再處理一次進位（因為上一步的相加可能又產生進位）
    sum += (sum >> 16);
    
    // 取 1's complement（位元反轉）作為最終的 checksum
    return (u16)(~sum);
}