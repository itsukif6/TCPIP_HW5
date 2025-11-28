#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>

typedef char u8;
typedef unsigned short u16;

#define PACKET_SIZE    92
#define IP_OPTION_SIZE 8

// 增加長度定義方便計算
#define IP_header_len sizeof(struct ip)
#define ICMP_header_len sizeof(struct icmphdr)
#define IP_option_len 8
#define Data_len 10 // 學號長度

#define ICMP_PACKET_SIZE   (PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE)
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef struct
{
	struct ip ip_hdr;
	u8 ip_option[8];
	struct icmphdr icmp_hdr;
	u8 data[0]; // Flexible array member
} myicmp ;

void 
fill_iphdr ( struct ip *ip_hdr, const char* dst_ip);

void
fill_icmphdr (struct icmphdr *icmp_hdr);

u16
fill_cksum ( struct icmphdr *icmp_hdr);
 
#endif