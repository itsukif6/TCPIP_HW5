#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

extern pid_t pid;
extern unsigned short icmp_seq;

void 
fill_iphdr(struct ip *ip_hdr, const char* dst_ip)
{
    ip_hdr->ip_v = 4;                          // IPv4
    ip_hdr->ip_hl = 5 + IP_OPTION_SIZE / 4;   // Header length (5 + 2 = 7 words)
    ip_hdr->ip_tos = 0;                        // Type of service
    ip_hdr->ip_len = htons(PACKET_SIZE);       // Total length
    ip_hdr->ip_id = 0;                         // Identification = 0
    ip_hdr->ip_off = htons(IP_DF);            // Don't fragment flag
    ip_hdr->ip_ttl = 1;                        // TTL = 1 (stay in subnet)
    ip_hdr->ip_p = IPPROTO_ICMP;              // Protocol = ICMP
    ip_hdr->ip_sum = 0;                        // Checksum (OS will fill it)
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip); // Destination IP
    
    // Source IP will be filled by kernel
    ip_hdr->ip_src.s_addr = INADDR_ANY;
}

void
fill_icmphdr(struct icmphdr *icmp_hdr)
{
    icmp_hdr->type = ICMP_ECHO;                // Type 8: Echo Request
    icmp_hdr->code = 0;                        // Code 0
    icmp_hdr->checksum = 0;                    // Will be calculated later
    icmp_hdr->un.echo.id = htons(pid);        // Process ID
    icmp_hdr->un.echo.sequence = htons(icmp_seq); // Sequence number
}

u16
fill_cksum(struct icmphdr* icmp_hdr)
{
    u16 *buf = (u16*)icmp_hdr;
    int size = ICMP_PACKET_SIZE;
    unsigned long sum = 0;
    
    // Calculate checksum
    while (size > 1) {
        sum += *buf++;
        size -= 2;
    }
    
    // Add odd byte if exists
    if (size == 1) {
        sum += *(u8*)buf;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (u16)(~sum);
}