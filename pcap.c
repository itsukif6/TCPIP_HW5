#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

extern pid_t pid;
extern unsigned short icmp_seq;

static char dev[IFNAMSIZ] = "eth0";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p = NULL;
static struct pcap_pkthdr hdr;

void pcap_init(const char* dst_ip, int timeout)
{	
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    
    struct in_addr addr;
    
    struct bpf_program fcode;
    
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1){
        fprintf(stderr,"%s\n",errbuf);
        exit(1);
    }
    
    addr.s_addr = netp;
    net = inet_ntoa(addr);	
    if(net == NULL){
        perror("inet_ntoa");
        exit(1);
    }
    
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if(mask == NULL){
        perror("inet_ntoa");
        exit(1);
    }
    
    p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
    if(!p){
        fprintf(stderr,"%s\n",errbuf);
        exit(1);
    }
    
    // Filter: ICMP echo reply (type 0) with our process ID
    sprintf(filter_string, "icmp[icmptype] = icmp-echoreply and icmp[4:2] = %d", pid);
    
    if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
        pcap_perror(p,"pcap_compile");
        exit(1);
    }
    
    if(pcap_setfilter(p, &fcode) == -1){
        pcap_perror(p,"pcap_setfilter");
        exit(1);
    }
}

int pcap_get_reply(void)
{
    const u_char *ptr;
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    
    ptr = pcap_next(p, &hdr);
    
    if (ptr == NULL) {
        return 0; // Timeout or no packet
    }
    
    // Skip Ethernet header (14 bytes)
    ptr += 14;
    
    // Get IP header
    ip_hdr = (struct ip*)ptr;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    
    // Get ICMP header
    icmp_hdr = (struct icmphdr*)(ptr + ip_hdr_len);
    
    // Verify ICMP type (0 = Echo Reply)
    if (icmp_hdr->type != ICMP_ECHOREPLY) {
        return 0;
    }
    
    // Verify ID matches our process ID
    if (ntohs(icmp_hdr->un.echo.id) != pid) {
        return 0;
    }
    
    // Verify sequence number matches
    if (ntohs(icmp_hdr->un.echo.sequence) != icmp_seq) {
        return 0;
    }
    
    // Print source IP (the host that replied)
    printf("Host %s is alive\n", inet_ntoa(ip_hdr->ip_src));
    
    return 1;
}