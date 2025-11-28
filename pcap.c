#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

extern pid_t pid;

static const char* dev;
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

void pcap_init( const char* interface_name , int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct bpf_program fcode;
    
    // 設定使用傳入的介面名稱
    dev = interface_name;
	
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	// Open live pcap
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
    // 設定 Filter: 只抓 ICMP 且 Type 為 Echo Reply (0)
	sprintf(filter_string, "icmp[icmptype] == 0");
	
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}

int pcap_get_reply( void )
{
	const u_char *ptr;
    
    // 嘗試抓取封包
	ptr = pcap_next(p, &hdr);
	
    if (ptr == NULL) {
        return 0; // Timeout
    }

    // ptr 指向 Ethernet Header (14 bytes)
    // 跳過 Ethernet Header 取得 IP Header
    struct ip *ip_ptr = (struct ip *)(ptr + 14);
    
    // 跳過 IP Header 取得 ICMP Header
    // ip_hl 是以 4 bytes 為單位
    int ip_hdr_len = ip_ptr->ip_hl * 4;
    struct icmphdr *icmp_ptr = (struct icmphdr *)((char *)ip_ptr + ip_hdr_len);

    // 檢查 ID 是否為我們的 Process ID [cite: 54]
    if (ntohs(icmp_ptr->un.echo.id) != pid) {
        return 0;
    }

    // 若符合，印出回覆來源 IP
    // 計算時間差通常比較複雜，這裡依照題目範例印出 Reply
    // 若需要精確時間，需在發送時記錄時間戳記
    printf("Reply from %s, time ... ms\n", inet_ntoa(ip_ptr->ip_src));
	
	return 1;
}