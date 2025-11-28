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

/**
 * 初始化 pcap 抓包功能
 * @param interface_name 網路介面名稱（例如：enp4s0f2, eth0）
 * @param timeout 超時時間（毫秒）
 */
void pcap_init(const char* interface_name, int timeout)
{    
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program fcode;
    
    // 設定使用傳入的介面名稱
    dev = interface_name;
    
    // 查詢網路介面的 IP 和 Netmask
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1){
        fprintf(stderr,"%s\n",errbuf);
        exit(1);
    }
    
    // 開啟 pcap 即時抓包
    // 參數: 介面, 抓取長度, 混雜模式, timeout, 錯誤訊息緩衝
    p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
    if(!p){
        fprintf(stderr,"%s\n",errbuf);
        exit(1);
    }
    
    // 設定 BPF Filter: 只抓取 ICMP Echo Reply (type 0)
    // 這樣可以過濾掉其他不相關的封包
    sprintf(filter_string, "icmp[icmptype] == 0");
    
    // 編譯 filter
    if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
        pcap_perror(p,"pcap_compile");
        exit(1);
    }
    
    // 套用 filter
    if(pcap_setfilter(p, &fcode) == -1){
        pcap_perror(p,"pcap_setfilter");
        exit(1);
    }
}

/**
 * 接收 ICMP Echo Reply
 * @return 1: 收到符合條件的回應, 0: timeout 或不符合條件
 */
int pcap_get_reply(void)
{
    const u_char *ptr;
    
    // 嘗試抓取一個封包（會等待 timeout 時間）
    ptr = pcap_next(p, &hdr);
    
    if (ptr == NULL) {
        // Timeout: 沒有收到任何封包
        return 0;
    }

    // ptr 指向整個封包的開頭
    // 封包結構: [Ethernet Header (14 bytes)][IP Header][ICMP Header][Data]
    
    // 跳過 Ethernet Header (14 bytes) 取得 IP Header
    struct ip *ip_ptr = (struct ip *)(ptr + 14);
    
    // 計算 IP Header 長度（ip_hl 以 4 bytes 為單位）
    // 例如: ip_hl = 5 表示 IP Header 長度為 5 * 4 = 20 bytes
    int ip_hdr_len = ip_ptr->ip_hl * 4;
    
    // 跳過 IP Header 取得 ICMP Header
    struct icmphdr *icmp_ptr = (struct icmphdr *)((char *)ip_ptr + ip_hdr_len);

    // 檢查 ICMP Echo Reply 的 ID 是否為我們的 Process ID
    // 這樣可以確保收到的是我們發送的封包的回應
    if (ntohs(icmp_ptr->un.echo.id) != pid) {
        // 不是我們的封包，忽略
        return 0;
    }

    // 若符合條件，印出回覆來源 IP（表示該主機存活）
    // 輸出格式: "Host X.X.X.X is alive"
    printf("Host %s is alive\n", inet_ntoa(ip_ptr->ip_src));
    
    return 1;
}