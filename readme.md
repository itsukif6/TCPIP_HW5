# ICMP Subnet Scanner - Homework 5
## 功能說明

程式會自動掃描同一子網內的所有主機，透過發送 ICMP echo request (type 8) 並接收 ICMP echo reply (type 0) 來判斷主機是否存活。

## 主要特點

- TTL 設為 1，確保封包只在子網內傳播
- 自動獲取網路介面的 IP 地址和子網遮罩
- 使用 libpcap 過濾並接收 ICMP 回應
- ICMP 資料欄位包含學號

## 編譯方式

```bash
make
```

## 使用方式

```bash
sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]
```

### 參數說明

- `-i`: 網路介面名稱（例如：enp4s0f2, eth0, ens33）
- `-t`: 逾時時間（毫秒），預設為 1500ms

### 使用範例

```bash
sudo ./ipscanner -i enp4s0f2 -t 1500
sudo ./ipscanner -i eth0 -t 1000
```

## 輸出範例

```
Interface: enp4s0f2
IP Address: 140.117.171.148
Netmask: 255.255.255.0
Scanning range: 140.117.171.1 - 140.117.171.254

Host 140.117.171.1 is alive
Host 140.117.171.10 is alive
Host 140.117.171.25 is alive

Scan completed.
```

## 重要事項

1. **執行權限**: 必須使用 `sudo` 執行，因為需要建立 raw socket

2. **網路介面**: 使用 `ip addr` 或 `ifconfig` 查看網路介面名稱

3. **防火牆**: 確保防火牆允許 ICMP 封包

## 封包結構

### IP Header
- Header length: 7 words (20 + 8 bytes option)
- Total length: 92 bytes
- Id: 0
- Flag: Don't Fragment
- TTL: 1
- Protocol: ICMP

### ICMP Header
- Type: 8 (Echo Request)
- Code: 0
- ID: Process ID
- Sequence: 從 1 開始遞增
- Data: 學號

## 檔案說明

- `main.c`: 主程式，處理命令列參數、網路介面資訊、掃描邏輯
- `fill_packet.c`: 填充 IP header、ICMP header 和計算 checksum
- `fill_packet.h`: 結構定義和函數宣告
- `pcap.c`: 使用 libpcap 接收和過濾 ICMP 回應
- `pcap.h`: pcap 相關函數宣告


## 依賴套件

```bash
sudo apt-get install libpcap-dev
```

## 測試環境

- Ubuntu 24.04
- gcc 編譯器
- libpcap-dev
