# ICMP 子網掃描器 - 作業 5

## 功能說明

本程式會自動掃描同一子網內的所有主機（1-254），透過發送 ICMP Echo Request（Type 8）並接收 ICMP Echo Reply（Type 0）來判斷主機是否存活。

## 主要特點

- TTL 設為 1，確保封包只在子網內傳播
- 自動獲取網路介面的 IP 地址和子網遮罩
- 使用 libpcap 過濾並接收 ICMP 回應
- ICMP 資料欄位包含學號
- 清晰的輸出格式，顯示掃描範圍和存活主機

## 使用方式

```bash
sudo ./ipscanner -i [網路介面名稱] -t [timeout(ms)]
```

### 參數說明

- `-i`: 網路介面名稱（必填）
  - 使用 `ip addr` 或 `ifconfig` 查看可用介面
  - 常見介面名稱：`enp4s0f2`, `eth0`, `ens33`, `wlan0`
- `-t`: 超時時間（選填，單位：毫秒，預設 1500ms）

### 使用範例

```bash
# 使用 enp4s0f2 介面，超時時間 1500ms
sudo ./ipscanner -i enp4s0f2 -t 1500

# 使用 eth0 介面，超時時間 1000ms
sudo ./ipscanner -i eth0 -t 1000

# 使用預設超時時間
sudo ./ipscanner -i ens33
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
Host 140.117.171.148 is alive

Scan completed.
```

## 重要事項

### 1. 執行權限
必須使用 `sudo` 執行，原因：
- 建立 RAW socket 需要 root 權限
- 使用 libpcap 抓取封包需要 root 權限

### 2. 查看網路介面

**方法 1：使用 ip 命令（推薦）**
```bash
ip addr show
```

**方法 2：使用 ifconfig 命令**
```bash
ifconfig
```

輸出範例：
```
2: enp4s0f2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 140.117.171.148/24 brd 140.117.171.255 scope global
    ↑ 這是介面名稱        ↑ 這是 IP 地址
```

### 3. 防火牆設定

確保防火牆允許 ICMP 封包：

**Ubuntu/Debian：**
```bash
# 檢查 ufw 狀態
sudo ufw status

# 如果需要允許 ICMP
sudo ufw allow proto icmp
```

**CentOS/RHEL：**
```bash
# 檢查 firewalld 狀態
sudo firewall-cmd --state

# 允許 ICMP
sudo firewall-cmd --permanent --add-protocol=icmp
sudo firewall-cmd --reload
```

### 4. 測試網路連線

掃描前先測試網路是否正常：
```bash
# Ping 網關（通常是 .1）
ping -c 4 140.117.171.1

# Ping 其他已知主機
ping -c 4 140.117.171.10
```

## 封包結構詳解

### IP Header（20 bytes）
```
版本(V): 4 (IPv4)
Header 長度(HL): 5 (20 bytes)
服務類型(TOS): 0
總長度: 92 bytes (20 + 8 + 8 + 10 + 46 padding)
識別碼(ID): 0
旗標(Flag): Don't Fragment (DF)
存活時間(TTL): 1  (重點：只在子網內傳播)
協定: ICMP (1)
來源 IP: 自動填入
目標 IP: 掃描的目標主機
```

### ICMP Header（8 bytes）
```
類型(Type): 8 (Echo Request)
代碼(Code): 0
檢查碼(Checksum): 自動計算
識別碼(ID): Process ID  (用於識別自己的封包)
序號(Sequence): 1, 2, 3, ... (依序遞增)
```

### Data（10 bytes）
```
內容: 學號（例如："M143040001"）
```

## 程式架構說明

```
ipscanner/
├── main.c              # 主程式：命令列參數、網路介面、掃描邏輯
├── fill_packet.c       # 填充 IP/ICMP header、計算 checksum
├── fill_packet.h       # 結構定義和函數宣告
├── pcap.c              # 使用 libpcap 接收和過濾 ICMP 回應
├── pcap.h              # pcap 相關函數宣告
├── Makefile            # 編譯腳本
└── README.md           # 本說明文件
```

### 程式流程

1. **解析參數**：讀取 `-i` 和 `-t` 參數
2. **初始化**：建立 socket、初始化 pcap
3. **獲取網路資訊**：取得本機 IP 和子網遮罩
4. **計算掃描範圍**：計算子網的第一個和最後一個 IP
5. **掃描迴圈**：
   - 填充 IP header（TTL=1, 目標 IP）
   - 填充 ICMP header（Type=8, ID=PID, Seq）
   - 計算 ICMP checksum
   - 發送封包
   - 等待接收回應（透過 pcap）
   - 如果收到回應，印出「Host X.X.X.X is alive」
6. **完成**：顯示「Scan completed.」

## 依賴套件安裝

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libpcap-dev gcc make
```

### CentOS/RHEL
```bash
sudo yum install libpcap-devel gcc make
```

### Arch Linux
```bash
sudo pacman -S libpcap gcc make
```

## 常見問題排除

### 問題 1：編譯錯誤 "pcap.h: No such file or directory"
**解決方法**：安裝 libpcap-dev
```bash
sudo apt-get install libpcap-dev
```

### 問題 2：執行時錯誤 "Operation not permitted"
**解決方法**：使用 sudo 執行
```bash
sudo ./ipscanner -i eth0 -t 1500
```

### 問題 3：找不到網路介面
**解決方法**：檢查介面名稱是否正確
```bash
# 列出所有網路介面
ip link show

# 或使用
ifconfig -a
```

### 問題 4：沒有掃描到任何主機
**可能原因**：
1. 防火牆阻擋 ICMP
2. 目標主機關閉或設定不回應 ICMP
3. 網路問題
4. Timeout 時間太短

**解決方法**：
```bash
# 增加 timeout 時間
sudo ./ipscanner -i eth0 -t 3000

# 檢查防火牆
sudo ufw status

# 測試單一主機
ping -c 4 140.117.171.1
```

### 問題 5：掃描速度太慢
**原因**：每個主機都要等待 timeout 時間



## 測試環境

- **作業系統**：Ubuntu 24.04 LTS
- **編譯器**：GCC 11.4.0
- **函式庫**：libpcap 1.10.1
- **網路**：Ethernet / Wi-Fi

## 參考資料

- [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/html/rfc792)
- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [Raw Socket Programming](https://www.tenouk.com/Module43a.html)