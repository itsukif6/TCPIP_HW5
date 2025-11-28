# 編譯器設定
CC = gcc

# 編譯旗標
# -Wall: 顯示所有警告訊息
# -g: 包含除錯資訊
CFLAGS = -Wall -g

# 連結器旗標
# -lpcap: 連結 libpcap 函式庫（用於封包擷取）
LDFLAGS = -lpcap

# 目標執行檔名稱
TARGET = ipscanner

# 所有的原始碼檔案
SRCS = main.c fill_packet.c pcap.c

# 將 .c 檔案轉換為對應的 .o 檔案名稱
# 例如: main.c -> main.o
OBJS = $(SRCS:.c=.o)

# 預設目標：編譯整個程式
all: $(TARGET)

# 連結所有 .o 檔案生成最終執行檔
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "編譯完成！執行方式: sudo ./$(TARGET) -i [介面名稱] -t [timeout]"

# 編譯規則：將每個 .c 檔案編譯成 .o 檔案
# $< 代表第一個相依檔案（.c 檔）
# $@ 代表目標檔案（.o 檔）
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理編譯產生的檔案
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "清理完成！"

# 清理並重新編譯
rebuild: clean all

# 宣告這些目標不是檔案名稱
.PHONY: all clean rebuild