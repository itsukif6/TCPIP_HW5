CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

TARGET = ipscanner
OBJS = main.o fill_packet.o pcap.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

main.o: main.c fill_packet.h pcap.h
	$(CC) $(CFLAGS) -c main.c

fill_packet.o: fill_packet.c fill_packet.h
	$(CC) $(CFLAGS) -c fill_packet.c

pcap.o: pcap.c pcap.h
	$(CC) $(CFLAGS) -c pcap.c

clean:
	rm -f $(TARGET) $(OBJS)