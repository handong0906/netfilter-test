CC = gcc
LIBS = -lnetfilter_queue

TARGET = netfilter-test
SOURCE = main.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -o $(TARGET) $(SOURCE) $(LIBS)

set-rule:
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0

unset-rule:
	sudo iptables -F

clean:
	rm -f $(TARGET)