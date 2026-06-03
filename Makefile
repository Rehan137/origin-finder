CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -lcurl -lssl -lcrypto -lm
TARGET = origin_finder
SRC = origin_finder.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Build complete! Run: ./$(TARGET) target.com"

debug:
	$(CC) $(CFLAGS) -g -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.log *.txt *.pem

install:
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)

.PHONY: all clean debug install
