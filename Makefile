CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -Isrc

SRC := src/hmac.c src/sha256/sha256.c tests/test_hmac.c
TARGET := test_hmac

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)