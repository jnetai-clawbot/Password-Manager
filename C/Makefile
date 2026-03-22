# Makefile for Password Manager (C Version)
# Requires: OpenSSL, SQLite3

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcrypto -lsqlite3

# Target
TARGET = password_manager

# Source files
SOURCES = password_manager.c

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET) passwords.db

test: $(TARGET)
	@echo "=== Password Manager Test ==="
	@echo ""
	@echo "1. Initializing database..."
	@echo "testpassword" | ./$(TARGET) --init --db test_passwords.db
	@echo ""
	@echo "2. Adding test entries..."
	./$(TARGET) --add github.com user@example.com secret123 --db test_passwords.db
	./$(TARGET) --add gmail.com another@example.com anotherpass --db test_passwords.db
	@echo ""
	@echo "3. Listing entries..."
	./$(TARGET) --list --db test_passwords.db
	@echo ""
	@echo "4. Getting password..."
	./$(TARGET) --get github.com --db test_passwords.db
	@echo ""
	@echo "=== Test complete ==="

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(TARGET)"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)
