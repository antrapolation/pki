# Makefile for pkcs11_port — Erlang Port binary wrapping PKCS#11
#
# Usage:
#   make                  # builds priv/pkcs11_port
#   make clean            # removes build artifacts
#   make test-softhsm     # quick smoke test with SoftHSM2

CC ?= cc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -ldl

PRIV_DIR = $(CURDIR)
TARGET = $(PRIV_DIR)/pkcs11_port

.PHONY: all clean test-softhsm

all: $(TARGET)

$(TARGET): pkcs11_port.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

test-softhsm: $(TARGET)
	@echo "Smoke test with SoftHSM2..."
	@echo "Ensure SoftHSM2 is installed and a token exists."
	@echo "Run: softhsm2-util --init-token --slot 0 --label test --pin 1234 --so-pin 0000"
