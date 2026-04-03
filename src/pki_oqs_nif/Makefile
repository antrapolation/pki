# Makefile for pki_oqs_nif — C NIF wrapping liboqs
#
# Prerequisites:
#   macOS: brew install liboqs
#   Linux: apt install liboqs-dev OR build from source

# Erlang NIF headers
ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval 'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)]).' -s init stop)

# liboqs paths
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  # macOS Homebrew
  LIBOQS_PREFIX ?= $(shell brew --prefix liboqs 2>/dev/null || echo /opt/homebrew/Cellar/liboqs/0.15.0)
else
  # Linux
  LIBOQS_PREFIX ?= /usr/local
endif

LIBOQS_INCLUDE = $(LIBOQS_PREFIX)/include
LIBOQS_LIB = $(LIBOQS_PREFIX)/lib

# Compiler settings
CC ?= cc
CFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter -fPIC -shared
CFLAGS += -I$(ERTS_INCLUDE_DIR) -I$(LIBOQS_INCLUDE)

ifeq ($(UNAME_S),Darwin)
  LDFLAGS = -dynamiclib -undefined dynamic_lookup
  TARGET = priv/oqs_nif.so
else
  LDFLAGS = -shared
  TARGET = priv/oqs_nif.so
endif

# Static link liboqs, dynamic link OpenSSL (liboqs dependency)
LDFLAGS += $(LIBOQS_LIB)/liboqs.a
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -lcrypto
else
  LDFLAGS += -lcrypto
endif

.PHONY: all clean

all: priv $(TARGET)

priv:
	mkdir -p priv

$(TARGET): c_src/oqs_nif.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
