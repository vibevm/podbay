OUT ?= /fast/git/v/research/2026-10-06-podbay-linux-broker-build
CC ?= cc
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wconversion
SQLITE_INCLUDE ?=
SQLITE_LIBRARY ?=

.PHONY: all
all: $(OUT)/broker

$(OUT)/broker: broker.c
	@test "$(OUT)" = /fast/git/v/research/2026-10-06-podbay-linux-broker-build
	@test -f "$(SQLITE_INCLUDE)/sqlite3.h"
	@test -f "$(SQLITE_LIBRARY)"
	mkdir -p "$(OUT)"
	$(CC) $(CFLAGS) -I"$(SQLITE_INCLUDE)" $< -o $@ "$(SQLITE_LIBRARY)"
