
CC=gcc

INCS=-I. -I../../util
CFLAGS=-Wall -Wextra -g
LDFLAGS=

BIN=bitmap_test
SRC=test_bitmap.c ../../util/bitmap.c
HDRS=../../util/bitmap.h

$(BIN): $(SRC) $(HDRS)
	@echo 'Building program: $@'
	@$(CC) $(CFLAGS) $(INCS) $(SRC) -o $@ $(LDFLAGS)

all: $(BIN)

test: $(BIN)
	@./$(BIN)

clean:
	@rm -rf $(BIN)

.PHONY: all test clean
