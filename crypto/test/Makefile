
CC=gcc

INCS=-I. -I..
CFLAGS=-Wall
LDFLAGS=

BIN=crypto_test
HDRS=$(wildcard *.h ../*.h)
SRC=$(wildcard *.c ../*.c)

$(BIN): $(HDRS) $(SRC)
	@echo 'Building program: $@'
	@$(CC) $(CFLAGS) $(INCS) $(SRC) -o $@ $(LDFLAGS)

all: $(BIN)

clean:
	@rm -rf $(BIN)

.PHONY: all clean

