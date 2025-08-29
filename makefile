CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC = src/main.c src/obf.c src/aes128e.c
NIST_SRC = test/nist_test.c src/obf.c src/aes128e.c

OUT = aes_ofb
NIST_OUT = nist_test

all: $(OUT) $(NIST_OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

$(NIST_OUT): $(NIST_SRC)
	$(CC) $(CFLAGS) -o $(NIST_OUT) $(NIST_SRC)

clean:
	rm -f $(OUT) $(NIST_OUT)
