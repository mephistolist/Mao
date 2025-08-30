CC        := cc
OUT       := mao
CPU := $(shell gcc -Q -march=native --help=target 2>/dev/null | grep -m1 march= | awk '{print $$2}' || echo native)
SRC       := shell.c
PORT_SRC  := port.c
BINDIR    := /usr/bin
CHMOD     := chmod +x

CFLAGS    := -static -s -pipe -march=$(CPU) -O2 -std=gnu17 -Wextra -pedantic \
             -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident \
             -ffunction-sections -fdata-sections -falign-functions=1 \
             -falign-loops=1 --no-data-sections -falign-jumps=1 \
             -falign-labels=1 -flto -fipa-icf

LDFLAGS   := -Wl,-z,norelro -Wl,-O1 -Wl,--build-id=none -Wl,-z,separate-code

.PHONY: all clean install

all: $(OUT) port.so

$(OUT): $(SRC)
	$(CC) $(SRC) -o $@ $(CFLAGS) $(LDFLAGS)

port.so: $(PORT_SRC)
	$(CC) -shared -fPIC -O2 -s -pipe -march=$(CPU) -o $@ $(PORT_SRC) -ldl

install: all
	install -Dm755 $(OUT) $(BINDIR)/$(OUT)

clean:
	rm -f $(OUT) $(CLIENT) port.so
