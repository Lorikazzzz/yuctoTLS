# ==============================================================================
# yoctoTLS Makefile
# High-performance custom TLS 1.3 & QUIC & HTTP/3 standalone library
# ==============================================================================

CC      ?= gcc
AR      ?= ar
ARFLAGS ?= rcs

PREFIX  ?= /usr/local

TARGET_A   = libyoctotls.a
TARGET_SO  = libyoctotls.so

# ABI Shared Library Versioning details
VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION_PATCH = 0
VERSION       = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
TARGET_SO_VER = $(TARGET_SO).$(VERSION)
TARGET_SO_MAJ = $(TARGET_SO).$(VERSION_MAJOR)

# Source files
SRCS = aes.c chacha20.c crypto.c mlkem768.c nanotls.c qpack.c quic.c prng.c
OBJS = $(SRCS:.c=.o)

# Base Compiler Flags
CFLAGS_BASE = -Wall -Wextra -I. -Iheaders -fPIC -D_GNU_SOURCE

# Debug vs Production Modes (Default: Production)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS_MODE = -O0 -g -DDEBUG
else
    CFLAGS_MODE = -O3 -DNDEBUG
endif

# Production Hardening Options (Default: Enabled)
HARDEN ?= 1
ifeq ($(HARDEN), 1)
    CFLAGS_HARDEN = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security
    LDFLAGS_HARDEN = -Wl,-z,relro,-z,now
endif

# Strip Symbols for Minimal Binary Footprint (Default: Disabled)
STRIP ?= 0
ifeq ($(STRIP), 1)
    LDFLAGS_STRIP = -s
endif

# Combined Flags
CFLAGS  += $(CFLAGS_BASE) $(CFLAGS_MODE) $(CFLAGS_HARDEN)
LDFLAGS += $(LDFLAGS_HARDEN) $(LDFLAGS_STRIP)

all: $(TARGET_A) $(TARGET_SO_VER)

# Static library build
$(TARGET_A): $(OBJS)
	@printf "  \033[0;32m%-9s\033[0m %s\n" "AR" "$@"
	@$(AR) $(ARFLAGS) $@ $^

# Shared library build with standard dynamic linking ABI versioning (soname)
$(TARGET_SO_VER): $(OBJS)
	@printf "  \033[0;32m%-9s\033[0m %s\n" "LD" "$@"
	@$(CC) -shared $(LDFLAGS) -Wl,-soname,$(TARGET_SO_MAJ) -o $@ $^
	@ln -sf $@ $(TARGET_SO_MAJ)
	@ln -sf $(TARGET_SO_MAJ) $(TARGET_SO)

# Pattern rule for object files
%.o: %.c
	@printf "  \033[0;34m%-9s\033[0m %s\n" "CC" "$<"
	@$(CC) $(CFLAGS) -c $< -o $@

# mlkem768.c is a single-TU amalgamation — suppress external-code warnings
mlkem768.o: mlkem768.c
	@printf "  \033[0;34m%-9s\033[0m %s\n" "CC" "$<"
	@$(CC) $(CFLAGS) -Ipqclean_mlkem -Wno-unused-parameter -Wno-sign-compare -c $< -o $@

# Cleanup rule
clean:
	@printf "  \033[0;31m%-9s\033[0m\n" "CLEAN"
	@rm -f $(OBJS) $(TARGET_A) $(TARGET_SO) $(TARGET_SO_VER) $(TARGET_SO_MAJ) test_tls test_h2 test_quic

# Test Target builds all test executables
test: all
	@printf "  \033[0;33m%-9s\033[0m %s\n" "BUILD" "test_h2 & test_quic"
	@$(CC) $(CFLAGS) testcodes/test_quic.c $(TARGET_A) -o test_quic
	@$(CC) $(CFLAGS) testcodes/test_h2.c $(TARGET_A) -o test_h2

# Installation Targets for Production Deployment
install: all
	@printf "  \033[0;33m%-9s\033[0m %s\n" "INSTALL" "Headers and Libraries to $(PREFIX)"
	@mkdir -p $(DESTDIR)$(PREFIX)/lib
	@mkdir -p $(DESTDIR)$(PREFIX)/include/yoctotls
	@cp -f $(TARGET_A) $(DESTDIR)$(PREFIX)/lib/
	@cp -f $(TARGET_SO_VER) $(DESTDIR)$(PREFIX)/lib/
	@ln -sf $(TARGET_SO_VER) $(DESTDIR)$(PREFIX)/lib/$(TARGET_SO_MAJ)
	@ln -sf $(TARGET_SO_MAJ) $(DESTDIR)$(PREFIX)/lib/$(TARGET_SO)
	@cp -f headers/*.h $(DESTDIR)$(PREFIX)/include/yoctotls/
	@printf "\033[0;32myoctoTLS successfully installed to $(PREFIX)!\033[0m\n"

uninstall:
	@printf "  \033[0;31m%-9s\033[0m %s\n" "UNINSTALL" "Headers and Libraries from $(PREFIX)"
	@rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET_A)
	@rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET_SO)
	@rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET_SO_MAJ)
	@rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET_SO_VER)
	@rm -rf $(DESTDIR)$(PREFIX)/include/yoctotls
	@printf "\033[0;32myoctoTLS successfully uninstalled from $(PREFIX).\033[0m\n"

.PHONY: all clean test install uninstall
