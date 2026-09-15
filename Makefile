CC      ?= gcc
MULTIARCH := $(shell $(CC) -print-multiarch)
PAM_DIR ?= /lib/$(MULTIARCH)/security

CFLAGS  := -shared -fPIC -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
           -Wall -Wextra -Wl,-z,relro -Wl,-z,now
LIBS    := -lpam

TARGET  := pam_hkpac.so
SRC     := pam_hkpac.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: $(TARGET)
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 644 $(TARGET) $(DESTDIR)$(PAM_DIR)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
