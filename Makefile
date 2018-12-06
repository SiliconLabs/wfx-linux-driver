ifeq ($(KERNELRELEASE),)

.NOTPARALLEL:

KDIR ?= /lib/modules/$(shell uname -r)/build

all: modules

install: modules_install
	@# When compiling with stock kernel header on Debian, System.map does
	@# not exist. So, Kbuild does not run depmod and our shiny new modules is
	@# not seen
	@echo "Make sure depmod is up-to-date:"
	depmod

%.o: %.c
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

deb-pkg:
	dkms mkdeb --source-only .

else



CFLAGS_debug.o = -I$(src)

wfx-y := \
		fwio.o \
		data_txrx.o \
		main.o \
		queue.o \
		hwio.o \
		bh.o \
		wsm_tx.o \
		wsm_rx.o \
		sta.o \
		scan.o \
		debug.o
wfx-$(CONFIG_NL80211_TESTMODE) += testmode.o
wfx-$(CONFIG_SPI) += wfx_spi.o
wfx-$(subst m,y,$(CONFIG_MMC)) += wfx_sdio.o

obj-m += wfx.o

endif
