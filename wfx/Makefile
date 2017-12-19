# Makefile 
# Silicon Labs WF200 WiFi SPI/SDIO Module

wfx_core-y := fwio.o fwio_sb.o txrx.o main.o queue.o hwio.o bh.o wsm.o sta.o scan.o pds/pds_parser.o pds/jsmn/jsmn.o debug.o wfx_cmd.o

wfx_core-$(CONFIG_WF200_TESTMODE) += testmode/testmode.o testmode/tm_hif.o testmode/tm_bitstream.o
wfx_core-$(CONFIG_PM)	+= pm.o

# allows the HI msg traces output
# -------------------------------
#CFLAGS_wsm.o += -DDEBUG
#CFLAGS_sta.o += -DDEBUG
#CFLAGS_txrx.o += -DDEBUG
#CFLAGS_bh.o += -DDEBUG

wfx_wlan_sdio-y := wfx_sdio.o
wfx_wlan_spi-y := wfx_spi.o

# Generates wfx module
#---------------------
# wfx_core.ko
obj-$(CONFIG_WFX) += wfx_core.o
# wfx_wlan_sdio.ko
obj-$(CONFIG_WFX_WLAN_SDIO) += wfx_wlan_sdio.o
# wfx_wlan_spi.ko
obj-$(CONFIG_WFX_WLAN_SPI) += wfx_wlan_spi.o
