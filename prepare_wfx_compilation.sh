BUILD_DIR=$(pwd)

echo "Disabling in main Makefile, Search for '-Werror=date-time' and comment the line"
nano Makefile

echo "Adding WFX 'source' to drivers/net/wireless/Kconfig (at the end, before endif '# WLAN')"
echo "
source \"drivers/net/wireless/siliconlabs/wfx/Kconfig\"
"
nano drivers/net/wireless/Kconfig

echo "Adding WFX 'obj' to drivers/net/wireless/Makefile"
echo "
obj-\$(CONFIG_WFX) += siliconlabs/wfx/
"
nano drivers/net/wireless/Makefile

echo "Adding WFX compilation CONFIG flags to my_defconfig"
echo "
#Silabs WF200 WFM200 WF250
CONFIG_WFX=y
CONFIG_WFX_WLAN_SPI=y
CONFIG_WFX_WLAN_SDIO=y
CONFIG_WF200_STA_DEBUG=y
CONFIG_WF200_WSM_DEBUG=y
CONFIG_WF200_TESTMODE=y
"
nano arch/arm/configs/my_defconfig

echo "#### Executing 'make my_defconfig' to apply the modifications"
make my_defconfig

echo "#### Executing 'make modules_prepare' to be ready to compile a new kernel module"
make modules_prepare
