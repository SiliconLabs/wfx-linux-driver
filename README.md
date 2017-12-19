# wfx_linux_driver_code

Silicon Laboratories WFx Wi-Fi linux driver source code


Original implementation based on Raspberry Pi drivers in a raspbian distribution.
Evolutions of raspbian distributions are listed in http://downloads.raspberrypi.org/raspbian/release_notes.txt

------------------------------------------------------------------
# STARTING FROM SCRATCH with a blank SD card
First create a SD card with the raspbian version you are interested in from http://downloads.raspberrypi.org/raspbian/images

*Since Linux device tree implementation has been completed as from kernel 4.4, we recommend using kernel 4.4 and above.*

*The description below is based on http://downloads.raspberrypi.org/raspbian/images/raspbian-2017-03-03/, featuring kernel v4.4.50-v7+. The zip file is 1.5 GB and it takes about half an hour to download.*

The procedure to burn a SD card with an .img file can be found here: https://www.raspberrypi.org/documentation/installation/installing-images/README.md

> Keep in mind that if you want to enable SSH on your Pi you need to add an empty 'ssh' file to the root of the SD card prior to plugging it in your Pi.

Plug your SD card in the Pi, power up the Raspberry Pi and move next.

# Identifying your kernel version
Use `uname -r` to retrieve your current kernel version.
```Bash
KERNEL_VERSION=$(uname -r)
```

If it says '4.4.50-V7+' it means you are running Linux Kernel 4.4.50 on an ARM7 or ARM9 processor (in a certain way, '7+' means '9').

------------------------------------------------------------------
# Preparing the Raspberry Pi for kernel module compilation
This is based on the assumptions that:
* Your platform is a Raspberry Pi
* The user is 'pi'. (don't forget to use `sudo raspi-config` to change the 'pi' password and keep you safe).
* You use the Raspberry Pi to compile the new module

NB: What we want to avoid here:
* Cloning a huge repository (the raspberrypi kernel is really huge, with more than 641000 commits!)
* Recompiling the entire Linux kernel (it takes several hours when done on the Pi). We'd rather compile only dedicated modules...
* Cross-compiling. If we can avoid the above 2 items, the Pi is perfectly good for the job of recompiling a single module.

In case you already have a cross-compilation environment for your patform, please jump to the 'Adding the WFX driver to an existing Raspberry Pi' section, which contains information also valid for other platforms.

To prepare a new module compilation (this is valid for any new module), you need to:
## Create a new build directory and cd in this directory
```Bash
mkdir /home/pi/build_dir
cd    /home/pi/build_dir
BUILD_DIR=$(pwd)
```
> NB: We'll use '$BUILD_DIR' in the rest of this doc to refer to the folder you've created to recompile kernel modules.

## Retrieve your original firmware git hash
You can get the 'firmware git hash' from the first lines of /usr/share/doc/raspberrypi-bootloader/changelog.Debian.gz (5th item of 1st line with 'firmware as of') as follows:
```Bash
FIRMWARE_GIT_HASH=$(zgrep "* firmware as of"  /usr/share/doc/raspberrypi-bootloader/changelog.Debian.gz | head -1 | awk '{print $5}' )
```
(for 4.4.50-V7+, the `FIRMWARE_GIT_HASH` is b51046a2b2bb69771579a549d157205d9982f858)

## Retrieve your original table of kernel symbols

The table of kernel symbols is stored under https://github.com/raspberrypi/firmware/tree/$FIRMWARE_GIT_HASH/extra

(for 4.4.50-V7+, the path to the firmware files is https://github.com/raspberrypi/firmware/tree/b51046a2b2bb69771579a549d157205d9982f858/extra).

There are 2 separate symbol files in the folder.

`Modules.symbvers`  is used with ARM6 platforms (Pi0 & Pi1, for instance)

`Modules7.symbvers` is used with ARM7/ARM9 platforms (platforms where $KERNEL_VERSION contains 'v7' or 'v7+', such as Pi2 & Pi 3)

> NB: Since, when compiling, the file needs to be named 'Modules.symvers' in both cases, for ARM7/ARM9 you need to rename the file to Module.symvers

You can retrieve the required symbols table using
```Bash
wget https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra/Module.symvers
```
or
```Bash
wget https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra/Module7.symvers
mv Module7.symvers  Module.symvers
```
> :raising_hand: **Note** here that for 4.4.50-V7+ (which is using an ARM7/ARM9, as indicated by the **'7+'**) you need to use the Module**7**.symvers file, and it needs to be named **Module.symvers** when copied to $BUILD_DIR/Module.symvers.

## Retrieve your linux git hash (for the kernel source code)
The 'linux git hash' value is stored in the firmware `extra` folder in a file named 'git_hash'
```Bash
wget https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra/git_hash
LINUX_GIT_HASH=$(cat git_hash)
```

## Download the linux source code for your 'linux git hash'
The linux source code is stored under https://github.com/raspberrypi/linux/commit/$LINUX_GIT_HASH.
To browse it, go to https://github.com/raspberrypi/linux/commit/master and replace 'master' with your LINUX_GIT_HASH value.
Download the linux source code using the 'Browse files' then 'Clone or Download'/'Download ZIP' buttons or
```Batch
wget https://github.com/raspberrypi/linux/archive/$LINUX_GIT_HASH.zip
```
Unzip the linux source code using
```Batch
unzip $LINUX_GIT_HASH.zip
```
Move the linux source code to the root of your build folder using
```Batch
mv linux-$LINUX_GIT_HASH/* $BUILD_DIR
```
Finally remove the empty folder using
```Batch
rm --recursive --force linux-$LINUX_GIT_HASH
```

## Retrieve the original Pi kernel configuration file
The usual name for the previously used configuration is `.config`. It is normally located at the root of the build folder.
On Raspberry Pi, this file is not directly visible. You need to execute `sudo modprobe configs` to get the /proc/config.gz file to be created.
```Batch
sudo modprobe configs
```
Then you can unzip the file and move it as 'my_defconfig' in the arm/arch/configs folder as follows:
```Batch
gunzip --keep --stdout /proc/config.gz > $BUILD_DIR/arch/arm/configs/my_defconfig
```
We will add compilation options in this file to enable a new module compilation, and set the possible compilation options for the new module.

NB: all files in arch/arm/configs/ ending with '_defconfig' can be used to do a `make <prefix>_defconfig` to select between different kernel configurations. This means that you can create several such files to cope with different setups.

## Configure the build chain
Create a symbolic link to your new build folder in /lib/modules/$KERNEL_VERSION
This link will be used by the compiler to locate the source code to compile
```Bash
sudo  ln --symbolic  $BUILD_DIR    /lib/modules/$KERNEL_VERSION/build
```

## Install 'bc' if not already installed
'bc' is required to handle clock-related stuff during compilation. Since it's not installed by default on the Raspberry Pi you need to install it.
```Bash
sudo apt-get install bc
```

## Configure modules compilation
To be ready to add new modules, we first want to make sure that we can recompile any already existing module without errors.
To configure compilation with the original configuration, use:
```Bash
cd $BUILD_DIR
make my_defconfig
```

## Prepare for modules compilation
We do this to make sure everything is fine, as well as to save time on future compilations.
```Bash
cd $BUILD_DIR
make modules_prepare
```

### Check compilation of an already existing module
We select one simple module in the i2c drivers to keep if fast (this folder only contains 3 .c files).
```Bash
cd $BUILD_DIR
make SUBDIRS=$BUILD_DIR/drivers/i2c/algos/
```
This should compile without errors, and the resulting .ko file should be created under $BUILD_DIR/drivers/i2c/algos within seconds.

> The `prepare_module_compilation.sh` script will do the above steps automatically.
> Just download it from this repository and execute it once in your new BUILD_DIR

------------------------------------------------------------------
# Adding the WFX driver to an existing Raspberry Pi

Before using the WFX driver on your setup, you need to compile it for your platform.
We describe this process below, considering that the Raspberry Pi preparation for kernel module compilation described above has been completed.

You need to:
## Clone the wfx driver source code from https://github.com/SiliconLabs/WFX-driver.
```Bash
cd $BUILD_DIR
mkdir drivers/net/wireless/silabs_sources
cd    drivers/net/wireless/silabs_sources
git clone https://<username>@stash.silabs.com/scm/whifer_software/wfx_linux_driver_production.git
cd    drivers/net/wireless
cp -r silabs_sources/  .
```

## Unzip the WFX driver
```Bash
cd $BUILD_DIR
unzip $WFX_GIT_HASH.zip
```

## Move the WFX driver source code under $BUILD_DIR/drivers/net/wireless
```Bash
cp  --recursive $BUILD_DIR/$WFX_GIT_HASH/*  $BUILD_DIR/drivers/net/wireless/siliconlabs/wfx
```

## Adding our new module to the Kbuild configuration
Add the following lines near the end of $BUILD_DIR/drivers/net/wireless/Kconfig using
```Bash
cd $BUILD_DIR
nano drivers/net/wireless/Kconfig
```
> NB: This line must be added before the `endif # WLAN` line. The best location is at the end of other `source` lines.
Add:
```Makefile
source "drivers/net/wireless/siliconlabs/wfx/Kconfig"
```

## Adding our new module files to the make process
Add the following lines at the end of $BUILD_DIR/drivers/net/wireless/Makefile using
```Bash
cd $BUILD_DIR
nano drivers/net/wireless/Makefile
```
Add:
```Makefile
obj-$(CONFIG_WFX) += siliconlabs/wfx/
```

## Configuring compilation for WFX
Add the following compilation flags at the end of %BUILD_DIR/arch/arm/configs/my_defconfig using
```Bash
cd $BUILD_DIR
nano arch/arm/configs/my_defconfig
```
Add
```Makefile
#Silabs WF200 WFM200 WF250
CONFIG_WFX=y
CONFIG_WFX_WLAN_SPI=y
CONFIG_WFX_WLAN_SDIO=y
CONFIG_WF200_STA_DEBUG=y
CONFIG_WF200_WSM_DEBUG=y
CONFIG_WF200_TESTMODE=y
```

## Reconfigure to take into account our changes in my_defconfig
```Bash
cd $BUILD_DIR
make my_defconfig
```

## Prepare for modules compilation with our changes
```Bash
cd $BUILD_DIR
make modules_prepare
```
> The `prepare_wfx_compilation.sh` script will help you perform the above steps automatically (to be completed!).
> Just download it from this repository and execute it once in your BUILD_DIR

------------------------------------------------------------------
# Compiling the WFX module
```Bash
cd $BUILD_DIR
make SUBDIRS=drivers/net/wireless/siliconlabs/wfx
```
### Check:
The corresponding .ko files are created under $BUILD_DIR/drivers/net/wireless/siliconlabs/wfx

------------------------------------------------------------------
# Prepare module installation
Update the nano include/config/kernel.release file to match your $KERNEL_VERSION. This is required to have the new module files copied to the correct folder.
```Bash
cd $BUILD_DIR
uname -r > include/config/kernel.release
```

### Check:
```Bash
cd $BUILD_DIR
cat  include/config/kernel.release
```

------------------------------------------------------------------
# Installing the WFX module
```Bash
cd $BUILD_DIR
sudo make SUBDIRS=drivers/net/wireless/siliconlabs/wfx  modules_install
```
### Check:
The corresponding .ko files are copied from the compilation folder to /lib/modules/$KERNEL_VERSION/extra
```Bash
ls -al /lib/modules/$KERNEL_VERSION/extra
```

------------------------------------------------------------------
# Updating the kernel modules dependencies
This is to allow our new module to be 'probed'
```Bash
sudo depmod -a
```
### Check:
```Bash
sudo modinfo wfx_wlan_spi
```
```Makefile
filename:       '/lib/modules/4.4.50-v7+/extra/wfx_wlan_spi.ko'
alias:          spi:wfx_wlan_spi
license:        GPL
description:    mac80211 SILABS WIRELESS SPI driver
srcversion:     695EF2C96A0A61163DF4230
alias:          of:N*T*Csiliconlabs,wfx-wlan-spi*
alias:          spi:wfx_spi
depends:        wfx_core
vermagic:       4.4.50-v7 SMP mod_unload modversions ARMv7
```

The path to the wfx_wlan_spi.ko file is from the 'extra' folder corresponding to your $KERNEL_VERSION

------------------------------------------------------------------
# Enabling the WFX driver
```Bash
sudo modprobe wfx_wlan_spi
```
### Check:
```Bash
lsmod | grep wfx
```

The wfx driver is loaded (i.e. it appears in 'lsmod'). If not, check the result of:
```Bash
sudo vcdbg log msg
```
or
```Bash
dmesg | grep 'wf\|WF'
```
for any error message related to wfx/wf200.

------------------------------------------------------------------
# (Pi3 only) Disabling the native WiFi interface
Pi # has an on-board WiFi interface, so it needs to be disabled to test WFX parts
To do so, we blacklist the brcmfmac (BRoadCoM Full MAC) driver in /etc/modprobe.d/fbdev-blacklist.conf (su privileges required)
```Bash
sudo nano /etc/modprobe.d/fbdev-blacklist.conf
```
Add
```Makefile
blacklist brcmfmac
```

------------------------------------------------------------------
# Selecting the WFX driver as your WiFi interface
We need to use the device tree mechanism to interconnect the WFX HW and driver. To do so we need to add the corresponding device tree files.
If using the SPI bus, we need to enable it in the device tree.
We also need to indicate which device tree blob we're using, as well as the name of our driver in a device tree overlay.

## WFX device tree files
Download the wfx-spi.dtbo and wfx-spi.dts files from the present repository and copy them to /boot/overlays
```Bash
cd /home/pi/Downloads
cp wfx-spi.dts  /boot/overlays/
cp wfx-spi.dtbo /boot/overlays/
```
## WFX firmware and PDS files
Download the wfx_wfm.sec file from the present repository and copy it to /lib/firmware/
```Bash
cd /home/pi/Downloads
cp wfm_wf200.sec  /lib/firmware/
cp pds_wf200.json /lib/firmware/
```

## WFX Configuration
Once the WFX files are copied to the proper places, the configuration is all set in /boot/config.txt (su privileges required).
```Bash
sudo nano /boot/config.txt
```
To allow using the SPI bus, add or uncomment (it's already present by default)
```Makefile
dtparam=spi=on
```
To select the 'core' device tree, add:
> (CAUTION: If this is wrongly set, your Pi may not start anymore. In this situation, extract the SD card, insert it as a mass storage device in another machine and edit the 'config.txt' file at the root of the SD card to revert your changes)

```Makefile
device_tree=bcm2710-rpi-3-b.dtb
dtoverlay=wfx-spi
```
## reboot
```Bash
sudo reboot
```
### Checks:
After rebooting, you should see the device tree load process traces when executing
```Bash
sudo vcdbg log msg
```
Look  for
```Bash
001309.361: Loading 'bcm2709-rpi-2-b_4.4.39-v7.dtb' to 0x41013c size 0x3bfc
001411.787: dtparam: audio=on
001422.431: dtparam: spi=on
001442.389: Loaded overlay 'wfx-spi'
```
These should match settings in /boot/config.txt:
```Bash
cat /boot/config.txt | grep ^device_tree
cat /boot/config.txt | grep ^dtparam
cat /boot/config.txt | grep ^dtoverlay
```
In addition to this, you should see traces from WFX FW download when using
```Bash
dmesg | grep 'wf\|WF'
```

------------------------------------------------------------------
# Scanning for WiFi networks
```Bash
sudo iw dev wlan0 scan | grep SSID
```
### Check:
Existing access points in your area are listed, with the corresponding SSIDs

------------------------------------------------------------------
# Preparing a WiFi connection to a selected AP (Access Point)
The tool used to control the Raspberry Pi in STA mode (STAtion Mode) is called the wpa-supplicant.
The wpa-supplicant configuration is normally stored in the /etc/wpa_supplicant/wpa_supplicant.conf file.

We can check that this is the case (or figure out which alternate file is used) using
```Bash
ifquery wlan0
```
This will show the path to the wpa-supplicant configuration file.
NB: this is in fact one line from /etc/network/interfaces, selected by 'ifquery'.

## Editing the wpa-supplicant configuration
Once the wpa-supplicant configuration file is known, we can edit it (with su privileges) to add the list of networks we want to connect to.
```Bash
sudo nano /etc/wpa_supplicant/wpa_supplicant.conf
```
To allow a WiFi connection to our AP of choice, we need to add a section with the following text per network:
```Makefile
network={
         ssid="<AP_SSID>"
         psk="<private_shared_key>"
         key_mgmt=WPA-PSK
}
```
The <AP_SSID> matches one of the SSIDs we can scan.

The <private_shared_key> matches the secret passphrase for this AP.

> Networks will be used depending on the capability to connect to each of them, the first one in the file being selected if several are within range.

## Reloading the wpa-supplicant configuration
```Bash
wpa_cli -i wlan0 reconfigure
```
> wpa_cli is the command line interface to the wpa_supplicant. When called without any argument it will enter an interactive mode, waiting for user input.

## Checking WiFi connectivity
```Bash
wpa_cli status
```
### Check:
If all went well, the 'ssid' line will match the name you selected in the configuration.

------------------------------------------------------------------
# AP or STA?
A short command useful to know which mode you're in (AP mode uses hostapd and SAT mode uses the wpa-supplicant)
```Bash
ps -e | grep 'wpa\|host'
```
If the result shows 'wpa_supplicant' you're in STAtion mode.
If it shows 'hostapd', you're in Access Point (AP) mode.

------------------------------------------------------------------
# Checking Device Tree loading
```Bash
sudo vcdbg log msg
```
Look  for
```Bash
001309.361: Loading 'bcm2709-rpi-2-b_4.4.39-v7.dtb' to 0x41013c size 0x3bfc
001411.787: dtparam: audio=on
001422.431: dtparam: spi=on
001442.389: Loaded overlay 'wfx-spi'
```
These should match settings in /boot/config.txt:
```Bash
cat /boot/config.txt | grep ^device_tree
cat /boot/config.txt | grep ^dtparam
cat /boot/config.txt | grep ^dtoverlay
```

------------------------------------------------------------------
# How to Retrieve the official image for your Pi

Check the date at the end of the first line ('Raspberry Pi reference YYYY-MM-DD') of /etc/rpi-issue using `cat /etc/rpi-issue`

NB: The explanations above are based on the 2017-03-02 issue, using linux kernel 4.4.50-V7+.

Unfortunately, it can be a bit tricky to locate a specific image on http://downloads.raspberrypi.org/raspbian/images because the names of the folders often don't exactly match the content of the /etc/rpi-issue file, probably since they were automatically created the day after the image generation. 

Looking for the 2017-03-02 images, we look into http://downloads.raspberrypi.org/raspbian/images/raspbian-2017-03-03/ (using the closest date following 2017-03-02) and we can find there the packages properly named with 2017-03-02:
```Bash
2017-03-02-raspbian-jessie.zip            03-Mar-2017 16:27  1.5G
2017-03-02-raspbian-jessie.zip.sha1       03-Mar-2017 17:47   118
2017-03-02-raspbian-jessie.zip.torrent    03-Mar-2017 17:48   30K 
```

Download the package to your machine, in order to create a new SD card.

NB: If you create a new SD card based on this official package, you will need to add the WFX driver again, as described above.
