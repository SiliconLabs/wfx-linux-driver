BUILD_DIR=$(pwd)
echo "#### BUILD_DIR     $BUILD_DIR"

KERNEL_VERSION=$(uname -r)
echo $KERNEL_VERSION >  KERNEL_VERSION
echo "#### KERNEL_VERSION      $KERNEL_VERSION"

echo "#### Retrieving FIRMWARE_GIT_HASH from  /usr/share/doc/raspberrypi-bootloader/changelog.Debian.gz (5th item of 1st line with 'firmware as of')"
FIRMWARE_GIT_HASH=$(zgrep "* firmware as of"  /usr/share/doc/raspberrypi-bootloader/changelog.Debian.gz | head -1 | awk '{print $5}' )
echo $FIRMWARE_GIT_HASH >  FIRMWARE_GIT_HASH
echo "#### FIRMWARE_GIT_HASH   $FIRMWARE_GIT_HASH"

echo "#### Downloading Module7.symvers from https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra (for Pi0, download Module.symvers)"
wget https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra/Module7.symvers

echo "#### Renaming Module7.symvers to Module.symvers (Don't do this if using ARM6 like on Pi0)"
mv Module7.symvers  Module.symvers

echo "#### Downloading git_hash file from https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra"
wget https://raw.github.com/raspberrypi/firmware/$FIRMWARE_GIT_HASH/extra/git_hash

echo "#### Retrieving LINUX_GIT_HASH from $BUILD_DIR/git_hash file"
LINUX_GIT_HASH=$(cat git_hash)
echo $LINUX_GIT_HASH   >  LINUX_GIT_HASH
echo "#### LINUX_GIT_HASH     $LINUX_GIT_HASH"

echo "#### Downloading Linux source code from https://raw.github.com/raspberrypi/linux/$LINUX_GIT_HASH"
wget https://github.com/raspberrypi/linux/archive/$LINUX_GIT_HASH.zip

echo "#### Unzipping Linux source code from $LINUX_GIT_HASH.zip"
unzip $LINUX_GIT_HASH.zip

echo "#### Copying  Linux source code from linux-$LINUX_GIT_HASH to $BUILD_DIR"
mv linux-$LINUX_GIT_HASH/* $BUILD_DIR

echo "#### Removing the empty linux-$LINUX_GIT_HASH folder"
rm --recursive --force  linux-$LINUX_GIT_HASH

echo "#### Creating the /proc/config.gz file"
sudo modprobe configs

echo "#### Unzipping /proc/config.gz and moving/renaming the .config file to arch/arm/configs/my_defconfig"
gunzip --keep --stdout /proc/config.gz > $BUILD_DIR/arch/arm/configs/my_defconfig

echo "#### Creating a symbolic link to $BUILD_DIR to use our sources for compilation"
sudo  ln --symbolic  $BUILD_DIR    /lib/modules/$KERNEL_VERSION/build

echo "#### Installing bc (required for compiling)"
sudo apt-get install bc

echo "#### Executing 'make my_defconfig' to re-apply the initial configuration (run this again if you add new kernel compilation configuration)"
make my_defconfig

echo "#### Executing 'make modules_prepare' to be ready to add a new kernel module"
make modules_prepare

echo "executing 'make SUBDIRS=$BUILD_DIR/drivers/i2c/algos/' to check if all is OK (i2c/algos selected because it contains only 3 .c files)"
make SUBDIRS=$BUILD_DIR/drivers/i2c/algos/
