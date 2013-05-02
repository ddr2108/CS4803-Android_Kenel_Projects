#!/bin/bash
if [[ -z "$EMOS_EABI_PATH" ]]
then
    PATH=~/android/aosp/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6/bin/:$PATH
    export EMOS_EABI_PATH=1 
    export ARCH=arm
    export SUBARCH=arm
    export CROSS_COMPILE=arm-eabi-
    echo -e "PATH is now set"
else
    echo -e "PATH is already set for arm-eabi"
fi
