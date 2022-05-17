![Alt text](https://www.advantech.tw/css/css-img/advantech-logo-notagl.svg "Advantech sbl")

# UEFI Payload Modification

    X001_1  Add DEBUG_ENABLE define to switch PLATFORM_BOOT_TIMEOUT 3 or 0.
    X001_2  Add Bios String support.
    X001_3  Removed Serial Io "Initialized" flag.

# UEFI Payload Build Step

#   Get EDK2 Source Code

    git clone --recurse-submodules https://github.com/tianocore/edk2.git edk2

#   Update EDK2 Source Module

    cd edk2
    git submodule update --recursive

#   Execute Batch for EDK2 enviroment

    edksetup.bat

#   Build base tools of EDK2 

    cd BaseTools
    toolsetup.bat Rebuild VS2017
    cd ..

#   Build UEFIPayload package

    build -a X64 -b DEBUG   -t VS2017 -D BOOTLOADER=SBL -p UefiPayloadPkg\UefiPayloadPkg.dsc
    build -a X64 -b RELEASE -t VS2017 -D BOOTLOADER=SBL -p UefiPayloadPkg\UefiPayloadPkg.dsc

