/** @file
  This driver will report some MMIO/IO resources to dxe core, extract smbios and acpi
  tables from bootloader.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
#include <Library/HobLib.h>
#include <Library/PrintLib.h>

#include <Guid/BiosStringHob.h>

#define ISTRSIZE    128

  EFI_PEI_BIOS_STRING_HOB TempBS = {
    1,
    10,
    'V',
    {"01/01/2018"},
    {"XXXX"},
    {"1234"}
  };

//----------------------------------------------------------------------------
//              
// Procedure:	BIOSStringCallBackReadyToBoot
//
// Description:	Call back function when ReadytoBoot event signal
// 
//
// Input:	    EFI_EVENT Event 
//		        VOID* Context
//
// Output:	    None 
//              
//----------------------------------------------------------------------------

VOID
EFIAPI
BIOSStringCallBackReadyToBoot (
  IN      EFI_EVENT  Event,
  IN      VOID       *Context
  )
{
    EFI_STATUS    Status;
    UINT8         iString[ISTRSIZE];
    UINTN         iStringSize = 0x40;
    EFI_PEI_BIOS_STRING_HOB *mBiosString = &TempBS;
    
    Status = EFI_SUCCESS;

    AsciiSPrintUnicodeFormat (iString, 
                              ISTRSIZE, 
                              L"%s %a-%a BIOS %c%d.%02d (%a) %s", 
                              L"****",
                              mBiosString->ProjectDep,
                              mBiosString->ProjectName,
                              mBiosString->BIOSFormalVersion,
                              mBiosString->BIOSMajorVersion,
                              mBiosString->BIOSMinorVersion,
                              mBiosString->ProjectBuildDate,
                              L"****");

    iStringSize = AsciiStrLen (iString);

    //
    // Create BIOS String variable
    //
    Status = gRT->SetVariable (
              L"BIOSString",
              &gAhcBiosStringGuid,
              EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
              iStringSize,
              iString
              );

}

/**
  Main entry for the bootloader support DXE module.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
BiosStringEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS              Status;
  EFI_EVENT               Event;
  EFI_HOB_GUID_TYPE       *GuidHob1;
  EFI_PEI_BIOS_STRING_HOB *NewBiosInfo;

  Status = EFI_SUCCESS;

  GuidHob1 = GetFirstGuidHob (&gAhcBiosStringGuid);
  if (GuidHob1 != NULL) {
    NewBiosInfo = (EFI_PEI_BIOS_STRING_HOB *)GET_GUID_HOB_DATA (GuidHob1);
    CopyMem (&TempBS, NewBiosInfo, sizeof (EFI_PEI_BIOS_STRING_HOB));
    DEBUG ((DEBUG_INFO, "TempBS %a-%a\n", TempBS.ProjectDep,TempBS.ProjectName));
    DEBUG ((DEBUG_INFO, "NewBiosInfo %a-%a\n", NewBiosInfo->ProjectDep,NewBiosInfo->ProjectName));
  }
  
  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             BIOSStringCallBackReadyToBoot,
             NULL,
             &Event
             );
  

  return Status;
}
