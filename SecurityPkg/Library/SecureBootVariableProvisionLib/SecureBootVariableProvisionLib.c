/** @file
  This library provides functions to set/clear Secure Boot
  keys and databases.

  Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2018 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2021, ARM Ltd. All rights reserved.<BR>
  Copyright (c) 2021, Semihalf All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <UefiSecureBoot.h>
#include <Guid/GlobalVariable.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/SecureBootVariableLib.h>
#include <Library/SecureBootVariableProvisionLib.h>
#include <Library/DxeServicesLib.h>
//X003
#include <Library/HobLib.h>
#include <Guid/BiosStringHob.h>


/**
  Searches all the availables firmware volumes and returns the first matching FFS section.

  This function searches all the firmware volumes for FFS files with an FFS filename specified by NameGuid.
  The order that the firmware volumes is searched is not deterministic. For each FFS file found a search
  is made for FFS sections of type SectionType. If the FFS file contains at least SectionInstance instances
  of the FFS section specified by SectionType, then the SectionInstance instance is returned in Buffer.
  Buffer is allocated using AllocatePool(), and the size of the allocated buffer is returned in Size.
  It is the caller's responsibility to use FreePool() to free the allocated buffer.
  See EFI_FIRMWARE_VOLUME2_PROTOCOL.ReadSection() for details on how sections
  are retrieved from an FFS file based on SectionType and SectionInstance.

  If SectionType is EFI_SECTION_TE, and the search with an FFS file fails,
  the search will be retried with a section type of EFI_SECTION_PE32.
  This function must be called with a TPL <= TPL_NOTIFY.

  If NameGuid is NULL, then ASSERT().
  If Buffer is NULL, then ASSERT().
  If Size is NULL, then ASSERT().


  @param  NameGuid             A pointer to to the FFS filename GUID to search for
                               within any of the firmware volumes in the platform.
  @param  SectionType          Indicates the FFS section type to search for within
                               the FFS file specified by NameGuid.
  @param  SectionInstance      Indicates which section instance within the FFS file
                               specified by NameGuid to retrieve.
  @param  Buffer               On output, a pointer to a callee allocated buffer
                               containing the FFS file section that was found.
                               Is it the caller's responsibility to free this buffer
                               using FreePool().
  @param  Size                 On output, a pointer to the size, in bytes, of Buffer.

  @retval  EFI_SUCCESS          The specified FFS section was returned.
  @retval  EFI_NOT_FOUND        The specified FFS section could not be found.
  @retval  EFI_OUT_OF_RESOURCES There are not enough resources available to
                                retrieve the matching FFS section.
  @retval  EFI_DEVICE_ERROR     The FFS section could not be retrieves due to a
                                device error.
  @retval  EFI_ACCESS_DENIED    The FFS section could not be retrieves because the
                                firmware volume that
                                contains the matching FFS section does not allow reads.
**/
EFI_STATUS
EFIAPI
GetSectionFromHob (
  IN CONST  EFI_GUID          *NameGuid,
  IN        EFI_SECTION_TYPE  SectionType,
  IN        UINTN             SectionInstance,
  OUT       VOID              **Buffer,
  OUT       UINTN             *Size
  )
{
  EFI_STATUS                Status = EFI_NOT_FOUND;
  UINT8                     *SectionBuffer = NULL;
  UINT32                    SectionBufferSize = 0;
  EFI_HOB_GUID_TYPE         *GuidHob;
  EFI_SECURE_BOOT_KEYS_HOB  *KeysHob;

  GuidHob = GetFirstGuidHob (&gEfiGlobalVariableGuid);
  if (GuidHob == NULL) {
    return Status;
  }
  KeysHob = (EFI_SECURE_BOOT_KEYS_HOB *)GET_GUID_HOB_DATA (GuidHob);

  if (CompareGuid (NameGuid, &gDefaultPKFileGuid)) {
    if (KeysHob->PKKeySize != 0) {
      SectionBuffer = (UINT8 *)(UINTN) (KeysHob->PKKeyAddress);
      SectionBufferSize = KeysHob->PKKeySize;
    }
  } else if (CompareGuid (NameGuid, &gDefaultKEKFileGuid)) {
    if (KeysHob->KEKKeySize != 0) {
      SectionBuffer = (UINT8 *)(UINTN) (KeysHob->KEKKeyAddress);
      SectionBufferSize = KeysHob->KEKKeySize;
    }
  } else if (CompareGuid (NameGuid, &gDefaultdbFileGuid)) {
    if (KeysHob->DBKeySize != 0) {
      SectionBuffer = (UINT8 *)(UINTN) (KeysHob->DBKeyAddress);
      SectionBufferSize = KeysHob->DBKeySize;
    }
  } else if (CompareGuid (NameGuid, &gDefaultdbxFileGuid)) {
    if (KeysHob->DBXKeySize != 0) {
      SectionBuffer = (UINT8 *)(UINTN) (KeysHob->DBXKeyAddress);
      SectionBufferSize = KeysHob->DBXKeySize;
    }
  } else if (CompareGuid (NameGuid, &gDefaultdbtFileGuid)) {
    if (KeysHob->DBTKeySize != 0) {
      SectionBuffer = (UINT8 *)(UINTN) (KeysHob->DBTKeyAddress);
      SectionBufferSize = KeysHob->DBTKeySize;
    }
  }

  if ((SectionBuffer != NULL) && (SectionBufferSize != 0)) {
      UINT8 *pkey = SectionBuffer;
      UINT32 total = 0;
      UINT32 onekey = 0;
      UINT8 i;

      for (i = 0; i < SectionInstance; i++) {
        onekey = (*((UINT32 *)pkey) & 0xFFFFFF);
        if ((onekey & 0x3) != 0)
          onekey = onekey + (4 - (onekey & 0x3));

        total = total + onekey;
        pkey = pkey + onekey;
      }

      if (total < SectionBufferSize) {
        *Size = (UINTN) (*((UINT32 *)pkey) & 0xFFFFFF) - 4;
        *Buffer = (VOID *)(pkey+4);
        //DEBUG ((DEBUG_INFO, "SecureBootFetchData: Buffer: %p Size: %x\n", *Buffer, *Size));
        Status = EFI_SUCCESS;

      }
  }
  return Status;
}

/**
  Create a EFI Signature List with data fetched from section specified as a argument.
  Found keys are verified using RsaGetPublicKeyFromX509().

  @param[in]        KeyFileGuid    A pointer to to the FFS filename GUID
  @param[out]       SigListsSize   A pointer to size of signature list
  @param[out]       SigListOut    a pointer to a callee-allocated buffer with signature lists

  @retval EFI_SUCCESS              Create time based payload successfully.
  @retval EFI_NOT_FOUND            Section with key has not been found.
  @retval EFI_INVALID_PARAMETER    Embedded key has a wrong format.
  @retval Others                   Unexpected error happens.

**/
STATIC
EFI_STATUS
SecureBootFetchData (
  IN  EFI_GUID            *KeyFileGuid,
  OUT UINTN               *SigListsSize,
  OUT EFI_SIGNATURE_LIST  **SigListOut
  )
{
  EFI_STATUS                    Status;
  VOID                          *Buffer;
  VOID                          *RsaPubKey;
  UINTN                         Size;
  UINTN                         KeyIndex;
  UINTN                         Index;
  SECURE_BOOT_CERTIFICATE_INFO  *CertInfo;
  SECURE_BOOT_CERTIFICATE_INFO  *NewCertInfo;
  BOOLEAN     KeysFromHob = FALSE;

  KeyIndex      = 0;
  *SigListOut   = NULL;
  *SigListsSize = 0;
  CertInfo      = AllocatePool (sizeof (SECURE_BOOT_CERTIFICATE_INFO));
  NewCertInfo   = CertInfo;
  while (1) {
    if (NewCertInfo == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      break;
    } else {
      CertInfo = NewCertInfo;
    }

    Status = GetSectionFromHob (
               KeyFileGuid,
               EFI_SECTION_RAW,
               KeyIndex,
               &Buffer,
               &Size
               );
//    DEBUG ((DEBUG_INFO, "SecureBootFetchData: GetSectionFromHob: %r\n", Status));
    if (Status == EFI_SUCCESS)
      KeysFromHob = TRUE;

    if (!KeysFromHob && (Status != EFI_SUCCESS)) {
    Status = GetSectionFromAnyFv (
               KeyFileGuid,
               EFI_SECTION_RAW,
               KeyIndex,
               &Buffer,
               &Size
               );
//    AsciiPrint ("SecureBootFetchData: GetSectionFromAnyFv: %r\n", Status);
        DEBUG ((DEBUG_INFO, "SecureBootFetchData: GetSectionFromAnyFv: %r\n", Status));
//        DEBUG ((DEBUG_INFO, "SecureBootFetchData: GetSectionFromAnyFv: %r\n",Buffer, Size));
        DEBUG ((DEBUG_INFO, "GetSectionFromAnyFv: %p %x\n", Buffer, Size));
    }

    if (Status == EFI_SUCCESS) {
      RsaPubKey = NULL;
        DEBUG ((DEBUG_INFO, "key format: %p %x\n", Buffer, Size));
      if (RsaGetPublicKeyFromX509 (Buffer, Size, &RsaPubKey) == FALSE) {
        DEBUG ((DEBUG_ERROR, "%a: Invalid key format: %d\n", __func__, KeyIndex));
        FreePool (Buffer);
        Status = EFI_INVALID_PARAMETER;
        break;
      }

        DEBUG ((DEBUG_INFO, "CertInfo %x: %p %x\n", KeyIndex, Buffer, Size));
      CertInfo[KeyIndex].Data     = Buffer;
      CertInfo[KeyIndex].DataSize = Size;
      KeyIndex++;
      NewCertInfo = ReallocatePool (
                      sizeof (SECURE_BOOT_CERTIFICATE_INFO) * KeyIndex,
                      sizeof (SECURE_BOOT_CERTIFICATE_INFO) * (KeyIndex + 1),
                      CertInfo
                      );
    }

    if (Status == EFI_NOT_FOUND) {
      Status = EFI_SUCCESS;
      break;
    }
  }

  if (EFI_ERROR (Status)) {
    goto Cleanup;
  }

  if (KeyIndex == 0) {
    Status = EFI_NOT_FOUND;
    goto Cleanup;
  }

  // Now that we collected all certs from FV, convert it into sig list
  Status = SecureBootCreateDataFromInput (SigListsSize, SigListOut, KeyIndex, CertInfo);
  if (EFI_ERROR (Status)) {
    goto Cleanup;
  }

Cleanup:
  if (CertInfo) {
    for (Index = 0; Index < KeyIndex; Index++) {
      if (!KeysFromHob)
        FreePool ((VOID *)CertInfo[Index].Data);
    }

    FreePool (CertInfo);
  }

  return Status;
}

/**
  Enroll a key/certificate based on a default variable.

  @param[in] VariableName        The name of the key/database.
  @param[in] DefaultName         The name of the default variable.
  @param[in] VendorGuid          The namespace (ie. vendor GUID) of the variable

  @retval EFI_OUT_OF_RESOURCES   Out of memory while allocating AuthHeader.
  @retval EFI_SUCCESS            Successful enrollment.
  @return                        Error codes from GetTime () and SetVariable ().
**/
STATIC
EFI_STATUS
EnrollFromDefault (
  IN CHAR16    *VariableName,
  IN CHAR16    *DefaultName,
  IN EFI_GUID  *VendorGuid
  )
{
  VOID        *Data;
  UINTN       DataSize;
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  DataSize = 0;
  Status   = GetVariable2 (DefaultName, &gEfiGlobalVariableGuid, &Data, &DataSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Error: GetVariable (\"%s\"): %r\n", DefaultName, Status));
    return Status;
  }

  Status = EnrollFromInput (VariableName, VendorGuid, DataSize, Data);

  if (Data != NULL) {
    FreePool (Data);
  }

  return Status;
}

/** Initializes PKDefault variable with data from FFS section.

  @retval  EFI_SUCCESS           Variable was initialized successfully.
  @retval  EFI_UNSUPPORTED       Variable already exists.
**/
EFI_STATUS
SecureBootInitPKDefault (
  IN VOID
  )
{
  EFI_SIGNATURE_LIST  *EfiSig;
  UINTN               SigListsSize;
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;

  //
  // Check if variable exists, if so do not change it
  //
  Status = GetVariable2 (EFI_PK_DEFAULT_VARIABLE_NAME, &gEfiGlobalVariableGuid, (VOID **)&Data, &DataSize);
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Variable %s exists. Old value is preserved\n", EFI_PK_DEFAULT_VARIABLE_NAME));
    FreePool (Data);
    return EFI_UNSUPPORTED;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  //
  // Variable does not exist, can be initialized
  //
  DEBUG ((DEBUG_INFO, "Variable %s does not exist.\n", EFI_PK_DEFAULT_VARIABLE_NAME));

  Status = SecureBootFetchData (&gDefaultPKFileGuid, &SigListsSize, &EfiSig);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Content for %s not found\n", EFI_PK_DEFAULT_VARIABLE_NAME));
    return Status;
  }

  Status = gRT->SetVariable (
                  EFI_PK_DEFAULT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  SigListsSize,
                  (VOID *)EfiSig
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Failed to set %s\n", EFI_PK_DEFAULT_VARIABLE_NAME));
  }

  FreePool (EfiSig);

  return Status;
}

/** Initializes KEKDefault variable with data from FFS section.

  @retval  EFI_SUCCESS           Variable was initialized successfully.
  @retval  EFI_UNSUPPORTED       Variable already exists.
**/
EFI_STATUS
SecureBootInitKEKDefault (
  IN VOID
  )
{
  EFI_SIGNATURE_LIST  *EfiSig;
  UINTN               SigListsSize;
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;

  //
  // Check if variable exists, if so do not change it
  //
  Status = GetVariable2 (EFI_KEK_DEFAULT_VARIABLE_NAME, &gEfiGlobalVariableGuid, (VOID **)&Data, &DataSize);
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Variable %s exists. Old value is preserved\n", EFI_KEK_DEFAULT_VARIABLE_NAME));
    FreePool (Data);
    return EFI_UNSUPPORTED;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  //
  // Variable does not exist, can be initialized
  //
  DEBUG ((DEBUG_INFO, "Variable %s does not exist.\n", EFI_KEK_DEFAULT_VARIABLE_NAME));

  Status = SecureBootFetchData (&gDefaultKEKFileGuid, &SigListsSize, &EfiSig);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Content for %s not found\n", EFI_KEK_DEFAULT_VARIABLE_NAME));
    return Status;
  }

  Status = gRT->SetVariable (
                  EFI_KEK_DEFAULT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  SigListsSize,
                  (VOID *)EfiSig
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Failed to set %s\n", EFI_KEK_DEFAULT_VARIABLE_NAME));
  }

  FreePool (EfiSig);

  return Status;
}

/** Initializes dbDefault variable with data from FFS section.

  @retval  EFI_SUCCESS           Variable was initialized successfully.
  @retval  EFI_UNSUPPORTED       Variable already exists.
**/
EFI_STATUS
SecureBootInitDbDefault (
  IN VOID
  )
{
  EFI_SIGNATURE_LIST  *EfiSig;
  UINTN               SigListsSize;
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;

  Status = GetVariable2 (EFI_DB_DEFAULT_VARIABLE_NAME, &gEfiGlobalVariableGuid, (VOID **)&Data, &DataSize);
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Variable %s exists. Old value is preserved\n", EFI_DB_DEFAULT_VARIABLE_NAME));
    FreePool (Data);
    return EFI_UNSUPPORTED;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  DEBUG ((DEBUG_INFO, "Variable %s does not exist.\n", EFI_DB_DEFAULT_VARIABLE_NAME));

  Status = SecureBootFetchData (&gDefaultdbFileGuid, &SigListsSize, &EfiSig);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gRT->SetVariable (
                  EFI_DB_DEFAULT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  SigListsSize,
                  (VOID *)EfiSig
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Failed to set %s\n", EFI_DB_DEFAULT_VARIABLE_NAME));
  }

  FreePool (EfiSig);

  return Status;
}

/** Initializes dbxDefault variable with data from FFS section.

  @retval  EFI_SUCCESS           Variable was initialized successfully.
  @retval  EFI_UNSUPPORTED       Variable already exists.
**/
EFI_STATUS
SecureBootInitDbxDefault (
  IN VOID
  )
{
  EFI_SIGNATURE_LIST  *EfiSig;
  UINTN               SigListsSize;
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;

  //
  // Check if variable exists, if so do not change it
  //
  Status = GetVariable2 (EFI_DBX_DEFAULT_VARIABLE_NAME, &gEfiGlobalVariableGuid, (VOID **)&Data, &DataSize);
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Variable %s exists. Old value is preserved\n", EFI_DBX_DEFAULT_VARIABLE_NAME));
    FreePool (Data);
    return EFI_UNSUPPORTED;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  //
  // Variable does not exist, can be initialized
  //
  DEBUG ((DEBUG_INFO, "Variable %s does not exist.\n", EFI_DBX_DEFAULT_VARIABLE_NAME));

  Status = SecureBootFetchData (&gDefaultdbxFileGuid, &SigListsSize, &EfiSig);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Content for %s not found\n", EFI_DBX_DEFAULT_VARIABLE_NAME));
    return Status;
  }

  Status = gRT->SetVariable (
                  EFI_DBX_DEFAULT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  SigListsSize,
                  (VOID *)EfiSig
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Failed to set %s\n", EFI_DBX_DEFAULT_VARIABLE_NAME));
  }

  FreePool (EfiSig);

  return Status;
}

/** Initializes dbtDefault variable with data from FFS section.

  @retval  EFI_SUCCESS           Variable was initialized successfully.
  @retval  EFI_UNSUPPORTED       Variable already exists.
**/
EFI_STATUS
SecureBootInitDbtDefault (
  IN VOID
  )
{
  EFI_SIGNATURE_LIST  *EfiSig;
  UINTN               SigListsSize;
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;

  //
  // Check if variable exists, if so do not change it
  //
  Status = GetVariable2 (EFI_DBT_DEFAULT_VARIABLE_NAME, &gEfiGlobalVariableGuid, (VOID **)&Data, &DataSize);
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Variable %s exists. Old value is preserved\n", EFI_DBT_DEFAULT_VARIABLE_NAME));
    FreePool (Data);
    return EFI_UNSUPPORTED;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  //
  // Variable does not exist, can be initialized
  //
  DEBUG ((DEBUG_INFO, "Variable %s does not exist.\n", EFI_DBT_DEFAULT_VARIABLE_NAME));

  Status = SecureBootFetchData (&gDefaultdbtFileGuid, &SigListsSize, &EfiSig);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gRT->SetVariable (
                  EFI_DBT_DEFAULT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  SigListsSize,
                  (VOID *)EfiSig
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Failed to set %s\n", EFI_DBT_DEFAULT_VARIABLE_NAME));
  }

  FreePool (EfiSig);

  return EFI_SUCCESS;
}

/**
  Sets the content of the 'db' variable based on 'dbDefault' variable content.

  @retval EFI_OUT_OF_RESOURCES      If memory allocation for EFI_VARIABLE_AUTHENTICATION_2 fails
                                    while VendorGuid is NULL.
  @retval other                     Errors from GetVariable2 (), GetTime () and SetVariable ()
**/
EFI_STATUS
EFIAPI
EnrollDbFromDefault (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = EnrollFromDefault (
             EFI_IMAGE_SECURITY_DATABASE,
             EFI_DB_DEFAULT_VARIABLE_NAME,
             &gEfiImageSecurityDatabaseGuid
             );

  return Status;
}

/**
  Sets the content of the 'dbx' variable based on 'dbxDefault' variable content.

  @retval EFI_OUT_OF_RESOURCES      If memory allocation for EFI_VARIABLE_AUTHENTICATION_2 fails
                                    while VendorGuid is NULL.
  @retval other                     Errors from GetVariable2 (), GetTime () and SetVariable ()
**/
EFI_STATUS
EFIAPI
EnrollDbxFromDefault (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = EnrollFromDefault (
             EFI_IMAGE_SECURITY_DATABASE1,
             EFI_DBX_DEFAULT_VARIABLE_NAME,
             &gEfiImageSecurityDatabaseGuid
             );

  return Status;
}

/**
  Sets the content of the 'dbt' variable based on 'dbtDefault' variable content.

  @retval EFI_OUT_OF_RESOURCES      If memory allocation for EFI_VARIABLE_AUTHENTICATION_2 fails
                                    while VendorGuid is NULL.
  @retval other                     Errors from GetVariable2 (), GetTime () and SetVariable ()
**/
EFI_STATUS
EFIAPI
EnrollDbtFromDefault (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = EnrollFromDefault (
             EFI_IMAGE_SECURITY_DATABASE2,
             EFI_DBT_DEFAULT_VARIABLE_NAME,
             &gEfiImageSecurityDatabaseGuid
             );

  return Status;
}

/**
  Sets the content of the 'KEK' variable based on 'KEKDefault' variable content.

  @retval EFI_OUT_OF_RESOURCES      If memory allocation for EFI_VARIABLE_AUTHENTICATION_2 fails
                                    while VendorGuid is NULL.
  @retval other                     Errors from GetVariable2 (), GetTime () and SetVariable ()
**/
EFI_STATUS
EFIAPI
EnrollKEKFromDefault (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = EnrollFromDefault (
             EFI_KEY_EXCHANGE_KEY_NAME,
             EFI_KEK_DEFAULT_VARIABLE_NAME,
             &gEfiGlobalVariableGuid
             );

  return Status;
}

/**
  Sets the content of the 'KEK' variable based on 'KEKDefault' variable content.

  @retval EFI_OUT_OF_RESOURCES      If memory allocation for EFI_VARIABLE_AUTHENTICATION_2 fails
                                    while VendorGuid is NULL.
  @retval other                     Errors from GetVariable2 (), GetTime () and SetVariable ()
**/
EFI_STATUS
EFIAPI
EnrollPKFromDefault (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = EnrollFromDefault (
             EFI_PLATFORM_KEY_NAME,
             EFI_PK_DEFAULT_VARIABLE_NAME,
             &gEfiGlobalVariableGuid
             );

  return Status;
}
