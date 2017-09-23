#include "ClrGuard.h"
#include <stdio.h>

//
// This is an amazing resource on the dotnet file format:
// http://www.ntcore.com/files/dotnetformat.htm
//

static inline bool IsValidPtr(void *pData, size_t dataSize, void *ptr, size_t ptrSize)
{
    if ((size_t)ptr < (size_t)pData)
        return false;

    if ((size_t)ptr + ptrSize > ((size_t)pData + dataSize))
        return false;

    if ((size_t)ptr + ptrSize < ((size_t)pData))
        return false;

    return true;
}

static inline bool IsValidStr(void *pData, size_t dataSize, char *pStr)
{
    if (!IsValidPtr(pData, dataSize, pStr, 1))
        return false;

    while (*pStr)
    {
        if (!IsValidPtr(pData, dataSize, pStr, 1))
            return false;

        pStr++;
    }

    return true;
}

#define ValidatePtr(pData, dataSize, ptr, ptrSize, msg) \
    if(!IsValidPtr(pData, dataSize, ptr, ptrSize)) \
    { \
        printf("Invalid Ptr: %s\n", msg); \
        return false; \
    }

#define ValidateStr(pData, dataSize, pStr, msg) \
    if(!IsValidStr(pData, dataSize, pStr)) \
    { \
        printf("Invalid Str: %s\n", msg); \
        return false; \
    }

#define ValidatePtrCleanup(pData, dataSize, ptr, ptrSize, msg) \
    if(!IsValidPtr(pData, dataSize, ptr, ptrSize)) \
    { \
        printf("Invalid Ptr: %s\n", msg); \
        goto cleanup; \
    }

PEMeta::PEMeta()
{
    //printf("Constructor\n");
    strIndexSize = 0;
    guidIndexSize = 0;
    blobIndexSize = 0;
    resolutionIndexSize = 0;

    ZeroMemory(&cliHeader, sizeof(cliHeader));
    ZeroMemory(typeRefHash, sizeof(typeRefHash));
}

PEMeta::~PEMeta()
{
    //printf("Destructor\n");
}

bool PEMeta::RvaToOffset(DWORD rva, DWORD & offset)
{
    if (0 == this->sections.size())
    {
        printf("No sections\n");
        return false;
    }

    for (auto it = sections.begin(); it != sections.end(); ++it)
    {
        if (rva >= it->VirtualAddress && rva < (it->VirtualAddress + it->SizeOfRawData))
        {
            offset = (DWORD)it->PointerToRawData + (DWORD)(rva - it->VirtualAddress);
            return true;
        }
    }

    // not found
    return false;
}

//
// Parses basic Clr/.NET PE information from the supplied file. Only a handful
// of the 30+ tables are currently parsed.
//
bool PEMeta::ParseData(void * pData, size_t dataSize)
{
    IMAGE_DOS_HEADER *pDosHeader = 0;
    IMAGE_NT_HEADERS *pNtHeaders = 0;
    IMAGE_SECTION_HEADER *pHeaderStart = 0;
    IMAGE_DATA_DIRECTORY *pDirCOM;
    CLI_HEADER * pCLIHeader = 0;
    CLI_META * pCLIMeta = 0;
    DWORD dwCliOffset = 0;
    DWORD dwMetaOffset = 0;
    void * pStream = 0;

    if (pData == 0)
    {
        printf("Invalid param\n");
        return false;
    }

    pDosHeader = (IMAGE_DOS_HEADER *)pData;
    ValidatePtr(pData, dataSize, pDosHeader, sizeof(*pDosHeader), "MZ header");

    if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic)
    {
        printf("No MZ Header\n");
        return false;
    }

    pNtHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)pData + pDosHeader->e_lfanew);
    ValidatePtr(pData, dataSize, pNtHeaders, sizeof(*pNtHeaders), "PE Header");

    // Read NT Header Info
    if (IMAGE_FILE_MACHINE_I386 == pNtHeaders->FileHeader.Machine)
    {
        IMAGE_NT_HEADERS32 *pNtHeader32 = (IMAGE_NT_HEADERS32*)pNtHeaders;
        ValidatePtr(pData, dataSize, pNtHeader32, sizeof(*pNtHeader32), "NT Header");

        pDirCOM = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        pHeaderStart = IMAGE_FIRST_SECTION(pNtHeader32);
    }
    else if (IMAGE_FILE_MACHINE_AMD64 == pNtHeaders->FileHeader.Machine)
    {
        IMAGE_NT_HEADERS64 *pNtHeader64 = (IMAGE_NT_HEADERS64*)pNtHeaders;
        ValidatePtr(pData, dataSize, pNtHeader64, sizeof(*pNtHeader64), "NT Header");

        pDirCOM = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        pHeaderStart = IMAGE_FIRST_SECTION(pNtHeader64);
    }
    else
    {
        printf("Unknown machine type: %hx\n", pNtHeaders->FileHeader.Machine);
        return false;
    }

    // Enumerate Sections
    ValidatePtr(pData, dataSize, pHeaderStart, sizeof(IMAGE_SECTION_HEADER)*pNtHeaders->FileHeader.NumberOfSections, "NT Header");

    for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        this->sections.push_back(*pHeaderStart);
        pHeaderStart++;
    }

    // Get Location of COM Data
    if (pDirCOM->VirtualAddress == 0 || pDirCOM->Size == 0)
    {
        printf("No COM Header\n");
        return false;
    }

    if (!RvaToOffset(pDirCOM->VirtualAddress, dwCliOffset))
    {
        printf("Invalid RVA\n");
        return false;
    }

    pCLIHeader = (CLI_HEADER*)((size_t)pData + dwCliOffset);
    ValidatePtr(pData, dataSize, pCLIHeader, sizeof(*pCLIHeader), "CLI Header");

    // Save cli header
    this->cliHeader = *pCLIHeader;

    if (!RvaToOffset(pCLIHeader->metaRva, dwMetaOffset))
    {
        printf("Invalid RVA\n");
        return false;
    }

    pCLIMeta = (CLI_META*)((size_t)pData + dwMetaOffset);
    ValidatePtr(pData, dataSize, pCLIMeta, sizeof(*pCLIMeta), "CLI Meta");

    char * pVerStr = (char*)((size_t)pCLIMeta + sizeof(CLI_META));

    STREAM_HEADER * pStreamHeader = (STREAM_HEADER *)((size_t)pCLIMeta + sizeof(CLI_META) + pCLIMeta->dwVerStr);
    ValidatePtr(pData, dataSize, pStreamHeader, sizeof(*pStreamHeader), "Stream Header");

    STREAM_INFO * pStreamInfo = (STREAM_INFO *)((size_t)pStreamHeader + sizeof(*pStreamHeader));
    for (int i = 0 ; i < pStreamHeader->streamCount; i++)
    {
        MY_STREAM_INFO myStreamInfo = { 0 };
        ValidatePtr(pData, dataSize, pStreamInfo, sizeof(*pStreamInfo), "Stream Info");
        ValidateStr(pData, dataSize, pStreamInfo->name, "Stream Info Name");

        // Calculate size of string with padding,
        // aligned to 4 bytes.
        size_t szStr = 0, rmd = 0;
        char * pStr = pStreamInfo->name;
        szStr = strlen(pStr) + 1;
        rmd = szStr % 4;
        if (rmd)
            szStr += 4 - rmd;

        if (szStr > 64)
        {
            printf("Stream name too long\n");
            return false;
        }

        myStreamInfo.offset = pStreamInfo->offset;
        myStreamInfo.size = pStreamInfo->size;
        myStreamInfo.pStreamData = (void*)((size_t)pData + dwMetaOffset + myStreamInfo.offset);
        ValidatePtr(pData, dataSize, myStreamInfo.pStreamData, myStreamInfo.size, "Stream Data");
        memcpy(myStreamInfo.name, pStreamInfo->name, szStr);

        this->streams.push_back(myStreamInfo);

        pStreamInfo = (STREAM_INFO*)((size_t)pStreamInfo->name + szStr);

    }

    if (!ParseTableStream(pData, dataSize))
    {
        return false;
    }

    //printf("Parsing successful\n");

    return true;
}

bool PEMeta::FindStream(char * name, void * &pStreamData)
{
    for (auto it = this->streams.begin(); it != this->streams.end(); ++it)
    {
        if (_stricmp(name, it->name) == 0)
        {
            pStreamData = it->pStreamData;
            return true;
        }
    }

    return false;
}

bool PEMeta::ParseTableStream(void * pData, size_t dataSize)
{
    void * pTableStream = 0;
    TABLE_HEADER * pTableHeader = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool funcStatus = false;

    if (!FindStream("#~", pTableStream))
    {
        printf("Tables not present\n");
        goto cleanup;
    }

    if (!InitHash(hProv, hHash))
    {
        printf("Error hash init\n");
        goto cleanup;
    }

    pTableHeader = (TABLE_HEADER*)pTableStream;
    ValidatePtrCleanup(pData, dataSize, pTableHeader, sizeof(*pTableHeader), "Table Header");

    if (pTableHeader->heapOffsetSz & 1)
        this->strIndexSize = 4;
    else
        this->strIndexSize = 2;

    if (pTableHeader->heapOffsetSz & 2)
        this->guidIndexSize = 4;
    else
        this->guidIndexSize = 2;

    if (pTableHeader->heapOffsetSz & 4)
        this->blobIndexSize = 4;
    else
        this->blobIndexSize = 2;

    DWORD moduleRows = 0;
    DWORD typeRefRows = 0;
    DWORD typeDefRows = 0;
    DWORD fieldRows = 0;
    DWORD methodDefRows = 0;
    DWORD paramRows = 0;
    DWORD interfaceImplRows = 0;
    DWORD memberRefRows = 0;
    DWORD constantMemberRows = 0;
    DWORD customAttributeRows = 0;
    DWORD moduleRefRows = 0;
    DWORD assemblyRefRows = 0;

    DWORD * pRows = (DWORD*)((size_t)pTableStream + sizeof(*pTableHeader));
    for (int i = 0; i < 64; i++)
    {
        DWORD64 flag = (DWORD64)1 << i;
        if (!(flag & pTableHeader->fValid))
        {
            // flag not set
            continue;
        }
        ValidatePtrCleanup(pData, dataSize, pRows, sizeof(*pRows), "Row");

        if (flag & F_MODULE)
            moduleRows = *pRows;
        else if (flag & F_TYPE_REF)
            typeRefRows = *pRows;
        else if (flag & F_TYPE_DEF)
            typeDefRows = *pRows;
        else if (flag & F_FIELD)
            fieldRows = *pRows;
        else if (flag & F_METHOD_DEF)
            methodDefRows = *pRows;
        else if (flag & F_PARAM)
            paramRows = *pRows;
        else if (flag & F_INTERFACE)
            interfaceImplRows = *pRows;
        else if (flag & F_MEMBER_REF)
            memberRefRows = *pRows;
        else if (flag & F_CONSTANT)
            constantMemberRows = *pRows;
        else if (flag & F_CUSTOM_ATTR)
            customAttributeRows = *pRows;
        else if (flag & F_MODULE_REF)
            moduleRefRows = *pRows;
        else if (flag & F_ASSEMBLY_REF)
            assemblyRefRows = *pRows;
        // there are more tables

        pRows++;
    }

    // Dynamically sized indexes
    if ((moduleRows > 0x3FFF) || (moduleRefRows > 0x3FFF) ||
        (assemblyRefRows > 0x3FFF) || (typeRefRows > 0x3FFF))
    {
        printf("DEBUG... resolution index 4\n");
        this->resolutionIndexSize = 4;
    }
    else
    {
        this->resolutionIndexSize = 2;
    }

    // Modules
    BYTE * pByte = (BYTE *)pRows;
    for (size_t i = 0; i < moduleRows;i++)
    {
        char * pModuleName = 0;
        ValidatePtrCleanup(pData, dataSize, pByte, 2, "Module Generation");
        pByte += 2;
        if (!GetString(pData, dataSize, pByte, pModuleName))
            goto cleanup;

        printf("  Module: %s\n", pModuleName);

        pByte += this->guidIndexSize * 3;
    }

    for (size_t i = 0; i < typeRefRows; i++)
    {
        char * pTypeName = 0;
        char * pNamespace = 0;

        ValidatePtrCleanup(pData, dataSize, pByte, this->resolutionIndexSize, "Resolution Scope");
        pByte += this->resolutionIndexSize;

        if (!GetString(pData, dataSize, pByte, pTypeName))
            goto cleanup;

        if (!GetString(pData, dataSize, pByte, pNamespace))
            goto cleanup;

        if (!UpdateHash(hHash, pNamespace, strlen(pNamespace)))
        {
            printf("Error hashing\n");
            goto cleanup;
        }

        if (!UpdateHash(hHash, pTypeName, strlen(pTypeName)))
        {
            printf("Error hashing\n");
            goto cleanup;
        }

        printf("  TypeRef: %s::%s\n", pNamespace, pTypeName);
    }

    if (!FinishHash(hProv, hHash, this->typeRefHash, _countof(this->typeRefHash)))
    {
        printf("Error finish hashing\n");
        goto cleanup;
    }

    funcStatus = true;

cleanup:
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return funcStatus;
}

bool PEMeta::GetString(void *pData, size_t dataSize, BYTE * &pByte, char * &pStr)
{
    void * pStringStream = 0;
    if (!FindStream("#Strings", pStringStream))
    {
        printf("Strings not present\n");
        return false;
    }

    DWORD offset = 0;

    if (this->strIndexSize == 2)
    {
        ValidatePtr(pData, dataSize, pByte, 2, "String Index");
        memcpy(&offset, pByte, 2);
        pByte += 2;
        pStr = (char*)((size_t)pStringStream + offset);
        ValidateStr(pData, dataSize, pStr, "String Ptr");
    }
    else
    {
        ValidatePtr(pData, dataSize, pByte, 4, "String Index");
        memcpy(&offset, pByte, 4);
        pByte += 4;
        pStr = (char*)((size_t)pStringStream + offset);
        ValidateStr(pData, dataSize, pStr, "String Ptr");
    }

    return true;
}

bool PEMeta::DumpFileInfo(const char * filePath)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    void * pFileData = 0;
    bool retVal = false;
    DWORD dwRead = 0;

    hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("Error opening file\n");
        goto Cleanup;
    }

    DWORD size = 0, high = 0;
    size = GetFileSize(hFile, &high);

    if (size == 0)
    {
        printf("GetFileSize 0\n");
        goto Cleanup;
    }

    pFileData = malloc(size);
    ReadFile(hFile, pFileData, size, &dwRead, 0);

    if (size != dwRead)
    {
        printf("Error reading file\n");
        goto Cleanup;
    }


    if (!this->ParseData(pFileData, size))
    {
        printf("Error parsing data\n");
        goto Cleanup;
    }
    else
    {
        printf("  TypeRef hash: %s\n", this->typeRefHash);
    }

    retVal = true;

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return retVal;
}