#pragma once
#include <Windows.h>
#include <vector>
#include <wincrypt.h>
#include <stdio.h>

bool GetSha256(void * data, size_t dataSize, char * sha256, size_t hashSize);
bool InitHash(HCRYPTPROV & hProv, HCRYPTHASH & hHash);
bool UpdateHash(HCRYPTHASH hHash, void * data, size_t dataSize);
bool FinishHash(HCRYPTPROV hProv, HCRYPTHASH hHash, char * sha256, size_t hashSize);
void ClrGuardServer();

// Service stuff
void ServiceInstall();
void ServiceEntry();
#define SVCNAME TEXT("ClrGuard")
#define SVCDESC TEXT("The ClrGuard Service.")

// Log stuff
void LogEvent(DWORD pid, wchar_t *processPath, char * moduleHash, char * fuzzyHash, DWORD action);
#define LOG_FILE L"ClrGuard.log"

typedef struct _CLI_HEADER {
    DWORD size;
    WORD majorVer;
    WORD minorVer;
    DWORD metaRva;
    DWORD metaSize;
    DWORD flags;
    DWORD entryPoint;
} CLI_HEADER, *PCLI_HEADER;

typedef struct _CLI_META {
    DWORD signature;
    WORD majorVer;
    WORD minorVer;
    DWORD reserved;
    DWORD dwVerStr;
} CLI_META, *PCLI_META;

typedef struct _STREAM_HEADER {
    WORD flags;
    WORD streamCount;
}STREAM_HEADER, *PSTREAM_HEADER;

typedef struct _STREAM_INFO {
    DWORD offset;
    DWORD size;
    char name[4];
}STREAM_INFO, *PSTREAM_INFO;

typedef struct _MY_STREAM_INFO {
    DWORD offset;
    DWORD size;
    void * pStreamData;
    char name[64];
}MY_STREAM_INFO, *PMY_STREAM_INFO;

typedef struct _TABLE_HEADER {
    DWORD reserved;
    BYTE majorVer;
    BYTE minorVer;
    BYTE heapOffsetSz;
    BYTE reserved2;
    DWORD64 fValid;
    DWORD64 fSorted;
}TABLE_HEADER, *PTABLE_HEADER;

#define F_MODULE       1
#define F_TYPE_REF     2
#define F_TYPE_DEF     4
#define F_FIELD        0x10
#define F_METHOD_DEF   0x40
#define F_PARAM        0x100
#define F_INTERFACE    0x200
#define F_MEMBER_REF   0x400
#define F_CONSTANT     0x800
#define F_CUSTOM_ATTR  0x1000
#define F_MODULE_REF   0x4000000
#define F_ASSEMBLY_REF 0x800000000

class PEMeta
{
public:
    std::vector<IMAGE_SECTION_HEADER> sections;
    CLI_HEADER cliHeader;
    std::vector<MY_STREAM_INFO> streams;
    DWORD strIndexSize;
    DWORD guidIndexSize;
    DWORD blobIndexSize;
    DWORD resolutionIndexSize;
    char typeRefHash[70];

    PEMeta();
    ~PEMeta();
    bool PEMeta::ParseData(void * pData, size_t dataSize);
    bool PEMeta::RvaToOffset(DWORD rva, DWORD & offset);
    bool PEMeta::ParseTableStream(void * pData, size_t dataSize);
    bool PEMeta::FindStream(char * name, void * &stream);
    bool PEMeta::GetString(void *pData, size_t dataSize, BYTE * &pByte, char * &pStr);
    bool PEMeta::DumpFileInfo(const char * filePath);
};

