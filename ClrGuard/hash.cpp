#include "ClrGuard.h"

//
// Calculates the sha256 from a block of data. Copy
// pasta from https://msdn.microsoft.com/en-us/library/windows/desktop/aa382379(v=vs.85).aspx
//
bool GetSha256(void * data, size_t dataSize, char * sha256, size_t hashSize)
{
    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    PBYTE       pbHash = NULL;
    DWORD       dwDataLen = 0;
    bool retCode = false;
    if (hashSize < 65)
    {
        goto cleanup;
    }

    if (!CryptAcquireContext(
        &hProv,                   // handle of the CSP
        NULL,                     // key container name
        NULL,                     // CSP name
        PROV_RSA_AES,             // provider type
        CRYPT_VERIFYCONTEXT))     // no key access is requested
    {
        printf(" Error in AcquireContext 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP
        CALG_SHA_256,             // hash algorithm to use
        0,                        // hash key
        0,                        // reserved
        &hHash))                  // address of hash object handle
    {
        printf("Error in CryptCreateHash 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    if (!CryptHashData(
        hHash,                    // handle of the hash object
        (const BYTE*)data,        // password to hash
        (DWORD)dataSize,          // number of bytes of data to add
        0))                       // flags
    {
        printf("Error in CryptHashData 0x%08x \n",
            GetLastError());
        goto cleanup;
    }
   
    if (!CryptGetHashParam(
        hHash,                    // handle of the hash object
        HP_HASHVAL,               // query on the hash value
        NULL,                     // filled on second call
        &dwDataLen,               // length, in bytes, of the hash
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    pbHash = (BYTE*)malloc(dwDataLen);
    if (NULL == pbHash)
    {
        printf("unable to allocate memory\n");
        goto cleanup;
    }

    if (!CryptGetHashParam(
        hHash,                     // handle of the hash object
        HP_HASHVAL,                // query on the hash value
        pbHash,                    // pointer to the hash value
        &dwDataLen,                // length, in bytes, of the hash
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
        goto cleanup;
    }

    retCode = true;
    ZeroMemory(sha256, hashSize);
    for (DWORD i = 0; i < dwDataLen; i++)
    {
        sprintf_s(&sha256[i * 2], 3, "%2.2X", pbHash[i]);
    }

    // Free resources.
cleanup:

    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    if (pbHash)
        free(pbHash);

    return retCode;
}

bool InitHash(HCRYPTPROV & hProv, HCRYPTHASH & hHash)
{
    bool retCode = false;

    if (!CryptAcquireContext(
        &hProv,                    // handle of the CSP
        NULL,                      // key container name
        NULL,                      // CSP name
        PROV_RSA_AES,              // provider type
        CRYPT_VERIFYCONTEXT))      // no key access is requested
    {
        printf(" Error in AcquireContext 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    if (!CryptCreateHash(
        hProv,                    // handle of the CSP
        CALG_SHA_256,             // hash algorithm to use
        0,                        // hash key
        0,                        // reserved
        &hHash))                  // address of hash object handle
    {
        printf("Error in CryptCreateHash 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    retCode = true;

cleanup:

    return retCode;
}

bool UpdateHash(HCRYPTHASH hHash, void * data, size_t dataSize)
{
    if (!CryptHashData(
        hHash,                    // handle of the hash object
        (const BYTE*)data,        // password to hash
        (DWORD)dataSize,          // number of bytes of data to add
        0))                       // flags
    {
        printf("Error in CryptHashData 0x%08x \n",
            GetLastError());
        return false;
    }

    return true;
}

bool FinishHash(HCRYPTPROV hProv, HCRYPTHASH hHash, char * sha256, size_t hashSize)
{
    bool retCode = false;
    DWORD dwDataLen = 0;
    PBYTE pbHash = NULL;

    if (!CryptGetHashParam(
        hHash,                    // handle of the hash object
        HP_HASHVAL,               // query on the hash value
        NULL,                     // filled on second call
        &dwDataLen,               // length, in bytes, of the hash
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n",
            GetLastError());
        goto cleanup;
    }

    pbHash = (BYTE*)malloc(dwDataLen);
    if (NULL == pbHash)
    {
        printf("unable to allocate memory\n");
        goto cleanup;
    }

    if (!CryptGetHashParam(
        hHash,                     // handle of the hash object
        HP_HASHVAL,                // query on the hash value
        pbHash,                    // pointer to the hash value
        &dwDataLen,                // length, in bytes, of the hash
        0))
    {
        printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
        goto cleanup;
    }

    ZeroMemory(sha256, hashSize);
    for (DWORD i = 0; i < dwDataLen; i++)
    {
        sprintf_s(&sha256[i * 2], 3, "%2.2X", pbHash[i]);
    }

    retCode = true;

cleanup:
    if (pbHash)
        free(pbHash);

    return retCode;
}