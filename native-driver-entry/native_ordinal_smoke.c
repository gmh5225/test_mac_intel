#include <windows.h>
#include <compressapi.h>
#include <stdio.h>

typedef BOOL (__cdecl *CloseCompressorFn)(COMPRESSOR_HANDLE);
typedef BOOL (__cdecl *CloseDecompressorFn)(DECOMPRESSOR_HANDLE);

BOOL __cdecl UseCloseCompressor(COMPRESSOR_HANDLE);
BOOL __cdecl highc_UseCloseCompressor(COMPRESSOR_HANDLE);
BOOL __cdecl llvmc_UseCloseCompressor(COMPRESSOR_HANDLE);
BOOL __cdecl UseCloseDecompressor(DECOMPRESSOR_HANDLE);
BOOL __cdecl highc_UseCloseDecompressor(DECOMPRESSOR_HANDLE);
BOOL __cdecl llvmc_UseCloseDecompressor(DECOMPRESSOR_HANDLE);

int main(void) {
    const char *names[] = {"original", "highc", "llvmc"};
    CloseCompressorFn compressors[] = {UseCloseCompressor, highc_UseCloseCompressor, llvmc_UseCloseCompressor};
    CloseDecompressorFn decompressors[] = {UseCloseDecompressor, highc_UseCloseDecompressor, llvmc_UseCloseDecompressor};
    puts("[");
    for (unsigned i = 0; i < 3; ++i) {
        COMPRESSOR_HANDLE compressor = NULL;
        DECOMPRESSOR_HANDLE decompressor = NULL;
        if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS, NULL, &compressor))
            return 2;
        if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS, NULL, &decompressor)) {
            CloseCompressor(compressor);
            return 3;
        }
        BOOL closed = compressors[i](compressor);
        BOOL decoded = decompressors[i](decompressor);
        printf("%s{\"route\":\"%s\",\"compressor_closed\":%s,\"decompressor_closed\":%s}\n",
               i ? "," : "", names[i], closed ? "true" : "false", decoded ? "true" : "false");
        if (!closed || !decoded)
            return 4;
    }
    puts("]");
    return 0;
}
