/*
 * Copyright (c) 2020 adversarial
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "pe_structs.h"

#ifndef NDEBUG
#define assert_msg(condition, msg) assert(condition)
#else
#define assert_msg(condition, msg)
#endif

static const char* Header = {
    "==========================================\n"
    "          eofstrip by adversarial         \n"
    "==========================================\n"
};

static const char* Usage = { "eofstrip - get appended data from PE files\n"
							"Usage: eofstrip <pe> [output]\n"
                           	"Default output is <pe>.eof\n"
};


int main(int argc, char* argv[]) {

	printf(Header);

    if (argc < 2) {
        printf(Usage);
		printf("Press any key to continue...");
        getchar();
        return 1;
    }

    FILE* fIn = fopen(argv[1], "rb");
    if (!fIn) {
		perror("Error opening input file");
		exit(1);
	}

    // read in PE structs
    dos_hdr* pDosHdr = malloc(sizeof(dos_hdr));
    assert_msg(pDosHdr, NULL);
    fread(pDosHdr, sizeof(dos_hdr), 1, fIn);
    
    fseek(fIn, pDosHdr->e_lfanew, SEEK_SET);

    nt_hdr* pNtHdr = malloc(sizeof(nt_hdr));
    assert_msg(pNtHdr, NULL);
    fread(pNtHdr, sizeof(nt_hdr), 1, fIn);

    fseek(fIn, pDosHdr->e_lfanew + sizeof(file_hdr) + sizeof(uint32_t) + pNtHdr->FileHeader.SizeOfOptionalHeader, SEEK_SET);

    sec_hdr** ppSecHdr = malloc(sizeof(sec_hdr*) * pNtHdr->FileHeader.NumberOfSections);
    assert_msg(ppSecHdr, NULL);

    for (register size_t i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
        ppSecHdr[i] = malloc(sizeof(sec_hdr));
        fread(ppSecHdr[i], sizeof(sec_hdr), 1, fIn);
        assert_msg(ppSecHdr[i], NULL);
    }

    // calculate max file offset
    //size_t cbMaxOffset = pNtHdr->OptionalHeader.SizeOfHeaders;

    // instead we calculate from info without relying on PE specific headers
    size_t cbMaxOffset = pDosHdr->e_lfanew + sizeof(file_hdr) + sizeof(uint32_t) + pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(sec_hdr) * pNtHdr->FileHeader.NumberOfSections;
    // align up

    // if sec_offset + sec_size > maxoffset
    //    maxoffset = that
    for (register size_t i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
        cbMaxOffset = cbMaxOffset > ppSecHdr[i]->PointerToRawData + ppSecHdr[i]->SizeOfRawData ? cbMaxOffset : ppSecHdr[i]->PointerToRawData + ppSecHdr[i]->SizeOfRawData;
    }

    // get file size
    fseek(fIn, 0, SEEK_END);
    size_t cbFileSize = ftell(fIn);

    printf("\nActual file size: %zu\nExpected file size: %zu", cbFileSize, cbMaxOffset);

    if (cbFileSize <= cbMaxOffset) {
        printf("\nNo overlay data was found.");
        return 0; // no eof data
    }

    // allocate and read data beyond typical PE
    size_t cbEof = cbFileSize - cbMaxOffset;
    void* pEof = calloc(1, cbEof);
    assert_msg(pEof, NULL);

    fseek(fIn, cbMaxOffset, SEEK_SET);
    assert_msg(fread(pEof, 1, cbEof, fIn) == cbEof, NULL);

    fclose(fIn);

	printf("\n%zu bytes of overlay data detected.", cbEof);

	// third arg is output
	char* szoutchoice = NULL;
	FILE* fEof = NULL;
	if (argc > 2) {
		szoutchoice = argv[2];
		fEof = fopen(szoutchoice, "wb+");
		if (!fEof)
			perror("\nCould not create specified output file, using default output file");
	}

    // use default, new file is [in.exe].eof
	if (!fEof) {
    	szoutchoice = calloc(1, strlen(argv[1]) + 5);
    	strcpy(szoutchoice, argv[1]);
    	strcat(szoutchoice, ".eof");
    	fEof = fopen(szoutchoice, "wb+");
		if (!fEof) {
			perror("\nCould not open default output file");
			exit(1);
		}
	}
	
    fwrite(pEof, cbEof, 1, fEof);
    fclose(fEof);

   	printf("\nOverlay data successfully dumped to %s", szoutchoice);

    return 0;
}
