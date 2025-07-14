#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h> 

#define shellcode_l 0x12
#define MessageBoxAddr 0x755D15A0
BYTE shellcode[] = {
    0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 
    0xE8, 00, 00, 00, 00, //751B AE23
    0xE9, 00, 00, 00, 00  //FFFF A8A1
};

// --- 函数原型声明 ---
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, IN DWORD imageSize, OUT LPVOID* pNewBuffer);
BOOL MemoryToFile(IN LPVOID pNewBuffer, IN size_t size, OUT LPSTR lpszFile);
DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);

/**
 * @brief 将文件读取到缓冲区FileBuffer
 * @param lpszFile 输入的文件路径
 * @param pFileBuffer 输出参数，指向文件内容缓冲区的指针
 * @return 成功则返回文件大小，失败返回 0
 */
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer) {
    FILE* pFile = NULL;
    DWORD fileSize = 0;
    LPVOID buffer = NULL;
    if (pFileBuffer == NULL) {  // 检查输出指针是否有效
        puts("Output pointer pFileBuffer is NULL!");
        return 0;
    }
    *pFileBuffer = NULL;
    if ((pFile = fopen(lpszFile, "rb")) == NULL) {
        printf("Fail to open file: %s\n", lpszFile);
        return 0;
    }
    fseek(pFile, 0, SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);
    buffer = malloc(fileSize);
    if (buffer == NULL) {
        puts("Memory allocation failed in ReadPEFile");
        fclose(pFile);
        return 0;
    }
    size_t n = fread(buffer, 1, fileSize, pFile);
    if (n != fileSize) {
        printf("Read data failed! Read %zu of %lu bytes\n", n, fileSize);
        free(buffer);
        fclose(pFile);
        return 0;
    }
    fclose(pFile);
    *pFileBuffer = buffer; // 将分配的缓冲区地址赋给输出参数
    return fileSize;
}

/**
 * @brief 将文件从FileBuffer复制到ImageBuffer（模拟PE加载）
 * @param pFileBuffer 指向文件内容缓冲区的指针
 * @param pImageBuffer 输出参数，指向内存镜像缓冲区的指针
 * @return 成功则返回镜像大小 (SizeOfImage)，失败返回 0
 */
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer) {
    if (pFileBuffer == NULL || pImageBuffer == NULL) {
        puts("Invalid input parameters for CopyFileBufferToImageBuffer");
        return 0;
    }
    *pImageBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        puts("Invalid MZ signature.");
        return 0;
    }
    pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        puts("Invalid PE signature.");
        return 0;
    }
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    // 根据可选头部的Magic字段判断是32位还是64位PE
    if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;
        sizeOfImage = pNTHeader64->OptionalHeader.SizeOfImage;
        sizeOfHeaders = pNTHeader64->OptionalHeader.SizeOfHeaders;
    }
    else if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_NT_HEADERS32 pNTHeader32 = (PIMAGE_NT_HEADERS32)pNTHeader;
        sizeOfImage = pNTHeader32->OptionalHeader.SizeOfImage;
        sizeOfHeaders = pNTHeader32->OptionalHeader.SizeOfHeaders;
    }
    else {
        puts("Unsupported PE format (not 32 or 64 bit).");
        return 0;
    }
    // 分配ImageBuffer内存
    LPVOID imageBuffer = malloc(sizeOfImage);
    if (imageBuffer == NULL) {
        puts("Memory allocation for ImageBuffer failed.");
        return 0;
    }
    memset(imageBuffer, 0, sizeOfImage); // 将缓冲区清零
    // 1. 复制PE头部
    memcpy(imageBuffer, pFileBuffer, sizeOfHeaders);
    // 2. 复制节区
    pPEHeader = &pNTHeader->FileHeader;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        // 计算节区在ImageBuffer中的目标地址
        LPVOID dest = (BYTE*)imageBuffer + pSectionHeader->VirtualAddress;
        // 计算节区在FileBuffer中的源地址
        LPVOID src = (BYTE*)pFileBuffer + pSectionHeader->PointerToRawData;
        // 复制节区数据
        memcpy(dest, src, pSectionHeader->SizeOfRawData);
        pSectionHeader++;
    }
    *pImageBuffer = imageBuffer;
    return sizeOfImage;
}
/**
 * @brief 将内存布局的ImageBuffer转换回文件布局的NewBuffer (CopyFileBufferToImageBuffer的逆过程)
 * @param pImageBuffer 指向内存镜像缓冲区的指针 (sections at VirtualAddress)
 * @param pNewBuffer 输出参数，指向新文件布局缓冲区的指针 (sections at PointerToRawData)
 * @return 成功则返回新缓冲区（即文件）的大小，失败返回 0
 */
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer) {
    if (pImageBuffer == NULL || pNewBuffer == NULL) {
        puts("Invalid input parameters for CopyImageBufferToNewBuffer");
        return 0;
    }
    *pNewBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    // 1. 从 ImageBuffer 解析PE头
    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        puts("Invalid MZ signature in ImageBuffer.");
        return 0;
    }
    pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pImageBuffer + pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        puts("Invalid PE signature in ImageBuffer.");
        return 0;
    }
    // 2. 计算最终文件的大小
    // 文件大小由最后一个节区的文件偏移 + 大小决定
    DWORD fileSize = pNTHeader->OptionalHeader.SizeOfHeaders; // 至少有头部那么大
    pPEHeader = &pNTHeader->FileHeader;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        DWORD sectionEndOffset = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;
        if (sectionEndOffset > fileSize) {
            fileSize = sectionEndOffset;
        }
        pSectionHeader++;
    }
    // 3. 分配 NewBuffer 内存
    LPVOID newBuffer = malloc(fileSize);
    if (newBuffer == NULL) {
        puts("Memory allocation for NewBuffer failed.");
        return 0;
    }
    memset(newBuffer, 0, fileSize);
    // 4. 开始逆向转换
    // 4.1. 复制PE头
    memcpy(newBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
    // 4.2. 逆向复制所有节区
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        // 源地址：ImageBuffer 中的虚拟地址
        LPVOID src = (BYTE*)pImageBuffer + pSectionHeader->VirtualAddress;
        // 目标地址：NewBuffer 中的文件偏移地址
        LPVOID dest = (BYTE*)newBuffer + pSectionHeader->PointerToRawData;
        // 复制大小：节区在文件中的原始数据大小
        DWORD sizeToCopy = pSectionHeader->SizeOfRawData;
        // 确保有数据需要复制
        if (sizeToCopy > 0) {
            memcpy(dest, src, sizeToCopy);
        }
        pSectionHeader++;
    }
    *pNewBuffer = newBuffer;
    return fileSize;
}

BOOL InjectShellcodeToImageBuffer(LPVOID pImageBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pImageBuffer + pDosHeader->e_lfanew);
    pPEHeader = &pNTHeader->FileHeader;
    int NumberOfSections = pPEHeader->NumberOfSections;
    //pOptionHeader = &pNTHeader->OptionalHeader;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    //pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBuffer + pDosHeader->e_lfanew)+ 4 + sizeof(IMAGE_FILE_HEADER));
    //pSectionHeader = (PIMAGE_SECTION_HEADER)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_NT_OPTIONAL_HDR32_MAGIC));
    int sectionHeaderNumber = 9;
    PIMAGE_SECTION_HEADER pTrulySectionHeader = pSectionHeader + sectionHeaderNumber;
    if(sectionHeaderNumber >= NumberOfSections){ printf("Section is null"); return 0;}
    if(pTrulySectionHeader->SizeOfRawData < pTrulySectionHeader->Misc.VirtualSize || ((pTrulySectionHeader->SizeOfRawData) - (pTrulySectionHeader->Misc.VirtualSize)) < shellcode_l){
        printf("Size of free code is no!\n");
        return 0;
    }
    //将代码复制到空闲区
    DWORD codeBeginRVA = pTrulySectionHeader->VirtualAddress + pTrulySectionHeader->Misc.VirtualSize;
    //DWORD codeBeginRVA = 0x11000 + 0x5770 + 0x10;
    PBYTE codeBegin = (PBYTE)pImageBuffer + codeBeginRVA;
    memcpy(codeBegin, shellcode, shellcode_l);
    //修正E8
    DWORD callAddr = (DWORD)(MessageBoxAddr - (pOptionHeader->ImageBase + codeBeginRVA + 0xD));
    *(PDWORD)(codeBegin + 9) = callAddr;
    //修正E9
    DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + codeBeginRVA + 0x12));
    *(PDWORD)(codeBegin + 0xE) = jmpAddr;
    //修改OEP
    pOptionHeader->AddressOfEntryPoint = codeBeginRVA;
    DWORD x = pTrulySectionHeader->Characteristics;
    DWORD y = pSectionHeader->Characteristics;
    pTrulySectionHeader->Characteristics = x|y;
    //printf("codeBeginRVA： 0x%X\n", codeBeginRVA);
    for(int i=0;i<0x12;i++){
        //printf("codeBegin%d： 0x%X\n", i, *(codeBegin + i));
    }
    return true;
}
/**
 * @brief 在 ImageBuffer 中新增一个节
 * @param ppImageBuffer 指向 ImageBuffer 指针的指针 (LPVOID*). 因为可能需要 realloc, 所以需要修改原指针.
 * @param sectionName 新节的名称 (最多8字节).
 * @param sectionSize 新节的实际大小.
 * @param characteristics 新节的属性 (例如 IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE).
 * @return 成功返回 TRUE, 失败返回 FALSE.
 */
DWORD AlignUp(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}
BOOL AddSectionToImageBuffer(LPVOID* ppImageBuffer, char* sectionName, DWORD sectionSize, DWORD characteristics){
    if (ppImageBuffer == NULL || *ppImageBuffer == NULL ) {//|| sectionSize == 0) {
        return FALSE;
    }
    LPVOID pImageBuffer = *ppImageBuffer;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS32 pNTHeader = (PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = &pNTHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
    DWORD SectionAlignment = pOptionHeader->SectionAlignment;
    DWORD FileAlignment = pOptionHeader->FileAlignment;
    DWORD NumberOfSections = pPEHeader->NumberOfSections;
                // 2. 检查头部空间是否足够 (要求 1)
    // 计算当前所有节表占用的空间
    DWORD sizeOfExistingSectionHeaders = NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    // 计算 PE 头 + 所有节表的总大小
    // (PBYTE)pFirstSectionHeader 是第一个节表的起始地址
    DWORD usedHeaderSize = (DWORD)((PBYTE)pFirstSectionHeader - (PBYTE)pImageBuffer) + sizeOfExistingSectionHeaders;
    // SizeOfHeaders 是整个头部（包括节表）在内存中对齐后的大小
    DWORD availableSpace = pOptionHeader->SizeOfHeaders - usedHeaderSize;
    // 我们需要 2 个节表大小的空间 (一个新的节表 + 一个全零的结束节表)
    if (availableSpace < 2 * sizeof(IMAGE_SECTION_HEADER)) {
        printf("Error: Not enough space in the header for a new section.\n");
        // 理论上可以通过移动第一个节来腾出空间，但这极其复杂，这里我们选择放弃。
        return FALSE;
    }
                // 3. 定位最后一个节和新节表的位置
    // 最后一个有效节表
    PIMAGE_SECTION_HEADER pLastSection = pFirstSectionHeader + (NumberOfSections - 1);
    // 新节表的位置（紧跟在最后一个有效节表之后，这里原本是全零的结束符）
    PIMAGE_SECTION_HEADER pNewSectionHeader = pFirstSectionHeader + NumberOfSections;

                // 4. 计算新节的 RVA 和大小
    // 新节的 RVA 必须在最后一个节的末尾，并按照 SectionAlignment 对齐
    DWORD newSectionRVA = AlignUp(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, SectionAlignment);
    // 新节在内存中对齐后的大小
    DWORD newSectionSizeAligned = AlignUp(sectionSize, SectionAlignment);
    // 新节在文件中的大小（虽然是 ImageBuffer，但模拟 FileBuffer 结构）
    DWORD newSectionSizeOnDisk = AlignUp(sectionSize, FileAlignment);

                // 5. 计算新的 SizeOfImage 并重新分配内存 (要求 4 & 5)
    DWORD oldSizeOfImage = pOptionHeader->SizeOfImage;
    // 新的 SizeOfImage = 新节的 RVA + 新节对齐后的大小
    DWORD newSizeOfImage = AlignUp(newSectionRVA + newSectionSizeAligned, SectionAlignment);
    // 如果新镜像大小大于旧的，需要重新分配 ImageBuffer
    if (newSizeOfImage > oldSizeOfImage) {
        // 使用 realloc 重新分配内存
        LPVOID newImageBuffer = realloc(pImageBuffer, newSizeOfImage);
        if (newImageBuffer == NULL) {
            printf("Error: Failed to reallocate memory for the new section.\n");
            return FALSE;
        }
        // 重要：如果 realloc 移动了内存块，需要更新所有指针！
        if (newImageBuffer != pImageBuffer) {
            *ppImageBuffer = newImageBuffer;
            pImageBuffer = newImageBuffer;
            // 重新定位 PE 头指针
            pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
            pNTHeader = (PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);
            pPEHeader = &pNTHeader->FileHeader;
            pOptionHeader = &pNTHeader->OptionalHeader;
            pFirstSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
            pNewSectionHeader = pFirstSectionHeader + NumberOfSections;
        }
        // 将新扩展出来的内存区域清零 (要求 2 的后半部分)
        memset((PBYTE)pImageBuffer + oldSizeOfImage, 0, newSizeOfImage - oldSizeOfImage);
    }

                // 6. 填充新节表信息 (要求 2 & 6)
    // 清空新节表位置（因为它可能包含旧数据或之前的NULL结束符）
    memset(pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    // 设置名称
    strncpy((char*)pNewSectionHeader->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME);
    // 设置大小和地址
    pNewSectionHeader->Misc.VirtualSize = sectionSize;          // 实际大小
    pNewSectionHeader->VirtualAddress = newSectionRVA;          // 内存 RVA
    pNewSectionHeader->SizeOfRawData = newSectionSizeOnDisk;    // 文件对齐后大小
    // 设置 PointerToRawData (文件偏移)。在 ImageBuffer 中这不太重要，但为了完整性，
    // 我们模拟它在 FileBuffer 中的位置，通常紧跟上一个节的文件末尾。
    // 注意：pLastSection 指针可能在 realloc 后失效，需要重新获取
    pLastSection = pFirstSectionHeader + (NumberOfSections - 1);
    pNewSectionHeader->PointerToRawData = AlignUp(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, FileAlignment);
    // 设置属性 (要求 6)
    pNewSectionHeader->Characteristics = characteristics;

                // 7. 确保新节表后面有一个全零的节表 (要求：最后一个节表后面要留40字节全零)
    PIMAGE_SECTION_HEADER pNullTerminator = pNewSectionHeader + 1;
    memset(pNullTerminator, 0, sizeof(IMAGE_SECTION_HEADER));

                // 8. 更新 PE 头信息
    // 修改节的数量 (要求 3)
    pPEHeader->NumberOfSections += 1;
    // 修改 SizeOfImage (要求 4)
    pOptionHeader->SizeOfImage = newSizeOfImage;
    return TRUE;
}

/**
 * @brief 在 ImageBuffer 中扩大最后一个节的大小。
 *
 * @param ppImageBuffer 指向 ImageBuffer 指针的指针 (LPVOID*). 因为需要 realloc, 所以需要修改原指针.
 * @param additionalSize 希望增加的字节数.
 * @return 成功返回 TRUE, 失败返回 FALSE.
 */
BOOL ExpandLastSectionInImageBuffer(LPVOID* ppImageBuffer, DWORD additionalSize) {
    if (ppImageBuffer == NULL || *ppImageBuffer == NULL || additionalSize == 0) {
        return FALSE;
    }
    LPVOID pImageBuffer = *ppImageBuffer;
                // 1. 定位 PE 头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    // 注意：这里假设处理的是 32 位 PE 文件 (PE32)。
    // 如果需要处理 64 位 (PE32+)，需要使用 PIMAGE_NT_HEADERS64 并进行判断。
    PIMAGE_NT_HEADERS32 pNTHeader = (PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid PE Signature.\n");
        return FALSE;
    }
    PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = &pNTHeader->OptionalHeader;
    DWORD SectionAlignment = pOptionHeader->SectionAlignment;
    DWORD FileAlignment = pOptionHeader->FileAlignment; // 虽在内存中，但更新 SizeOfRawData 时需要
    DWORD NumberOfSections = pPEHeader->NumberOfSections;
    DWORD OldSizeOfImage = pOptionHeader->SizeOfImage;
    if (NumberOfSections == 0) {
        printf("Error: No sections found.\n");
        return FALSE;
    }
                // 2. 定位最后一个节
    PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
    PIMAGE_SECTION_HEADER pLastSection = pFirstSectionHeader + (NumberOfSections - 1);

                // 3. 计算新的大小
    // 新的 VirtualSize (节的实际数据大小)
    DWORD newVirtualSize = pLastSection->Misc.VirtualSize + additionalSize;
    // 新的 SizeOfImage (最后一个节的RVA + 新的VirtualSize, 按 SectionAlignment 对齐)
    DWORD newSizeOfImage = AlignUp(pLastSection->VirtualAddress + newVirtualSize, SectionAlignment);
    // 检查是否真的需要扩展 ImageBuffer
    if (newSizeOfImage == OldSizeOfImage) {
        printf("Info: Slack space in memory sufficient. No reallocation needed.\n");
        // 空间足够，只需更新 VirtualSize
        pLastSection->Misc.VirtualSize = newVirtualSize;
        // 同时更新 SizeOfRawData (如果需要保存回文件)
        pLastSection->SizeOfRawData = AlignUp(newVirtualSize, FileAlignment);
        return TRUE;
    }
                // 4. 重新分配 ImageBuffer 内存 (realloc)
    printf("Attempting to reallocate ImageBuffer from 0x%X to 0x%X\n", OldSizeOfImage, newSizeOfImage);
    LPVOID newImageBuffer = realloc(pImageBuffer, newSizeOfImage);
    if (newImageBuffer == NULL) {
        printf("Error: Failed to reallocate memory (realloc failed).\n");
        // pImageBuffer (旧的) 仍然有效，但操作失败
        return FALSE;
    }

                // 5. 更新指针 (如果 realloc 移动了内存块)
    if (newImageBuffer != pImageBuffer) {
        printf("Info: ImageBuffer moved by realloc. Updating pointers.\n");
        *ppImageBuffer = newImageBuffer;
        pImageBuffer = newImageBuffer;
        // 重新定位所有 PE 头指针
        pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
        pNTHeader = (PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);
        pPEHeader = &pNTHeader->FileHeader;
        pOptionHeader = &pNTHeader->OptionalHeader;
        pFirstSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
        pLastSection = pFirstSectionHeader + (NumberOfSections - 1);
    }

                // 6. 将新扩展出来的内存空间清零
    // 新增的空间从 OldSizeOfImage 开始，长度为 newSizeOfImage - OldSizeOfImage
    memset((PBYTE)pImageBuffer + OldSizeOfImage, 0, newSizeOfImage - OldSizeOfImage);

                // 7. 更新节表信息
    pLastSection->Misc.VirtualSize = newVirtualSize;
    // 重要：同时更新 SizeOfRawData (文件大小)，以便如果将此 ImageBuffer 转换回 FileBuffer 时保持一致
    pLastSection->SizeOfRawData = AlignUp(newVirtualSize, FileAlignment);

                // 8. 更新 Optional Header 中的 SizeOfImage
    pOptionHeader->SizeOfImage = newSizeOfImage;
    printf("Success: Last section and SizeOfImage expanded.\n");
    return TRUE;
}
/**
 * @brief 将 ImageBuffer 中的所有节合并到第一个节中。
 *
 * @param pImageBuffer 指向已拉伸的内存映像 (ImageBuffer) 的指针 (LPVOID).
 * @return 成功返回 TRUE, 失败返回 FALSE.
 */
BOOL MergeSectionsToFirst(LPVOID pImageBuffer) {
    if (pImageBuffer == NULL) {
        return FALSE;
    }

    // 1. 定位 PE 头 (假设为 32 位 PE)
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS32 pNTHeader = (PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pDosHeader->e_lfanew);

    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid PE Signature.\n");
        return FALSE;
    }

    PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = &pNTHeader->OptionalHeader;
    DWORD NumberOfSections = pPEHeader->NumberOfSections;
    DWORD FileAlignment = pOptionHeader->FileAlignment;

    // 如果节的数量小于等于1，无需合并
    if (NumberOfSections <= 1) {
        printf("Info: Only one or zero sections, no merging needed.\n");
        return TRUE;
    }

    // 2. 定位第一个节和最后一个节
    PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNTHeader);
    PIMAGE_SECTION_HEADER pLastSection = pFirstSection + (NumberOfSections - 1);

    // 3. 计算合并后的新属性 (要求 4: 将第一个节的属性改为包含所有节的属性)
    DWORD newCharacteristics = 0;
    PIMAGE_SECTION_HEADER pCurrentSection = pFirstSection;
    for (DWORD i = 0; i < NumberOfSections; ++i) {
        newCharacteristics |= pCurrentSection->Characteristics;
        pCurrentSection++;
    }

    // 4. 计算合并后的新大小 (要求 2 & 3)
    // 确定最后一个节的实际结束大小 (取 VirtualSize 和 SizeOfRawData 中较大的一个，虽然在 ImageBuffer 中 VirtualSize 更关键)
    DWORD lastSectionEndSize = (pLastSection->SizeOfRawData > pLastSection->Misc.VirtualSize) ? 
                                pLastSection->SizeOfRawData : pLastSection->Misc.VirtualSize;

    // 新的 VirtualSize = 最后一个节的结束 RVA - 第一个节的起始 RVA
    // 结束 RVA = pLastSection->VirtualAddress + lastSectionEndSize
    // 注意：这里假设第一个节的 VirtualAddress 是所有节中最小的（通常如此）。
    DWORD newVirtualSize = (pLastSection->VirtualAddress + lastSectionEndSize) - pFirstSection->VirtualAddress;

    // 新的 SizeOfRawData (需要按 FileAlignment 对齐)
    DWORD newSizeOfRawData = AlignUp(newVirtualSize, FileAlignment);

    // 5. 更新第一个节的信息
    pFirstSection->Misc.VirtualSize = newVirtualSize;
    pFirstSection->SizeOfRawData = newSizeOfRawData;
    pFirstSection->Characteristics = newCharacteristics;

    // 6. 更新 PE 头中的节数量 (要求 5)
    pPEHeader->NumberOfSections = 1;

    // 7. 清理剩余的节表 (可选，但是好习惯)
    // 将第一个节表之后的其他节表全部清零
    PIMAGE_SECTION_HEADER pNextSection = pFirstSection + 1;
    DWORD sizeToClear = (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER);
    memset(pNextSection, 0, sizeToClear);
    // 注意：SizeOfImage 不需要修改，因为它已经足够大以容纳最后一个节的末尾。
    printf("Success: Merged %d sections into the first section.\n", NumberOfSections);
    printf("New VirtualSize: 0x%X\n", newVirtualSize);
    printf("New Characteristics: 0x%X\n", newCharacteristics);
    return TRUE;
}
int main() {
    //char szSrcFile[] = "C:\\Windows\\System32\\notepad.exe";
    //char szSrcFile[] = "D:\\code\\sublime\\111.exe";
    char szSrcFile[] = "D:\\code\\c++\\新增节ing.exe";
    //char szSrcFile[] = "D:\\Download\\WPS Office\\ksolaunch.exe";
    //char szDstFile[] = "D:\\code\\c++\\1_wps.exe";
    char szDstFile[] = "D:\\code\\c++\\新增节ed.exe"; // 将在当前程序目录下生成 1.exe

    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewBuffer = NULL;
    DWORD fileSize = 0;
    DWORD imageSize = 0;
    DWORD newBufferSize = 0;

    PIMAGE_NT_HEADERS pNTHeader_ForTest;
    DWORD entryPointRva;
    DWORD entryPointFoa;

    // 步骤 1: 读取PE文件到 pFileBuffer
    printf("Step 1: Reading PE file '%s' into buffer...\n", szSrcFile);
    fileSize = ReadPEFile(szSrcFile, &pFileBuffer);
    if (fileSize == 0) {
        puts("Failed to read PE file.");
        return 0;
    }
    printf("Success. Read %lu bytes.\n\n", fileSize);
    
    /*printf("--- Testing RVA to FOA conversion ---\n");
    pNTHeader_ForTest = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);
    entryPointRva = pNTHeader_ForTest->OptionalHeader.AddressOfEntryPoint;
    entryPointRva = 0x1001;
    printf("Address Of Entry Point (RVA): 0x%X\n", entryPointRva);
    entryPointFoa = RvaToFoa(pFileBuffer, entryPointRva);
    if (entryPointFoa != 0) {
        printf("Calculated File Offset (FOA): 0x%X\n\n", entryPointFoa);
    } else {
        printf("Failed to convert Entry Point RVA to FOA.\n\n");
    }*/

    // 步骤 2: 将 pFileBuffer 映射到 pImageBuffer
    printf("Step 2: Copying file buffer to image buffer (simulating PE loading)...\n");
    imageSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
    if (imageSize == 0) {
        puts("Failed to copy to image buffer.");
        free(pFileBuffer);
        return 0;
    }
    printf("Success. Image size is %lu bytes.\n\n", imageSize);

    //新增节
    AddSectionToImageBuffer(&pImageBuffer, "hellosec", 0x28, 0x60000020);
    //扩大节
    ExpandLastSectionInImageBuffer(&pImageBuffer, 0x1DA);

    //任意节空白区添加代码
    if(InjectShellcodeToImageBuffer(pImageBuffer)){
        printf("The code was added successfully\n");
    }else{
        printf("Failed to add code\n");
    }

    // 步骤 3: 将 pImageBuffer 复制到 pNewBuffer
    printf("Step 3: Copying image buffer to a new buffer...\n");
    newBufferSize = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
    if (newBufferSize == 0) {
        puts("Failed to copy to new buffer.");
        free(pFileBuffer);
        free(pImageBuffer);
        return 0;
    }
    printf("Success. New buffer created with size %lu bytes.\n\n", newBufferSize);
    // 步骤 4: 将 pNewBuffer 写入文件
    printf("Step 4: Writing the new buffer to file '%s'...\n", szDstFile);
    //if (!MemoryToFile(pFileBuffer, fileSize, szDstFile)) {
    if (!MemoryToFile(pNewBuffer, newBufferSize, szDstFile)) {
        puts("Failed to write memory to file.");
        free(pFileBuffer);
        free(pImageBuffer);
        free(pNewBuffer);
        return 0;
    }
    printf("Success. File '%s' created.\n\n", szDstFile);
    
    puts("All operations completed successfully!");

    return 0;
}

/**
 * @brief 将内存中的数据复制到文件
 * @param pBuffer 指向要写入文件的内存缓冲区
 * @param size 要写入的数据大小
 * @param lpszFile 输出文件的路径
 * @return 成功返回 TRUE, 失败返回 FALSE
 */
BOOL MemoryToFile(IN LPVOID pBuffer, IN size_t size, OUT LPSTR lpszFile) {
    if (pBuffer == NULL || size == 0 || lpszFile == NULL) {
        puts("Invalid input parameters for MemoryToFile");
        return FALSE;
    }
    FILE* pFile = NULL;
    if ((pFile = fopen(lpszFile, "wb")) == NULL) {
        printf("Fail to create output file: %s\n", lpszFile);
        return FALSE;
    }
    size_t written = fwrite(pBuffer, 1, size, pFile);
    fclose(pFile);
    if (written != size) {
        printf("Failed to write all data to file. Wrote %zu of %zu bytes.\n", written, size);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief 将 RVA (Relative Virtual Address) 转换为 FOA (File Offset Address)
 * @param pFileBuffer 指向文件内容缓冲区的指针
 * @param dwRva 要转换的RVA值
 * @return 成功则返回计算出的FOA，失败（如RVA无效）则返回 0
 */
DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva) {
    if (pFileBuffer == NULL) {
        return 0;
    }
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    // 1. 解析PE头
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0; // 不是有效的PE文件
    }
    pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        return 0; // PE签名无效
    }
    // 2. 检查RVA是否在PE头内
    // 如果是，RVA直接等于FOA
    if (dwRva < pNTHeader->OptionalHeader.SizeOfHeaders) {
        return dwRva;
    }
    // 3. 遍历节表，查找RVA所在的节区
    pPEHeader = &pNTHeader->FileHeader;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    WORD wNumberOfSections = pPEHeader->NumberOfSections;
    for (WORD i = 0; i < wNumberOfSections; i++) {
        DWORD dwVirtualAddress = pSectionHeader->VirtualAddress;
        // 使用 VirtualSize 来判断范围，因为这是节区在内存中的实际大小
        DWORD dwVirtualSize = pSectionHeader->Misc.VirtualSize; 
        if (dwRva >= dwVirtualAddress && dwRva < (dwVirtualAddress + dwVirtualSize)) {
            // 4. 在节区内找到，进行转换
            // 公式：FOA = RVA - 节区虚拟地址 + 节区文件偏移
            DWORD dwFoa = (dwRva - dwVirtualAddress) + pSectionHeader->PointerToRawData;
            return dwFoa;
        }
    }
    // 5. 如果遍历完所有节区都未找到，说明RVA无效
    return 0;
}