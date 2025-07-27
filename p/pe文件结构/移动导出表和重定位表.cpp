#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
// 内存对齐宏
#define ALIGN_UP(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define min(a, b) ((a) < (b) ? (a) : (b))
using namespace std;
// 辅助函数：获取PE文件的NT头
IMAGE_NT_HEADERS* GetNtHeaders(LPVOID pFileBuffer) {
    if (pFileBuffer == NULL) return NULL;
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return (IMAGE_NT_HEADERS*)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
}

// 辅助函数：获取节表数组
IMAGE_SECTION_HEADER* GetSectionHeaders(IMAGE_NT_HEADERS* pNtHeaders) {
    if (pNtHeaders == NULL) return NULL;
    return (IMAGE_SECTION_HEADER*)((BYTE*)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
}

// 辅助函数：RVA转FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva) {
    IMAGE_NT_HEADERS* pNtHeaders = GetNtHeaders(pFileBuffer);
    if (!pNtHeaders) return 0;

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (dwRva >= pSectionHeader[i].VirtualAddress &&
            dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData) {
            return dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
        }
    }
    return 0;
}

// 辅助函数：FOA转RVA
DWORD FoaToRva(LPVOID pFileBuffer, DWORD dwFoa) {
    IMAGE_NT_HEADERS* pNtHeaders = GetNtHeaders(pFileBuffer);
    if (!pNtHeaders) return 0;

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (dwFoa >= pSectionHeader[i].PointerToRawData &&
            dwFoa < pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) {
            return dwFoa - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress;
        }
    }
    return 0;
}

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer) {
    FILE* pFile = NULL;
    DWORD fileSize = 0;
    LPVOID buffer = NULL;
    if (pFileBuffer == NULL) {
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
    *pFileBuffer = buffer;
    return fileSize;
}

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

// 添加新节函数
DWORD AddNewSection(LPVOID* ppFileBuffer, DWORD* pFileSize, const char* sectionName, DWORD sectionSize, DWORD characteristics) {
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)*ppFileBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)*ppFileBuffer + pDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
    
    // 获取最后一个节
    IMAGE_SECTION_HEADER* pLastSection = &pSectionHeaders[pNtHeaders->FileHeader.NumberOfSections - 1];
    
    // 计算新节的RVA和文件偏移
    DWORD newSectionRVA = ALIGN_UP(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, 
                                  pNtHeaders->OptionalHeader.SectionAlignment);
    DWORD newSectionFOA = ALIGN_UP(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, 
                                  pNtHeaders->OptionalHeader.FileAlignment);
    
    // 计算新文件大小
    DWORD newFileSize = ALIGN_UP(newSectionFOA + sectionSize, pNtHeaders->OptionalHeader.FileAlignment);
    
    // 重新分配内存
    LPVOID newBuffer = realloc(*ppFileBuffer, newFileSize);
    if (!newBuffer) {
        printf("Memory reallocation failed in AddNewSection\n");
        return 0;
    }
    *ppFileBuffer = newBuffer;
    
    // 更新NT头
    pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)*ppFileBuffer + pDosHeader->e_lfanew);
    pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
    pLastSection = &pSectionHeaders[pNtHeaders->FileHeader.NumberOfSections];
    
    // 初始化新节
    memset(pLastSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(pLastSection->Name, sectionName, min(8, strlen(sectionName)));
    pLastSection->Misc.VirtualSize = sectionSize;
    pLastSection->VirtualAddress = newSectionRVA;
    pLastSection->SizeOfRawData = ALIGN_UP(sectionSize, pNtHeaders->OptionalHeader.FileAlignment);
    pLastSection->PointerToRawData = newSectionFOA;
    pLastSection->Characteristics = characteristics;
    
    // 更新节数量
    pNtHeaders->FileHeader.NumberOfSections++;
    
    // 更新SizeOfImage
    pNtHeaders->OptionalHeader.SizeOfImage = ALIGN_UP(
        newSectionRVA + sectionSize, 
        pNtHeaders->OptionalHeader.SectionAlignment
    );
    
    // 更新文件大小
    *pFileSize = newFileSize;
    
    // 清空新节内容
    memset((BYTE*)*ppFileBuffer + newSectionFOA, 0, pLastSection->SizeOfRawData);
    
    return newSectionFOA; // 返回新节的FOA
}

// 移动导出表函数
BOOL MoveExportTable(LPVOID* ppFileBuffer, DWORD* pFileSize) {
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)*ppFileBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)*ppFileBuffer + pDosHeader->e_lfanew);
    
    // 获取导出表目录项
    IMAGE_DATA_DIRECTORY* exportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress == 0 || exportDir->Size == 0) {
        printf("No export table found\n");
        return FALSE;
    }
    
    // 获取导出表结构
    DWORD exportFoa = RvaToFoa(*ppFileBuffer, exportDir->VirtualAddress);
    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)*ppFileBuffer + exportFoa);
    
    // 获取DLL名称
    DWORD dllNameFoa = RvaToFoa(*ppFileBuffer, pExportDir->Name);
    char* dllName = (char*)((BYTE*)*ppFileBuffer + dllNameFoa);
    DWORD dllNameLen = strlen(dllName) + 1; // 包括null终止符
    
    // 计算导出表总大小
    DWORD totalSize = sizeof(IMAGE_EXPORT_DIRECTORY);
    totalSize += pExportDir->NumberOfFunctions * sizeof(DWORD);  // AddressOfFunctions
    totalSize += pExportDir->NumberOfNames * sizeof(DWORD);      // AddressOfNames
    totalSize += pExportDir->NumberOfNames * sizeof(WORD);       // AddressOfNameOrdinals
    
    // 计算函数名字符串总长度
    DWORD* nameRVAs = (DWORD*)((BYTE*)*ppFileBuffer + RvaToFoa(*ppFileBuffer, pExportDir->AddressOfNames));
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD nameFoa = RvaToFoa(*ppFileBuffer, nameRVAs[i]);
        totalSize += strlen((char*)*ppFileBuffer + nameFoa) + 1; // 字符串+null终止符
    }
    
    // 添加DLL名称长度
    totalSize += dllNameLen;
    
    // 添加新节
    DWORD newSectionFoa = AddNewSection(ppFileBuffer, pFileSize, ".edata", totalSize, 
                                       IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!newSectionFoa) {
        printf("Failed to add new section for export table\n");
        return FALSE;
    }
    
    // 获取新节RVA
    DWORD newSectionRva = FoaToRva(*ppFileBuffer, newSectionFoa);
    
    // 准备复制指针
    BYTE* newSectionStart = (BYTE*)*ppFileBuffer + newSectionFoa;
    BYTE* currentPos = newSectionStart;
    
    // 1. 复制AddressOfFunctions数组
    DWORD* srcFunctions = (DWORD*)((BYTE*)*ppFileBuffer + RvaToFoa(*ppFileBuffer, pExportDir->AddressOfFunctions));
    DWORD* destFunctions = (DWORD*)currentPos;
    memcpy(destFunctions, srcFunctions, pExportDir->NumberOfFunctions * sizeof(DWORD));
    DWORD newFunctionsRva = newSectionRva + (DWORD)((BYTE*)destFunctions - newSectionStart);
    currentPos += pExportDir->NumberOfFunctions * sizeof(DWORD);
    
    // 2. 复制AddressOfNameOrdinals数组
    WORD* srcOrdinals = (WORD*)((BYTE*)*ppFileBuffer + RvaToFoa(*ppFileBuffer, pExportDir->AddressOfNameOrdinals));
    WORD* destOrdinals = (WORD*)currentPos;
    memcpy(destOrdinals, srcOrdinals, pExportDir->NumberOfNames * sizeof(WORD));
    DWORD newOrdinalsRva = newSectionRva + (DWORD)((BYTE*)destOrdinals - newSectionStart);
    currentPos += pExportDir->NumberOfNames * sizeof(WORD);
    
    // 3. 复制AddressOfNames数组和函数名字符串
    DWORD* srcNames = (DWORD*)((BYTE*)*ppFileBuffer + RvaToFoa(*ppFileBuffer, pExportDir->AddressOfNames));
    DWORD* destNames = (DWORD*)currentPos;
    currentPos += pExportDir->NumberOfNames * sizeof(DWORD);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        // 复制字符串
        DWORD nameFoa = RvaToFoa(*ppFileBuffer, srcNames[i]);
        char* srcName = (char*)*ppFileBuffer + nameFoa;
        char* destName = (char*)currentPos;
        DWORD nameLen = strlen(srcName) + 1;
        memcpy(destName, srcName, nameLen);
        
        // 更新AddressOfNames数组
        destNames[i] = newSectionRva + (DWORD)(currentPos - newSectionStart);
        currentPos += nameLen;
    }
    DWORD newNamesRva = newSectionRva + (DWORD)((BYTE*)destNames - newSectionStart);
    
    // 4. 复制DLL名称字符串
    char* newDllName = (char*)currentPos;
    memcpy(newDllName, dllName, dllNameLen);
    DWORD newDllNameRva = newSectionRva + (DWORD)(currentPos - newSectionStart);
    currentPos += dllNameLen;
    
    // 5. 复制IMAGE_EXPORT_DIRECTORY结构
    IMAGE_EXPORT_DIRECTORY* destExportDir = (IMAGE_EXPORT_DIRECTORY*)currentPos;
    memcpy(destExportDir, pExportDir, sizeof(IMAGE_EXPORT_DIRECTORY));
    
    // 修复导出表指针
    destExportDir->AddressOfFunctions = newFunctionsRva;
    destExportDir->AddressOfNames = newNamesRva;
    destExportDir->AddressOfNameOrdinals = newOrdinalsRva;
    destExportDir->Name = newDllNameRva; // 更新DLL名称的RVA
    
    // 6. 更新数据目录
    DWORD newExportDirRva = newSectionRva + (DWORD)(currentPos - newSectionStart);
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = newExportDirRva;
    
    return TRUE;
}

// 移动重定位表函数
BOOL MoveRelocationTable(LPVOID* ppFileBuffer, DWORD* pFileSize) {
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)*ppFileBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)*ppFileBuffer + pDosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
        pDataDirectory = pOptionHeader->DataDirectory;
    } else {
        PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;
        pDataDirectory = pOptionHeader->DataDirectory;
    }
    // 获取导出表目录项
    IMAGE_DATA_DIRECTORY* relocDir = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
        printf("No relocation table found, %xh--%xh\n", relocDir->VirtualAddress, relocDir->Size);
        return FALSE;
    }
    
    // 添加新节
    DWORD newSectionFoa = AddNewSection(ppFileBuffer, pFileSize, ".reloc", relocDir->Size, 
                                       IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!newSectionFoa) {
        printf("Failed to add new section for relocation table\n");
        return FALSE;
    }
    
    // 获取重定位表FOA
    DWORD relocFoa = RvaToFoa(*ppFileBuffer, relocDir->VirtualAddress);
    
    // 复制重定位表数据
    memcpy((BYTE*)*ppFileBuffer + newSectionFoa, 
           (BYTE*)*ppFileBuffer + relocFoa, 
           relocDir->Size);
    
    // 更新数据目录
    DWORD newRelocRva = FoaToRva(*ppFileBuffer, newSectionFoa);
    relocDir->VirtualAddress = newRelocRva;
    
    return TRUE;
}

// 修改ImageBase并应用重定位修正
BOOL RebasePE(LPVOID pFileBuffer, DWORD newImageBase) {
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pFileBuffer;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    DWORD oldImageBase = 0;
    if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
        oldImageBase = pOptionHeader->ImageBase;
        pOptionHeader->ImageBase = newImageBase;    // 更新ImageBase
        pDataDirectory = pOptionHeader->DataDirectory;
    } else {
        PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNtHeaders->OptionalHeader;
        oldImageBase = pOptionHeader->ImageBase;
        pOptionHeader->ImageBase = newImageBase;
        pDataDirectory = pOptionHeader->DataDirectory;
    }
    // 如果新旧基址相同，不需要重定位
    if (oldImageBase == newImageBase) {
        printf("ImageBase unchanged (0x%08X), no rebasing needed\n", newImageBase);
        return TRUE;
    }
    printf("ImageBase changed from 0x%08X to 0x%08X\n", oldImageBase, newImageBase);
    
    // 获取重定位表
    IMAGE_DATA_DIRECTORY* relocDir = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
        printf("No relocation table found, skipping rebasing\n");
        return TRUE;
    }
    
    // 计算基址差值
    DWORD_PTR delta = (DWORD_PTR)newImageBase - (DWORD_PTR)oldImageBase;
    
    // 获取重定位表起始位置
    DWORD relocFoa = RvaToFoa(pFileBuffer, relocDir->VirtualAddress);
    IMAGE_BASE_RELOCATION* pRelocTable = (IMAGE_BASE_RELOCATION*)((BYTE*)pFileBuffer + relocFoa);
    
    // 遍历重定位块
    int i=1;
    while (pRelocTable->VirtualAddress != 0 && pRelocTable->SizeOfBlock != 0){  //遍历重定位表
        DWORD dwItems = ((pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2);
        PWORD pRelocData = (PWORD)((BYTE*)pRelocTable + 0x8);
        for (int i = 0; i < dwItems; i++ ){
            if (*(pRelocData + i) >> 12 == IMAGE_REL_BASED_HIGHLOW){    //IMAGE_REL_BASED_HIGHLOW = 3
                DWORD dwRva = ((*(pRelocData + i) & 0x0fff) + pRelocTable->VirtualAddress);
                DWORD dwFoa = RvaToFoa(pFileBuffer, dwRva);
                DWORD* pFuncall = (DWORD*)(pFileBuffer + dwFoa);
                *pFuncall += delta; //重定位
            }
        }
        pRelocTable = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocTable + pRelocTable->SizeOfBlock);
        i++;
    }
    return TRUE;
}

int main() {
    LPSTR inputFile = "D:\\code\\c++\\123.exe";
    LPSTR outputFile = "D:\\code\\c++\\abc.exe";
    
    LPVOID pFileBuffer = NULL;
    DWORD fileSize = 0;
    
    // 1. 读取PE文件到内存
    fileSize = ReadPEFile(inputFile, &pFileBuffer);
    if (fileSize == 0 || pFileBuffer == NULL) {
        printf("Failed to read PE file: %s\n", inputFile);
        return 1;
    }
    printf("Successfully read PE file: %s (Size: %lu bytes)\n", inputFile, fileSize);
    /*
    // 2. 移动导出表
    if (!MoveExportTable(&pFileBuffer, &fileSize)) {
        printf("Failed to move export table\n");
        free(pFileBuffer);
        return 1;
    }
    printf("Export table moved successfully\n");
    
    // 3. 移动重定位表
    if (!MoveRelocationTable(&pFileBuffer, &fileSize)) {
        printf("Failed to move relocation table\n");
        free(pFileBuffer);
        return 1;
    }
    printf("Relocation table moved successfully\n");
    */
    if (!RebasePE(pFileBuffer, 0x600000)){
        printf("Failed to change ImageBase\n");
        free(pFileBuffer);
        return 1;
    }
    printf("ImageBase changed successfully\n");
    // 4. 将修改后的缓冲区写回文件
    if (!MemoryToFile(pFileBuffer, fileSize, outputFile)) {
        printf("Failed to write output file: %s\n", outputFile);
        free(pFileBuffer);
        return 1;
    }
    printf("Successfully wrote modified PE file: %s (Size: %lu bytes)\n", outputFile, fileSize);
    
    // 清理内存
    free(pFileBuffer);
    return 0;
}