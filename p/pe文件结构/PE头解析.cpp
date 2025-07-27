#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <malloc.h>
#include <string.h> 

LPVOID ReadPEFile(LPSTR lpszFile) {
    FILE *pFile = NULL;
    DWORD fileSize = 0;
    LPVOID pFileBuffer = NULL;
    if ((pFile = fopen(lpszFile, "rb")) == NULL) {
        puts("Fail to open file!");
        return NULL;
    }
    fseek(pFile, 0, SEEK_END);  //定位到文件末尾
    fileSize = ftell(pFile);    //获取文件大小
    fseek(pFile, 0, SEEK_SET);  //回到文件开头
    pFileBuffer = malloc(fileSize); //分配缓冲区
    if (pFileBuffer == NULL) {
        puts("Memory allocation failed");
        fclose(pFile);
        return NULL;
    }
    size_t n = fread(pFileBuffer, 1, fileSize, pFile); //将文件数据读取到缓冲区
    if (n != fileSize) {
        printf("Read data failed! Read %zu of %lu bytes\n", n, fileSize);
        free(pFileBuffer);
        fclose(pFile);
        return NULL;
    }
    fclose(pFile);
    return pFileBuffer;
}

VOID PrintNTHeaders()
{
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    
    char path[MAX_PATH];
    strcpy(path, "C:\\Windows\\system32\\notepad.exe");
    pFileBuffer = ReadPEFile(path);
    if (pFileBuffer == NULL) {
        puts("Fail to read file!");
        return;
    }
    
    if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {
        printf("Invalid MZ signature: 0x%X\n", pDosHeader->e_magic);
        free(pFileBuffer);
        return;
    }
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    printf("******************** DOS Header ********************\n");
    printf("MZ signature: 0x%X\n", pDosHeader->e_magic);
    printf("PE offset: 0x%X\n", pDosHeader->e_lfanew);
    
    //使用BYTE*指针进行PE标志地址计算
    BYTE* pBase = (BYTE*)pFileBuffer;
    DWORD peOffset = pDosHeader->e_lfanew;
    if (*((DWORD*)(pBase + peOffset)) != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE signature: 0x%X\n", *((DWORD*)(pBase + peOffset)));
        free(pFileBuffer);
        return;
    }
    pNTHeader = (PIMAGE_NT_HEADERS)(pBase + peOffset);
    printf("\n******************** NT Header ********************\n");
    printf("Signature: 0x%X\n", pNTHeader->Signature);
    
    pPEHeader = &pNTHeader->FileHeader;
    printf("\n******************** PE Header ********************\n");
    printf("Machine: 0x%X\n", pPEHeader->Machine);
    printf("Number of sections: %d\n", pPEHeader->NumberOfSections);
    printf("Size of optional header: %d\n", pPEHeader->SizeOfOptionalHeader);
    printf("Characteristics: 0x%X\n", pPEHeader->Characteristics);
    
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    printf("\n******************** Optional Header ********************\n");
    printf("Magic: 0x%X\n", pOptionHeader->Magic);
    printf("Address of entry point: 0x%X\n", pOptionHeader->AddressOfEntryPoint);
    printf("Image base: 0x%X\n", pOptionHeader->ImageBase);
    printf("Section alignment: 0x%X\n", pOptionHeader->SectionAlignment);
    printf("File alignment: 0x%X\n", pOptionHeader->FileAlignment);
    
    pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    printf("\n******************** Section Table ********************\n");
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        printf("Section %d:\n", i + 1);
        printf("  Name: %-8.8s\n", pSectionHeader->Name);
        printf("  Misc: 0x%X\n", pSectionHeader->Misc);
        printf("  Virtual address: 0x%X\n", pSectionHeader->VirtualAddress);
        printf("  Size of raw data: 0x%X\n", pSectionHeader->SizeOfRawData);
        printf("  Pointer to raw data: 0x%X\n", pSectionHeader->PointerToRawData);
        printf("  Characteristics: 0x%X\n", pSectionHeader->Characteristics);
        printf("\n");
        
        pSectionHeader++; //指针递增到下一个节表项
    }
    free(pFileBuffer);
}

int main()
{
    PrintNTHeaders();
    return 0;
}
