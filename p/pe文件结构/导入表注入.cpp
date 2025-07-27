#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

BOOL InjectImportTable(LPCSTR pszFilePath, LPCSTR pszDllName, LPCSTR pszFuncName) {
    HANDLE hFile = CreateFileA(pszFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return FALSE;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // 获取导入表信息
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    
    // 查找导入表所在节
    PIMAGE_SECTION_HEADER pImportSection = NULL;
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (importRVA >= pSection[i].VirtualAddress && 
            importRVA < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
            pImportSection = &pSection[i];
            break;
        }
    }
    if (!pImportSection) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // 计算所需空间
    DWORD newImportSize = importSize + sizeof(IMAGE_IMPORT_DESCRIPTOR); // 增加新描述符
    DWORD dllNameLen = (DWORD)strlen(pszDllName) + 1;
    DWORD funcNameLen = (DWORD)strlen(pszFuncName) + 1 + sizeof(WORD); // Hint + 函数名
    
    // 计算总需求空间 (描述符+INT+IAT+DLL名+函数名)
    DWORD totalSpace = newImportSize + 2 * sizeof(DWORD_PTR) * 2 + dllNameLen + funcNameLen;

    // 寻找空白区域 (从各节末尾查找)
    PIMAGE_SECTION_HEADER pTargetSection = NULL;
    DWORD blankOffset = 0;
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = pSection[i].PointerToRawData + pSection[i].SizeOfRawData;
        DWORD blankSize = sectionEnd - (pSection[i].PointerToRawData + pSection[i].Misc.VirtualSize);
        
        if (blankSize >= totalSpace) {
            pTargetSection = &pSection[i];
            blankOffset = pSection[i].PointerToRawData + pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pTargetSection) {
        // 没有足够空间，使用文件末尾
        pTargetSection = &pSection[pNtHeaders->FileHeader.NumberOfSections - 1];
        blankOffset = pTargetSection->PointerToRawData + pTargetSection->SizeOfRawData;
        
        // 扩展文件大小
        DWORD newFileSize = blankOffset + totalSpace;
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        
        // 重新打开文件并设置大小
        hFile = CreateFileA(pszFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        SetFilePointer(hFile, newFileSize, NULL, FILE_BEGIN);
        SetEndOfFile(hFile);
        
        // 重新映射
        hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, newFileSize, NULL);
        pBase = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, newFileSize);
        if (!pBase) return FALSE;
        
        // 更新指针
        pDosHeader = (PIMAGE_DOS_HEADER)pBase;
        pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);
        pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        pTargetSection = &pSection[pNtHeaders->FileHeader.NumberOfSections - 1];
    }

    // 计算新导入表RVA
    DWORD newImportRVA = pTargetSection->VirtualAddress + (blankOffset - pTargetSection->PointerToRawData);
    DWORD newImportOffset = blankOffset;

    // 1. 复制原导入表
    DWORD oldImportOffset = importRVA - pImportSection->VirtualAddress + pImportSection->PointerToRawData;
    memcpy((BYTE*)pBase + newImportOffset, (BYTE*)pBase + oldImportOffset, importSize);
    
    // 2. 追加新的导入描述符
    PIMAGE_IMPORT_DESCRIPTOR pNewImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + newImportOffset + importSize);
    memset(pNewImport, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    
    // 3. 在描述符后追加结束标记
    PIMAGE_IMPORT_DESCRIPTOR pEnd = pNewImport + 1;
    memset(pEnd, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    
    // 4. 计算INT/IAT位置
    DWORD thunkOffset = newImportOffset + newImportSize;
    PDWORD_PTR pINT = (PDWORD_PTR)((BYTE*)pBase + thunkOffset);
    PDWORD_PTR pIAT = pINT + 2; // INT后紧跟IAT
    
    // 5. 设置INT/IAT内容
    *pINT = 0; // 初始化为0
    *(pINT + 1) = 0; // 结束标记
    *pIAT = 0;
    *(pIAT + 1) = 0;
    
    // 6. 写入DLL名称
    DWORD dllNameOffset = thunkOffset + 4 * sizeof(DWORD_PTR); // INT(8)+IAT(8)=16字节
    strcpy((char*)pBase + dllNameOffset, pszDllName);
    
    // 7. 写入函数名结构
    DWORD funcNameOffset = dllNameOffset + dllNameLen;
    *(WORD*)((BYTE*)pBase + funcNameOffset) = 0; // Hint=0
    strcpy((char*)pBase + funcNameOffset + sizeof(WORD), pszFuncName);
    
    // 8. 设置描述符字段
    pNewImport->OriginalFirstThunk = newImportRVA + importSize; // INT的RVA
    pNewImport->Name = newImportRVA + newImportSize; // DLL名称RVA
    pNewImport->FirstThunk = newImportRVA + newImportSize + 8; // IAT的RVA (INT后8字节)
    
    // 9. 设置函数地址指针
    *pINT = newImportRVA + newImportSize + 16; // 函数名结构RVA (INT后16字节)
    *pIAT = *pINT; // 初始时相同
    
    // 10. 更新数据目录
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newImportRVA;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newImportSize;
    
    // 11. 更新节属性
    pTargetSection->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    pTargetSection->Misc.VirtualSize = ALIGN_UP(pTargetSection->Misc.VirtualSize + totalSpace, 
        pNtHeaders->OptionalHeader.SectionAlignment);
    
    // 清理
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}

int main() {
    if (InjectImportTable("D:\\code\\c++\\1.exe", "D:\\code\\c++\\TestDll.dll", "mySub")) {
        printf("Import table injected successfully!\n");
    } else {
        printf("Injection failed!\n");
    }
    return 0;
}