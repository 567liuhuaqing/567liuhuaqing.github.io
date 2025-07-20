#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
//char path[] = "D:\\code\\c++\\TestDll.dll";
char path[] = "D:\\code\\c++\\123.exe";
//char path[] = "C:\\Windows\\System32\\notepad.exe";
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);
DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
VOID DisplayExportTable();
VOID DisplayRelocTable();
VOID DisplayImportTable();
VOID DisplayBoundImportTable();
DWORD GetFunctionAddrByName(IN char* pFunctionName);
DWORD GetFunctionAddrByOrdinals(IN DWORD pFunctionOrdinals);
DWORD AlignUp(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}
bool isPE(IN LPVOID pFileBuffer){
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("Invalid MZ signature");
		free(pFileBuffer);
		return false;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((BYTE*)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("Invalid PE signature");
		free(pFileBuffer);
		return false;
	}
	return true;
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

DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva) {
    if (pFileBuffer == NULL) {
        return 0;
    }
    PIMAGE_DOS_HEADER pDos = NULL;
    PIMAGE_NT_HEADERS pNT = NULL;
    PIMAGE_FILE_HEADER pPE = NULL;
    PIMAGE_SECTION_HEADER pSec = NULL;
    pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    pNT = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDos->e_lfanew);
    if (pNT->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    if (dwRva < pNT->OptionalHeader.SizeOfHeaders) {
        return dwRva;
    }
    pPE = &pNT->FileHeader;
    if (pNT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOpt = (PIMAGE_OPTIONAL_HEADER64)&pNT->OptionalHeader;
    	pSec = (PIMAGE_SECTION_HEADER)((BYTE*)pOpt + pPE->SizeOfOptionalHeader);
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOpt = (PIMAGE_OPTIONAL_HEADER32)&pNT->OptionalHeader;
    	pSec = (PIMAGE_SECTION_HEADER)((BYTE*)pOpt + pPE->SizeOfOptionalHeader);
	}
    WORD numSec = pPE->NumberOfSections;
    for (WORD i = 0; i < numSec; i++) {
        DWORD dwVA = pSec->VirtualAddress;
        DWORD dwVS = pSec->Misc.VirtualSize;
        if (dwRva >= dwVA && dwRva < (dwVA + dwVS)) {
            // 公式：FOA = RVA - 节区虚拟地址 + 节区文件偏移
            DWORD dwFoa = (dwRva - dwVA) + pSec->PointerToRawData;
            return dwFoa;
        }
        pSec++;
    }
    return 0;
}

VOID DisplayExportTable(){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return ;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[0].VirtualAddress);	//定位导出表
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pFileBuffer + dwFOA);
	if(pExportDirectory->Name == NULL || pExportDirectory->NumberOfFunctions == 0){
		printf("ExportDirectory is NULL\n");
		return ;
	}
	printf("***************ExportDirectory***************\n");
	printf("导出表RVA:0x%x\n", pDataDirectory[0].VirtualAddress);
	printf("导出表大小:0x%x字节\n", pDataDirectory[0].Size);
	printf("导出表FOA：0x%x\n", dwFOA);
	printf("TimeDataStamp(经加密):0x%x\n", pExportDirectory->TimeDateStamp);
	printf("Name(导出表文件名字符串):%s\n", (BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->Name));
	printf("Base(函数起始序号)：%d\n", pExportDirectory->Base);
	printf("NumberOfFunction(导出函数总数):0x%x\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames(以名称导出函数的总数)：0x%x\n", pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions(导出函数地址表RVA)：0x%x\n", pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames(导出函数名称表RVA)：0x%x\n", pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals(导出函数序号表RVA)：0x%x\n", pExportDirectory->AddressOfNameOrdinals);
	printf("-------AddressOfFunctions-------\n");
	int i = 0;
	PDWORD AddressOfFunction = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfFunctions));
	for(i = 0; i < pExportDirectory->NumberOfFunctions; i++){
		dwFOA = (DWORD)(RvaToFoa(pFileBuffer, *AddressOfFunction));
		printf("下标:%d\t函数地址RVA:0x%x\tFOA:0x%x\n", i, *(AddressOfFunction), dwFOA);
		AddressOfFunction++;
	}
	printf("-------NameOfFunctions-------\n");
	PDWORD AddressOfNames = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNames));
	for(i = 0; i < pExportDirectory->NumberOfNames; i++){
		char* name = (char*)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, *AddressOfNames));
		printf("下标:%d\t函数名称：%s\t\t名称RVA:0x%x\n", i, name, *AddressOfNames);
		AddressOfNames++;
	}
	printf("-------OrdinalsOfFunctions-------\n");
	PWORD AddressOfNameOrdinals = (PWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals));
	for(i = 0; i < pExportDirectory->NumberOfNames; i++){
		printf("下标:%d\t函数序号(加Base)：%d\n", i, *AddressOfNameOrdinals + pExportDirectory->Base);
		AddressOfNameOrdinals++;
	}
}

DWORD GetFunctionAddrByName(IN char* pFunctionName){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return -1;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return -1;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[0].VirtualAddress);	//定位导出表
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pFileBuffer + dwFOA);
	if(pExportDirectory->Name == NULL || pExportDirectory->NumberOfFunctions == 0){
		printf("ExportDirectory is NULL\n");
		return -1;
	}
	DWORD i, idx, f = 1;
	PDWORD AddressOfNames = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNames));
	for(i = 0; i < pExportDirectory->NumberOfNames; i++){
		char* name = (char*)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, *AddressOfNames));
		if(!strcmp(name, pFunctionName)){
			f = 0; break;
		}
		AddressOfNames++;
	}
	if(f){
		printf("Notfound addr by name\n");
		return -1;
	}
	PWORD AddressOfNameOrdinals = (PWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals));
	idx = AddressOfNameOrdinals[i];	//名称下标对应函数序号（真正导出序号 = idx + Base）
	PDWORD AddressOfFunction = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfFunctions));
	return AddressOfFunction[idx];
}

DWORD GetFunctionAddrByOrdinals(IN DWORD pFunctionOrdinals){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return -1;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return -1;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[0].VirtualAddress);	//定位导出表
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pFileBuffer + dwFOA);
	if(pExportDirectory->Name == NULL || pExportDirectory->NumberOfFunctions == 0){
		printf("ExportDirectory is NULL\n");
		return -1;
	}
	PDWORD AddressOfFunction = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfFunctions));
	if(pFunctionOrdinals - pExportDirectory->Base >= pExportDirectory->NumberOfFunctions){
		printf("The ordinals is wrong");
		return -1;
	}
	return AddressOfFunction[pFunctionOrdinals - pExportDirectory->Base];
}

VOID DisplayRelocTable(){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PWORD pRelocData = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_BASE_RELOCATION pRelocTable = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return ;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[5].VirtualAddress);	//定位重定位表
	pRelocTable = (PIMAGE_BASE_RELOCATION)((BYTE*)pFileBuffer + dwFOA);
	printf("***************BaseRelocation***************\n");
	int i=1;
	while (pRelocTable->VirtualAddress != 0 && pRelocTable->SizeOfBlock != 0){	//遍历重定位表
		printf("RelocTable[%d]\tRVA:%0X, Size:%0X\n", i, pRelocTable->VirtualAddress, pRelocTable->SizeOfBlock);
		DWORD dwItems = ((pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2);
		printf("项目数:%X h / %d d\r\n", dwItems, dwItems);
		pRelocData = (PWORD)((BYTE*)pRelocTable + 0x8);
		for (int i = 0; i < dwItems; i++ ){
			if (*(pRelocData + i) >> 12 == IMAGE_REL_BASED_HIGHLOW){	//IMAGE_REL_BASED_HIGHLOW = 3
				DWORD dwRva = ((*(pRelocData + i) & 0x0fff) + pRelocTable->VirtualAddress);
				DWORD dwFoa = RvaToFoa(pFileBuffer, dwRva);
				DWORD dwFarCall = *(DWORD*)(pFileBuffer + dwFoa);
				printf("RVA:0x%X\tFOA:0x%X\tFarCall:0x%X\t(HIGHLOW)\n", dwRva, dwFoa, dwFarCall);	//需要重定位的函数
			}else{
				printf("-(ABSLUTE)\r\n");	//类型非3的提示
			}
		}
		pRelocTable = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocTable + pRelocTable->SizeOfBlock);
		i++;
	}
}

VOID DisplayImportTable(){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PWORD pRelocData = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return ;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[1].VirtualAddress);	//定位导入表
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pFileBuffer + dwFOA);
	printf("***************ImportDescriptor***************\n");
	while(!(pImportDescriptor->FirstThunk == 0 && pImportDescriptor->OriginalFirstThunk == 0)){	//遍历导入表
		printf("***%s***\n", (PBYTE)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pImportDescriptor->Name)));
		printf("-------OriginalFirstThunk-------\n");
		PDWORD pOriginalFirstThunk = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pImportDescriptor->OriginalFirstThunk));
		printf("%x - %x\n", pOriginalFirstThunk, *pOriginalFirstThunk);
		printf("TimeDateStamp: %x\n", pImportDescriptor->TimeDateStamp);
		while(*pOriginalFirstThunk){	//遍历INT表
			if(*pOriginalFirstThunk & IMAGE_ORDINAL_FLAG32){	//IMAGE_ORDINAL_FLAG32 = 0x80000000
				printf("按序号导入：%x\n", (*pOriginalFirstThunk)&0x0FFFF);
			}else{
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, *pOriginalFirstThunk));
				printf("按名称导入Hint-Name: %x-%s\n", pImageByName->Hint, pImageByName->Name);
			}
			//pOriginalFirstThunk = (PDWORD)((BYTE*)pOriginalFirstThunk + sizeof(IMAGE_THUNK_DATA32));
			pOriginalFirstThunk++;
		}
		printf("-------FirstThunk-------\n");
		PDWORD pFirstThunk = (PDWORD)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, pImportDescriptor->FirstThunk));
		printf("%x - %x\n", pFirstThunk, *pFirstThunk);
		while(*pFirstThunk){
			if(*pFirstThunk & IMAGE_ORDINAL_FLAG32){	//IMAGE_ORDINAL_FLAG32 = 0x80000000
				printf("按序号导入：%x\n", (*pFirstThunk)&0x0FFFF);
			}else{
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, *pFirstThunk));
				printf("按名称导入Hint-Name: %x-%s\n", pImageByName->Hint, pImageByName->Name);
			}
			//pFirstThunk = (PDWORD)((BYTE*)pFirstThunk + sizeof(IMAGE_THUNK_DATA32));
			pFirstThunk++;
		}
		pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	free(pFileBuffer);
}

VOID DisplayBoundImportTable(){
	DWORD dwSize = 0;
	DWORD dwFOA = 0;
	DWORD dwSizeOfDirectory = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL; 
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;
	PIMAGE_BOUND_FORWARDER_REF pBoundImportRef = NULL;
	dwSize = ReadPEFile(path, &pFileBuffer);
	if(dwSize == 0 || !pFileBuffer){
		printf("Fail to read file\n");
		return ;
	}
	if(!isPE(pFileBuffer)){
		printf("Is not PE file!\n");
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    	PIMAGE_OPTIONAL_HEADER64 pOptionHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	} else {
    	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
    	dwSizeOfDirectory = pOptionHeader->NumberOfRvaAndSizes;
		pDataDirectory = pOptionHeader->DataDirectory;
	}
	dwFOA = RvaToFoa(pFileBuffer, pDataDirectory[11].VirtualAddress);	//定位绑定导入表
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE*)pFileBuffer + dwFOA);
	auto dwNameBase = (DWORD_PTR)pBoundImportDescriptor;
	printf("***************BoundImportDescriptor***************\n");
	while(pBoundImportDescriptor->OffsetModuleName != 0){
		printf("TimeDateStamp: %x\n", pBoundImportDescriptor->TimeDateStamp);
		printf("OffsetModuleName: %s\n", (char*)((BYTE*)pFileBuffer + RvaToFoa(pFileBuffer, dwNameBase + pBoundImportDescriptor->OffsetModuleName)));
		printf("NumberOfModuleForwarderRefs: %x\n", pBoundImportDescriptor->NumberOfModuleForwarderRefs);
		DWORD temp = pBoundImportDescriptor->NumberOfModuleForwarderRefs;
		while(temp--){
			printf("--------------Ref--------------\n");
			pBoundImportRef = (PIMAGE_BOUND_FORWARDER_REF)((BYTE*)pBoundImportDescriptor + 8);
			pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE*)pBoundImportDescriptor + 8);
			printf("	TimeDateStamp: %x\n", pBoundImportDescriptor->TimeDateStamp);
			printf("	OffsetModuleName: %s\n", dwNameBase + pBoundImportDescriptor->OffsetModuleName);
		}
		pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE*)pBoundImportDescriptor + 8);
	}
	free(pFileBuffer);
}

BOOL AddNewSection(LPVOID* ppFileBuffer, DWORD* pFileSize, const char* sectionName, DWORD sectionSize, DWORD* pNewSectionFOA, DWORD* pNewSectionRVA) {
    BYTE* pFileBuffer = (BYTE*)*ppFileBuffer;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
    
    // 获取可选头指针
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNTHeader->OptionalHeader;
    DWORD SectionAlignment = pOptHeader->SectionAlignment;
    DWORD FileAlignment = pOptHeader->FileAlignment;
    
    // 计算新节位置
    DWORD lastSectionIndex = pNTHeader->FileHeader.NumberOfSections - 1;
    PIMAGE_SECTION_HEADER pLastSection = &pSectionHeader[lastSectionIndex];
    
    // 计算新节的RVA和FOA
    DWORD newSectionRVA = AlignUp(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, SectionAlignment);
    DWORD newSectionFOA = AlignUp(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, FileAlignment);
    
    // 计算新节大小（对齐后）
    DWORD newSectionSizeAligned = AlignUp(sectionSize, FileAlignment);
    DWORD newSectionVSizeAligned = AlignUp(sectionSize, SectionAlignment);
    
    // 计算新的SizeOfImage
    DWORD newSizeOfImage = AlignUp(newSectionRVA + newSectionVSizeAligned, SectionAlignment);
    
    // 检查是否需要扩展内存
    DWORD newFileSize = newSectionFOA + newSectionSizeAligned;
    if (newFileSize > *pFileSize) {
        BYTE* pNewBuffer = (BYTE*)realloc(pFileBuffer, newFileSize);
        if (!pNewBuffer) return FALSE;
        
        // 初始化新内存为零
        memset(pNewBuffer + *pFileSize, 0, newFileSize - *pFileSize);
        
        *ppFileBuffer = pNewBuffer;
        *pFileSize = newFileSize;
        pFileBuffer = pNewBuffer;
        
        // 重新获取指针
        pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
        pNTHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHeader->e_lfanew);
        pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
        pLastSection = &pSectionHeader[lastSectionIndex];
        pOptHeader = &pNTHeader->OptionalHeader;
    }
    
    // 更新NT头中的节数
    pNTHeader->FileHeader.NumberOfSections++;
    
    // 设置新节表头
    PIMAGE_SECTION_HEADER pNewSection = &pSectionHeader[lastSectionIndex + 1];
    memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
    
    // 设置节名（确保不超过8字节）
    strncpy((char*)pNewSection->Name, sectionName, 8);
    
    // 设置节属性
    pNewSection->Misc.VirtualSize = sectionSize;
    pNewSection->VirtualAddress = newSectionRVA;
    pNewSection->SizeOfRawData = newSectionSizeAligned;
    pNewSection->PointerToRawData = newSectionFOA;
    pNewSection->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | 
                                 IMAGE_SCN_MEM_READ | 
                                 IMAGE_SCN_MEM_WRITE;
    
    // 更新可选头
    pOptHeader->SizeOfImage = newSizeOfImage;
    
    // 返回新节信息
    *pNewSectionFOA = newSectionFOA;
    *pNewSectionRVA = newSectionRVA;
    
    return TRUE;
}

/*
// 移动导出表函数
BOOL MoveExportTable(LPVOID* ppFileBuffer, DWORD* pFileSize) {
    BYTE* pFileBuffer = (BYTE*)*ppFileBuffer;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHeader->e_lfanew);
    
    // 获取导出表目录
    PIMAGE_DATA_DIRECTORY pExportDirEntry = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pExportDirEntry->VirtualAddress == 0 || pExportDirEntry->Size == 0) {
        printf("No export table found\n");
        return FALSE;
    }
    
    // 定位导出表
    DWORD expFoa = RvaToFoa(pFileBuffer, pExportDirEntry->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pFileBuffer + expFoa);
    
    // 计算导出表各部分的大小
    DWORD totalSize = sizeof(IMAGE_EXPORT_DIRECTORY);
    totalSize += pExportDir->NumberOfFunctions * sizeof(DWORD);  // AddressOfFunctions
    totalSize += pExportDir->NumberOfNames * sizeof(DWORD);      // AddressOfNames
    totalSize += pExportDir->NumberOfNames * sizeof(WORD);       // AddressOfNameOrdinals
    
    // 计算所有函数名的总大小
    PDWORD pAddressOfNames = (PDWORD)(pFileBuffer + RvaToFoa(pFileBuffer, pExportDir->AddressOfNames));
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD nameRva = pAddressOfNames[i];
        DWORD nameFoa = RvaToFoa(pFileBuffer, nameRva);
        totalSize += (DWORD)strlen((char*)(pFileBuffer + nameFoa)) + 1;
    }
    
    // 添加新节
    DWORD newSectionFOA, newSectionRVA;
    if (!AddNewSection(ppFileBuffer, pFileSize, ".edata", totalSize, &newSectionFOA, &newSectionRVA)) {
        printf("Failed to add new section for export table\n");
        return FALSE;
    }
    
    pFileBuffer = (BYTE*)*ppFileBuffer; // 重新获取指针
    
    // 新节中的当前位置
    DWORD currentOffset = newSectionFOA;
    
    // 1. 复制IMAGE_EXPORT_DIRECTORY
    PIMAGE_EXPORT_DIRECTORY pNewExportDir = (PIMAGE_EXPORT_DIRECTORY)(pFileBuffer + currentOffset);
    memcpy(pNewExportDir, pExportDir, sizeof(IMAGE_EXPORT_DIRECTORY));
    currentOffset += sizeof(IMAGE_EXPORT_DIRECTORY);
    
    // 2. 复制AddressOfFunctions数组
    PDWORD pOldAddressOfFunctions = (PDWORD)(pFileBuffer + RvaToFoa(pFileBuffer, pExportDir->AddressOfFunctions));
    PDWORD pNewAddressOfFunctions = (PDWORD)(pFileBuffer + currentOffset);
    DWORD newAddressOfFunctionsRVA = currentOffset - newSectionFOA + newSectionRVA;
    
    memcpy(pNewAddressOfFunctions, pOldAddressOfFunctions, pExportDir->NumberOfFunctions * sizeof(DWORD));
    currentOffset += pExportDir->NumberOfFunctions * sizeof(DWORD);
    
    // 3. 复制AddressOfNameOrdinals数组
    PWORD pOldAddressOfNameOrdinals = (PWORD)(pFileBuffer + RvaToFoa(pFileBuffer, pExportDir->AddressOfNameOrdinals));
    PWORD pNewAddressOfNameOrdinals = (PWORD)(pFileBuffer + currentOffset);
    DWORD newAddressOfNameOrdinalsRVA = currentOffset - newSectionFOA + newSectionRVA;
    
    memcpy(pNewAddressOfNameOrdinals, pOldAddressOfNameOrdinals, pExportDir->NumberOfNames * sizeof(WORD));
    currentOffset += pExportDir->NumberOfNames * sizeof(WORD);
    
    // 4. 复制AddressOfNames数组和函数名字符串
    PDWORD pNewAddressOfNames = (PDWORD)(pFileBuffer + currentOffset);
    DWORD newAddressOfNamesRVA = currentOffset - newSectionFOA + newSectionRVA;
    currentOffset += pExportDir->NumberOfNames * sizeof(DWORD);
    
    // 复制函数名字符串并更新AddressOfNames数组
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD oldNameRva = pAddressOfNames[i];
        DWORD oldNameFoa = RvaToFoa(pFileBuffer, oldNameRva);
        char* pOldName = (char*)(pFileBuffer + oldNameFoa);
        
        // 复制字符串
        DWORD nameLen = (DWORD)strlen(pOldName) + 1;
        char* pNewName = (char*)(pFileBuffer + currentOffset);
        strcpy(pNewName, pOldName);
        
        // 更新AddressOfNames条目
        pNewAddressOfNames[i] = currentOffset - newSectionFOA + newSectionRVA;
        
        currentOffset += nameLen;
    }
    
    // 5. 更新导出目录中的指针
    pNewExportDir->AddressOfFunctions = newAddressOfFunctionsRVA;
    pNewExportDir->AddressOfNames = newAddressOfNamesRVA;
    pNewExportDir->AddressOfNameOrdinals = newAddressOfNameOrdinalsRVA;
    
    // 6. 更新数据目录
    pExportDirEntry->VirtualAddress = newSectionRVA;
    // 大小保持不变
    
    return TRUE;
}

// 移动重定位表函数
BOOL MoveRelocationTable(LPVOID* ppFileBuffer, DWORD* pFileSize) {
    BYTE* pFileBuffer = (BYTE*)*ppFileBuffer;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHeader->e_lfanew);
    
    // 获取重定位表目录
    PIMAGE_DATA_DIRECTORY pRelocDirEntry = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDirEntry->VirtualAddress == 0 || pRelocDirEntry->Size == 0) {
        printf("No relocation table found\n");
        return FALSE;
    }
    
    // 添加新节
    DWORD newSectionFOA, newSectionRVA;
    if (!AddNewSection(ppFileBuffer, pFileSize, ".reloc", pRelocDirEntry->Size, &newSectionFOA, &newSectionRVA)) {
        printf("Failed to add new section for relocation table\n");
        return FALSE;
    }
    
    pFileBuffer = (BYTE*)*ppFileBuffer; // 重新获取指针
    
    // 定位原始重定位表
    DWORD relocFoa = RvaToFoa(pFileBuffer, pRelocDirEntry->VirtualAddress);
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pFileBuffer + relocFoa);
    
    // 复制整个重定位表到新位置
    memcpy(pFileBuffer + newSectionFOA, pReloc, pRelocDirEntry->Size);
    
    // 更新数据目录
    pRelocDirEntry->VirtualAddress = newSectionRVA;
    // 大小保持不变
    
    return TRUE;
}

// 保存到新文件
void SaveToNewFile(BYTE* pFileBuffer, DWORD fileSize, const char* filename) {
    FILE* pFile = fopen(filename, "wb");
    if (!pFile) {
        printf("Failed to create file: %s\n", filename);
        return;
    }
    
    fwrite(pFileBuffer, 1, fileSize, pFile);
    fclose(pFile);
    printf("File saved as %s\n", filename);
}

// 示例使用
int main() {
    const char* inputFile = "input.dll";
    const char* outputFile = "a.exe";
    
    // 读取原始文件
    DWORD fileSize = 0;
    BYTE* pFileBuffer = NULL;
    fileSize = ReadPEFile(inputFile, &pFileBuffer); // 假设已实现此函数
    
    if (fileSize == 0 || !pFileBuffer) {
        printf("Failed to read file: %s\n", inputFile);
        return 1;
    }
    
    // 移动导出表
    if (!MoveExportTable((LPVOID*)&pFileBuffer, &fileSize)) {
        printf("Failed to move export table\n");
    } else {
        printf("Export table moved successfully\n");
    }
    
    // 移动重定位表
    if (!MoveRelocationTable((LPVOID*)&pFileBuffer, &fileSize)) {
        printf("Failed to move relocation table\n");
    } else {
        printf("Relocation table moved successfully\n");
    }
    
    // 保存到新文件
    SaveToNewFile(pFileBuffer, fileSize, outputFile);
    
    // 清理
    free(pFileBuffer);
    return 0;
}*/

int main() {
	//DisplayExportTable();
	//DWORD funAddr = GetFunctionAddrByName("mySub");
    DWORD funAddr = -1;
    //funAddr = GetFunctionAddrByOrdinals(1);
    if(funAddr != -1){
    	printf("The function RVA is 0x%x\n", funAddr);
    }
	DisplayRelocTable();
    //DisplayImportTable();
    //DisplayBoundImportTable();
    

    return 0;
}