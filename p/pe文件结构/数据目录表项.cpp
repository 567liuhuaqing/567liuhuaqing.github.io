#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
char path[] = "D:\\code\\c++\\1.exe";
//char path[] = "D:\\code\\c++\\abc.exe";
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

int main() {
	//DisplayExportTable();
	//DWORD funAddr = GetFunctionAddrByName("mySub");
    DWORD funAddr = -1;
    //funAddr = GetFunctionAddrByOrdinals(1);
    if(funAddr != -1){
    	printf("The function RVA is 0x%x\n", funAddr);
    }
	//DisplayRelocTable();
    DisplayImportTable();
    //DisplayBoundImportTable();
    

    return 0;
}