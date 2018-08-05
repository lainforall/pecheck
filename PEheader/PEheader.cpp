// PEheader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdint.h"

typedef uint8_t  BYTE;
typedef uint32_t DWORD;
typedef int32_t  LONG;
typedef uint16_t WORD;


#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
// Каталог импортируемых объектов
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
// Каталог ресурсов
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
// Каталог исключений
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
// Каталог безопасности
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
// Таблица переадресации
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
// Отладочный каталог
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
// Строки описания
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
// Машинный значения (MIPS GP)
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
// Каталог TLS (Thread local storage - локальная память потоков)
#define IMAGE_DIRECTORY_ENTRY_TLS            9
// Каталог конфигурации загрузки
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    11   
// таблица адресов импорта
#define IMAGE_DIRECTORY_ENTRY_IAT            12   
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   
// информация COM объектов
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_SIZEOF_SHORT_NAME 8


typedef struct _IMAGE_DOS_HEADER {

	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2p[10];
	DWORD e_lfanew;
} IMAGE_DOS_HEADER;



typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER;


typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;
	DWORD   AddressOfNames;
	DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;
		DWORD   OriginalFirstThunk;
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;
	DWORD   ForwarderChain;
	DWORD   Name;
	DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_NT_HEADERS {
	DWORD                 Signature;
	IMAGE_FILE_HEADER     FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
	} u1;
} IMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME;

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Need argument");
		return 1;
	}

	

    return 0;
}

