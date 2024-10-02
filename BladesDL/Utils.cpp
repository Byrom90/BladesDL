#include "stdafx.h"

HANDLE dllHandle = NULL;
DWORD g_Protection = PROTECT_OFF; // 1 = on, 0 = off

QWORD __declspec(naked) HvxGetVersions(DWORD magic, DWORD mode, UINT64 dest, UINT64 src, UINT32 len, UINT64 arg_r8)
{
	__asm
	{
		li r0, 0 // HvxGetVersion
		sc
		blr
	}
}

#define SYS_STRING "\\System??\\%s"
#define USR_STRING "\\??\\%s"


HRESULT doMountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both)
{
	HRESULT res;
	if (both)
	{
		res = doMountPath(szDrive, szDevice, SYS_STRING);
		res = doMountPath(szDrive, szDevice, USR_STRING);
	}
	else
	{
		if (KeGetCurrentProcessType() == SYSTEM_PROC)
			res = doMountPath(szDrive, szDevice, SYS_STRING);
		else
			res = doMountPath(szDrive, szDevice, USR_STRING);
	}
	return res;
}

PIMAGE_EXPORT_ADDRESS_TABLE getModuleEat(char* modName)
{
	PLDR_DATA_TABLE_ENTRY moduleHandle = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modName);
	if (moduleHandle != NULL)
	{
		DWORD ret;
		PIMAGE_XEX_HEADER xhead = (PIMAGE_XEX_HEADER)moduleHandle->XexHeaderBase;
		ret = (DWORD)RtlImageXexHeaderField(xhead, 0xE10402);
		if (ret == 0)
		{
			return xhead->SecurityInfo->ExportTableAddress;
		}
	}
	return NULL;
}

DWORD resolveFunct(PCHAR modname, DWORD ord)
{
	DWORD ptr2 = 0;
	HANDLE hand;
	if (NT_SUCCESS(XexGetModuleHandle(modname, &hand)))
		XexGetProcedureAddress(hand, ord, &ptr2);
	return ptr2; // function not found
}

// this is how xam does it...
BOOL fileExists(PCHAR path)
{
	OBJECT_ATTRIBUTES obAtrib;
	FILE_NETWORK_OPEN_INFORMATION netInfo;
	STRING filePath;
	RtlInitAnsiString(&filePath, path); //  = 0x10
	InitializeObjectAttributes(&obAtrib, &filePath, 0x40, NULL);
	if (path[0] != '\\')
		obAtrib.RootDirectory = (HANDLE)0xFFFFFFFD;
	if (NT_SUCCESS(NtQueryFullAttributesFile(&obAtrib, &netInfo)))
	{
		// filter out directories from the result
		if ((netInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
			return TRUE;
	}
	return FALSE;
}

// this one was fixed to allow busy files to be detected as existing
//BOOL fileExists(PCHAR path)
//{
//	HANDLE = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//	if(file == INVALID_HANDLE_VALUE)
//	{
//		if(GetLastError() != 5) // inaccessible means it exists but is probably open somewhere else
//			return FALSE;
//	}
//	CloseHandle(file);
//	return TRUE;
//}

VOID patchInJump(PDWORD addr, DWORD dest, BOOL linked)
{
	if (dest & 0x8000) // If bit 16 is 1
		addr[0] = 0x3D600000 + (((dest >> 16) & 0xFFFF) + 1); // lis %r11, dest>>16 + 1
	else
		addr[0] = 0x3D600000 + ((dest >> 16) & 0xFFFF); // lis %r11, dest>>16

	addr[1] = 0x396B0000 + (dest & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
	addr[2] = 0x7D6903A6; // mtctr %r11

	if (linked)
		addr[3] = 0x4E800421; // bctrl
	else
		addr[3] = 0x4E800420; // bctr
	/*
	__dcbst(0, addr);
	__sync();
	__isync();
	*/
	doSync(addr);
}

DWORD hookExportOrd(char* modName, DWORD ord, DWORD dstFun)
{
	PIMAGE_EXPORT_ADDRESS_TABLE expbase = getModuleEat(modName);
	if (expbase != NULL)
	{
		DWORD modOffset = (expbase->ImageBaseAddress) << 16;
		DWORD origOffset = (expbase->ordOffset[ord - 1]) + modOffset;
		expbase->ordOffset[ord - 1] = dstFun - modOffset;
		/*
		__dcbst(0, &expbase->ordOffset[ord - 1]);
		__sync();
		__isync();
		*/
		doSync(&expbase->ordOffset[ord - 1]);
		return origOffset;
	}
	return 0;
}

BOOL hookImpStub(char* modname, char* impmodname, DWORD ord, DWORD patchAddr)
{
	DWORD orgAddr;
	PLDR_DATA_TABLE_ENTRY ldat;
	int i, j;
	BOOL ret = FALSE;
	// get the address of the actual function that is jumped to
	orgAddr = resolveFunct(impmodname, ord);
	if (orgAddr != 0)
	{
		// find where kmod info is stowed
		ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modname);
		if (ldat != NULL)
		{
			// use kmod info to find xex header in memory
			PXEX_IMPORT_DESCRIPTOR imps = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(ldat->XexHeaderBase, 0x000103FF);
			if (imps != NULL)
			{
				char* impName = (char*)(imps + 1);
				PXEX_IMPORT_TABLE impTbl = (PXEX_IMPORT_TABLE)(impName + imps->NameTableSize);
				for (i = 0; i < (int)(imps->ModuleCount); i++)
				{
					// use import descriptor strings to refine table
					for (j = 0; j < impTbl->ImportCount; j++)
					{
						PDWORD add = (PDWORD)impTbl->ImportStubAddr[j];
						if (add[0] == orgAddr)
						{
							//DbgPrint("%s %s tbl %d has ord %x at tstub %d location %08x\n", modname, impName, i, ord, j, impTbl->ImportStubAddr[j+1]);
							patchInJump((PDWORD)(impTbl->ImportStubAddr[j + 1]), patchAddr, FALSE);
							j = impTbl->ImportCount;
							ret = TRUE;
						}
					}
					impTbl = (PXEX_IMPORT_TABLE)((BYTE*)impTbl + impTbl->TableSize);
					impName = impName + strlen(impName);
					while ((impName[0] & 0xFF) == 0x0)
						impName++;
				}
			}
			//else DbgPrint("could not find import descriptor for mod %s\n", modname);
		}
		//else DbgPrint("could not find data table for mod %s\n", modname);
	}
	//else DbgPrint("could not find ordinal %d in mod %s\n", ord, impmodname);

	return ret;
}

BYTE* getModBaseSize(char* modName, PDWORD size)
{
	PLDR_DATA_TABLE_ENTRY ldat;
	ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modName);
	if (ldat != NULL)
	{
		if (ldat->EntryPoint > ldat->ImageBase)
			size[0] = ((DWORD)ldat->EntryPoint - (DWORD)ldat->ImageBase);
		else
			size[0] = ldat->SizeOfFullImage;
		return (BYTE*)ldat->ImageBase;
	}
	return NULL;
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr)
{
	DWORD inst = 0, repl;
	int i;
	PDWORD saver = (PDWORD)GLPR_FUN;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if (offset & 0x2000000)
		offset = offset | 0xFC000000;
	//DbgPrint("frame save offset: %08x\n", offset);
	repl = orgAddr[offset / 4];
	//DbgPrint("replacing %08x\n", repl);
	for (i = 0; i < 20; i++)
	{
		if (repl == saver[i])
		{
			int newOffset = (int)&saver[i] - (int)saveStubAddr;
			inst = 0x48000001 | (newOffset & 0x3FFFFFC);
			//DbgPrint("saver addr: %08x savestubaddr: %08x\n", &saver[i], saveStubAddr);
		}
	}
	//DbgPrint("new instruction: %08x\n", inst);
	return inst;
}

VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest)
{
	if ((saveStub != NULL) && (addr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
		//DbgPrint("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
		// build the stub
		// make a jump to go to the original function start+4 instructions
		if (addrReloc & 0x8000) // If bit 16 is 1
			saveStub[0] = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1); // lis %r11, dest>>16 + 1
		else
			saveStub[0] = 0x3D600000 + ((addrReloc >> 16) & 0xFFFF); // lis %r11, dest>>16

		saveStub[1] = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		saveStub[2] = 0x7D6903A6; // mtctr %r11
		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for (i = 0; i < 4; i++)
		{
			if ((addr[i] & 0x48000003) == 0x48000001) // branch with link
			{
				//DbgPrint("relink %08x\n", addr[i]);
				saveStub[i + 3] = relinkGPLR((addr[i] & ~0x48000003), &saveStub[i + 3], &addr[i]);
			}
			else
			{
				//DbgPrint("copy %08x\n", addr[i]);
				saveStub[i + 3] = addr[i];
			}
		}
		saveStub[7] = 0x4E800420; // bctr
		/*
		__dcbst(0, saveStub);
		__sync();
		__isync();
		*/
		doSync(saveStub);

		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//	DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		patchInJump(addr, dest, FALSE);
	}
}

PDWORD hookFunctionStartOrd(char* modName, DWORD ord, PDWORD saveStub, DWORD dest)
{
	PDWORD addr = (PDWORD)resolveFunct(modName, ord);
	if (addr != NULL)
		hookFunctionStart(addr, saveStub, dest);
	return addr;
}


void MakeBranchTo(int Address, int Dest)
{
	*(int*)Address = ((Dest - Address) & 0x03FFFFFC) | 0x48000000;
}

//=============================================================================================================================================
//		UART PRINTING
//		Prints will be sent directly to uart
//=============================================================================================================================================
#pragma region UART_Print
DWORD g_spinvar;
DWORD g_oldIrql;

char xtoa(unsigned char inp)
{
	char ret;
	if (inp < 0xa) // 0-9 = 0x30-0x39 
		ret = inp + 0x30;
	else		// 0xa-f = 0x61-66
		ret = inp + 0x57;
	return ret;
}

void makeString(char* dest, void* inpt, unsigned long len, unsigned long maxlen)
{
	unsigned char* inp = (unsigned char*)inpt;
	unsigned long i, j = 0, k = 0;

	if (inp != NULL)
	{
		for (i = 0; i < len; i++)
		{
			dest[j] = xtoa((inp[i] & 0xF0) >> 4) & 0xFF;
			j++;
			dest[j] = xtoa(inp[i] & 0xF) & 0xFF;
			j++;
			k++;
			if (k == 4)
			{
				dest[j] = ' ';
				j++;
				k = 0;
			}
			if (j >= maxlen - 3)
				i = len;
		}
	}
	else
	{
		dest[j] = '!';
		j++;
	}
	dest[j] = 0;
}

#pragma warning(push)
#pragma warning(disable: 4100) // unreferenced formal param
#pragma warning(disable: 4996) // _s not used warning

void __declspec(naked) cygPut(char ch)
{
	__asm
	{
		// Function prologue. Set up a stack frame and
		// preserve r31, and the link register;
		mflr    r12
		stw     r12, -8(r1)
		std     r31, -0x10(r1)
		stwu    r1, -0x18(r1)
		//// Preserve r3 and r4 so their values aren't lost by
		//// the function call.
		mr      r31, r4

		lis 	r4, 0x7fea
		slwi 	r3, r3, 24
		stw 	r3, 0x1014(r4)
		waiter:
		lwz 	r3, 0x1018(r4)
			rlwinm.r3, r3, 0, 6, 6
			beq 	waiter

			// Function epilogue. Tear down the stack frame and
			// restore r30, r31, and the link register.
			mr      r4, r31
			addi    r1, r1, 0x18
			lwz     r12, -8(r1)
			mtlr    r12
			ld      r31, -10h(r1)
			blr
	}
}

void cprintf(const char* s, ...)
{
	//size_t Size = strlen(s);
	va_list argp;
	int i, j;
	char temp[512];
	BYTE irql;

	//char* temp = new char[Size + 1];  // +1 you probably want zero-termination

	va_start(argp, s);
	vsnprintf(temp, 512, s, argp);
	//vsnprintf(temp, Size + 1, s, argp);
	va_end(argp);

	irql = KfAcquireSpinLock(&g_spinvar);

	j = strlen(temp);
	//j = Size;
	for (i = 0; i < j; i++)
	{
		if (temp[i] == 0)
			break;
		else
			cygPut(temp[i]);
	}
	cygPut(0x0D);
	cygPut(0x0A);


	//delete[] temp;
	KfReleaseSpinLock(&g_spinvar, irql);
	//Sleep(20);
}

#pragma warning(pop)
#pragma endregion
//=============================================================================================================================================









