#include "stdafx.h"

//=============================================================================================================================================
//		Hook used to catch the XB1 emulator load
//		Will toggle the Mem protection on/off to prevent the crash
//=============================================================================================================================================
#pragma region OGXFix
#define XBOX_XEX		"\\Device\\Harddisk0\\SystemPartition\\Compatibility"
#define DASH_XEX		"\\SystemRoot\\dash.xex"

#define LoaderPrep_Addr_6670	0x818DA950 // TitleLoaderPrepareLoadExecutableFile

#define LOADPREPSAVE_VAL	1
typedef DWORD(*LOADPREPSAVEFUN)(DWORD argR3, char* xex, DWORD argR5, PVOID handle, DWORD typeinfo, DWORD ver, DWORD argR9, DWORD argR10, DWORD argSt1);
VOID __declspec(naked) loadPrepSaveVar(VOID)
{
	__asm {
		li r3, LOADPREPSAVE_VAL
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
LOADPREPSAVEFUN loadPrepSave = (LOADPREPSAVEFUN)loadPrepSaveVar;

DWORD LoaderPrepHook(DWORD argR3, const char* xex, DWORD argR5, PVOID handle, DWORD typeinfo, DWORD ver, DWORD argR9, DWORD argR10, DWORD argSt1)
{
	char* xexname = (char*)xex;
	//DbgPrint("loadPrep r3: %08x r4:'%s' r5: %08x hand: %08x typ: %08x ver: %08x r9: %08x r10: %08x st1: %08x\n", argR3, xexname, argR5, handle, typeinfo, ver, argR9, argR10, argSt1);
	if (strncmp(xexname, XBOX_XEX, strlen(XBOX_XEX)) == 0)
	{
		//HvxSetState(SET_PROT_ON);
		HvxGetVersions(FREEBOOT_SYSCALL_KEY, SET_PROT_ON);
		g_Protection = PROTECT_ON;
		__dcbst(0, &g_Protection);
		__sync();
	}
	else if (strcmp(xex, DASH_XEX) == 0)
	{
		if (g_Protection)
		{
			//HvxSetState(SET_PROT_OFF);
			HvxGetVersions(FREEBOOT_SYSCALL_KEY, SET_PROT_OFF);
			g_Protection = PROTECT_OFF;
			__dcbst(0, &g_Protection);
			__sync();
		}
	}
	return loadPrepSave(argR3, xexname, argR5, handle, typeinfo, ver, argR9, argR10, argSt1);
}

VOID SetupLoaderPrepHook()
{

	//Byrom_Dbg("[HOOK] Applying LoaderPrep Hook...");
	cprintf("[BladesDL] [HOOK] Applying LoaderPrep Hook...");
	// using this to catch dash.xex and xbox emu loading
	hookFunctionStart((PDWORD)LoaderPrep_Addr_6670, (PDWORD)loadPrepSave, (DWORD)LoaderPrepHook);
}
#pragma endregion
//=============================================================================================================================================

//=============================================================================================================================================
//		LIVEBLOCK
//		NetDll_XNetDnsLookup Hook
//=============================================================================================================================================
#pragma region LiveBlock
#define NetDll_XNetDnsLookup_ORD 67
#define DNSLOOKUPSAVE_VAL	2
typedef DWORD(*DNSLOOKUPSAVEFUN)(XNCALLER_TYPE xnc, const char* pszHost, WSAEVENT hEvent, XNDNS** ppxndns);
VOID __declspec(naked) DnsLookupSaveVar(VOID)
{
	__asm {
		li r3, DNSLOOKUPSAVE_VAL
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
DNSLOOKUPSAVEFUN DnsLookupSave = (DNSLOOKUPSAVEFUN)DnsLookupSaveVar;

NTSTATUS DnsLookupHook(XNCALLER_TYPE xnc, const char* pszHost, WSAEVENT hEvent, XNDNS** ppxndns)
{
	const char* LiveBlockList[] = {
	"xemacs.xboxlive.com",
	"xeas.xboxlive.com",
	"xetgs.xboxlive.com",
	"xexds.xboxlive.com",
	"piflc.xboxlive.com",
	"siflc.xboxlive.com",
	"msac.xboxlive.com",
	"xlink.xboxlive.com",
	"xuacs.xboxlive.com",
	"sts.xboxlive.com",
	"xam.xboxlive.com",
	"notice.xbox.com",
	"macs.xbox.com",
	"rad.msn.com"
	};

	for (int i = 0; i < ARRAYSIZE(LiveBlockList); i++) {
		if (strcmpi(pszHost, LiveBlockList[i]) == 0)
		{
			cprintf("[BladesDL] [LIVEBLOCK] Lookup address %s is on our 'LiveBlock' block list!", LiveBlockList[i]);
			return DnsLookupSave(xnc, "live.block\0", hEvent, ppxndns);
		}

	}

	return DnsLookupSave(xnc, pszHost, hEvent, ppxndns);
}

VOID SetupDNSHook()
{
	cprintf("[BladesDL] [HOOK] Applying LiveBlock Hook...");
	hookFunctionStartOrd(MODULE_XAM, NetDll_XNetDnsLookup_ORD, (PDWORD)DnsLookupSave, (DWORD)DnsLookupHook);
}
#pragma endregion
//=============================================================================================================================================

//=============================================================================================================================================
//		SOCKPATCH
//		Always allows executables to use insecure sockets
//=============================================================================================================================================
#pragma region Sockpatch
#define XexCheckExecPriv_ORD	404 // 0x194
BOOL XamCheckExecPriv(DWORD priv)
{
	BOOL ret = XexCheckExecutablePrivilege(priv);

	if (priv == PRIV_INSECURE_SOCKS)
		ret = TRUE;

	return ret;
}

VOID SetupXamCheckExecPrivHook()
{
	cprintf("[BladesDL] [HOOK] Applying CheckExecPriv Hook...");
	hookImpStub(MODULE_XAM, MODULE_KERNEL, XexCheckExecPriv_ORD, (DWORD)XamCheckExecPriv);
}
#pragma endregion
//=============================================================================================================================================

//=============================================================================================================================================
//		FATALREBOOT
//		Reboot on crashes instead of freeze - UNTESTED
//=============================================================================================================================================
#pragma region FatalReboot
#define keBugCheckEx_ORD	83
#define KEBUGCHECKEXSAVE_VAL	3

typedef VOID(*KEBUGCHECKEXFUN)(DWORD r3, DWORD r4, DWORD r5, DWORD r6, DWORD r7);

#define HAL_HARD_REBOOT			2
#define HAL_SOFT_POWEROFF		5
#define HAL_SOFT_REBOOT			6 // many jtag's won't work with this one...

VOID __declspec(naked) keBugCheckExSaveVar(VOID)
{
	__asm {
		li r3, KEBUGCHECKEXSAVE_VAL
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
KEBUGCHECKEXFUN keBugCheckExSave = (KEBUGCHECKEXFUN)keBugCheckExSaveVar;
// OPT_FATAL_NOFREEZE bit is set when freeze is avoided
// OPT_FATAL_REBOOT when above is set, this will cause the box to reboot instead of shutoff
VOID keBugCheckExHook(DWORD r3, DWORD r4, DWORD r5, DWORD r6, DWORD r7)
{
	cprintf("\n*** Fatal System Error: 0x%08lx\n                       (0x%p,0x%p,0x%p,0x%p)\n\n", r3, r4, r5, r6, r7);
	//if (getOpt(OPT_FATAL_NOFREEZE))
	//{
	//	if (getOpt(OPT_FATAL_REBOOT))
	//		HalReturnToFirmware(HAL_HARD_REBOOT);
	//	else
	//		HalReturnToFirmware(HAL_SOFT_POWEROFF);
	//}
	//else
		//keBugCheckExSave(r3, r4, r5, r6, r7);
	HalReturnToFirmware(HAL_HARD_REBOOT);
}

VOID SetupkeBugCheckExHook()
{
	cprintf("[BladesDL] [HOOK] Applying FatalReboot Hook...");
	hookFunctionStartOrd(MODULE_KERNEL, keBugCheckEx_ORD, (PDWORD)keBugCheckExSave, (DWORD)keBugCheckExHook);
}
#pragma endregion
//=============================================================================================================================================