#pragma once
#include "stdafx.h"

#ifndef _UTILS_H
#define _UTILS_H

extern HANDLE dllHandle;

#define MODULE_KERNEL	"xboxkrnl.exe"
#define MODULE_XAM		"xam.xex"

//=============================================================================================================================================
//		Toggle Memory Protection Patch
//		(XB1 Backwards Compatibility Fix)
//=============================================================================================================================================
#define FREEBOOT_SYSCALL_KEY	0x72627472 
// values to send when toggling
#define PROTECT_OFF		0
#define PROTECT_ON		1
// track the current status by setting this value
extern DWORD g_Protection; // 1 = on, 0 = off
// change whether TLB memory protections are in effect
#define SET_PROT_OFF	2
#define SET_PROT_ON		3

QWORD HvxGetVersions(DWORD magic, DWORD mode, UINT64 dest = NULL, UINT64 src = NULL, UINT32 len = NULL, UINT64 arg_r8 = NULL);
//=============================================================================================================================================


// resolve an ordinal to an address
DWORD resolveFunct(PCHAR modname, DWORD ord);

// mount a path to a drive name
HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both);

// find the Export Address Table in a given module
// only works in threads with the ability to peek crypted memory
// only tested on "xam.xex" and "xboxkrnl.exe"
PIMAGE_EXPORT_ADDRESS_TABLE getModuleEat(char* modName);

// returns true if the file exists
BOOL fileExists(PCHAR path);

// patches in a 4 instruction jump which uses R11/scratch reg and ctr to assemble
// addr = pointer to address being patched
// dest = address of the new destination
// linked = (true = ctr branch with link used) (false = ctr branch, link register unaffected)
VOID patchInJump(PDWORD addr, DWORD dest, BOOL linked);

// hook export table ordinals of a module, anything linked after this hook is redirected to dstFun
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// ord = ordinal number
// dstFun = address to change ordinal link address to
// returns the address of the start of the hook patched into modName@ord
// ** note that this type of hook ONLY works on things that haven't been linked by the time the patch is made
DWORD hookExportOrd(char* modName, DWORD ord, DWORD dstFun);

// hook imported jumper stubs to a different function
// modname = module with the import to patch
// impmodname = module name with the function that was imported
// ord = function ordinal to patch
// patchAddr = destination where it is patched to
// returns TRUE if hooked
// ** NOTE THIS FUNCTION MAY STILL BE BROKEN FOR MODULES WITH MULTIPLE IMPORT TABLES OF THE SAME impmodname
BOOL hookImpStub(char* modname, char* impmodname, DWORD ord, DWORD patchAddr);

// hook a function start based on address, using 8 instruction saveStub to do the deed
// addr = address of the hook
// saveStub = address of the area to create jump stub for replaced instructions
// dest = where the hook at addr is pointing to
VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest);

// hook a function start based on ordinal, using 8 instruction saveStub to do the deed
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// ord = ordinal number of the function to hook in module modName
// saveStub = address of the area to create jump stub for replaced instructions
// dest = where the hook at addr is pointing to
// returns the address of the start of the hook patched into modName@ord
PDWORD hookFunctionStartOrd(char* modName, DWORD ord, PDWORD saveStub, DWORD dest);

// tries to get the data segment size and start address of named module
// modName = pointer to string of the module name to alter the export table, like "xam.xex" or "xboxkrnl.exe"
// size = pointer to a DWORD to take the size from base
BYTE* getModBaseSize(char* modName, PDWORD size);

void MakeBranchTo(int Address, int Dest);

void cprintf(const char* s, ...);
void makeString(char* dest, void* inpt, unsigned long len, unsigned long maxlen);


enum _XEXPRIVS {
	PRIV_NO_FORCE_REBOOT = 0x0,
	PRIV_FOREGROUND_TASKS = 0x1,
	PRIV_NO_ODD_MAP = 0x2,
	PRIV_HANDLE_MCE_INPUT = 0x3,
	PRIV_RESTRICT_HUD = 0x4,
	PRIV_HANDLE_GC_DISCON = 0x5,
	PRIV_INSECURE_SOCKS = 0x6,
	PRIV_XBOX1_XSP_INTEROP = 0x7,
	PRIV_SET_DASH_CNTXT = 0x8,
	PRIV_USE_VOICE_CHAN = 0x9,
	PRIV_PAL50_INCOMPAT = 0xA,
	PRIV_INSECURE_UTILITY_DRV = 0xB,
	PRIV_TITLE_HOOKS_XAM = 0xC,
	PRIV_PII_ALLOW_BGD_DWNLD = 0xD,
	PRIV_CROSS_SYSTEMLINK = 0xE,
	PRIV_MULTIDISK_SWAP = 0xF,
	PRIV_MULTIDISK_INSECURE = 0x10,
	PRIV_AP25_MEDIA = 0x11,
	PRIV_NO_CONFIRM_EXIT = 0x12,
	PRIV_ALLOW_BGD_DWNLD = 0x13,
	PRIV_CREATE_RAM_DRIVE = 0x14,
	PRIV_INHERIT_RAM_DRIVE = 0x15,
	PRIV_ALLOW_HUD_VIBRATION = 0x16,
	PRIV_USE_BOTH_UTILITY = 0x17,
	PRIV_HANLES_IPTV_IN = 0x18,
	PRIV_PREFER_BIG_BUTTON = 0x19,
	PRIV_RESERVED = 0x1A,
	PRIV_MULTIDISK_CROSS_TITLE = 0x1B,
	PRIV_TITLE_INSTALL_INCOMPAT = 0x1C,
	PRIV_ALLOW_AVA_BY_XUID = 0x1D,
	PRIV_ALLOW_GC_SWAP = 0x1E,
	PRIV_DASH_EXTEND_MOD = 0x1F,
	PRIV_ALLOW_NET_READ_CANCEL = 0x20,
	PRIV_UNINTERUPT_READS = 0x21,
	PRIV_REQUIRES_FULL_XPRNC = 0x22,
	PRIV_VOICE_REQUIRED = 0x23,
	PRIV_TITLE_SET_PRESENCE_STRING = 0x24,
	PRIV_NATAL_TILT_CONTROL = 0x25, // unk
	PRIV_NUI_HEALTH_MESSAGE_REQUIRED = 0x26, // unk
	PRIV_0X27 = 0x27, // unk
	PRIV_0X28 = 0x28, // unk
};

#endif // _UTILS_H