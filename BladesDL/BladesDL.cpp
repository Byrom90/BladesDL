//===============================================================================================================================================
//
//		BladesDL - A basic Dashlaunch substitute for Blades kernel (6770). Performs some of the basic tasks Dashlaunch would normally provide.
//
// Created by Byrom - https://github.com/Byrom90
//
// Credits:
//			- c0z - Majority of the functions/hooks were backported from an old version of Dashlaunch
//
//===============================================================================================================================================

#include "stdafx.h"
#include "BladesDL.h"


BOOL WINAPI DllMain(HANDLE hInstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	dllHandle = hInstDLL;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		cprintf("[BladesDL] Loaded!");
		SetupDNSHook();
		SetupLoaderPrepHook();
		SetupkeBugCheckExHook();
		SetupXamCheckExecPrivHook();
		PatchUpdStrings();
		ApplyPingPatch();

		cprintf("[BladesDL] Init complete!");
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}