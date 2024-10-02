#include "stdafx.h"


VOID PatchUpdStrings(VOID)
{
	DWORD siz = 0;
	PBYTE ptr = getModBaseSize(MODULE_XAM, &siz);
	//DbgPrint("updater detect patch start %08x size %08x\n", ptr, siz);
	int Str_Patched = 0;
	if ((ptr != NULL) && (siz != 0))
	{
		DWORD i;
		for (i = 0; i < siz; i++)
		{
			if (ptr[i] == '$')
			{
				if (strnicmp("$systemupdate", (char*)&ptr[i], strlen("$systemupdate")) == 0)
				{
					ptr[i + 1] = '$';
					//DbgPrint("patch %s at %08x\n", &ptr[i], &ptr[i]);
					i += strlen("$systemupdate");
					Str_Patched++;
				}
			}
		}
	}
	cprintf("[BladesDL] [PatchUpdStrings] Patched %i strings to $$ystemupdate", Str_Patched);
}


// Ping Patch - NOP the jump for when ping exceeds 30
#define PING_PATCH_ADDR_6770 0x81947D38
VOID ApplyPingPatch()
{
	cprintf("[BladesDL] [PingPatch] Removing ping limit for system link play");
	//*(DWORD*)PING_PATCH_ADDR_6770 = 0x60000000;
	PDWORD ptr = (PDWORD)PING_PATCH_ADDR_6770;
	ptr[0] = 0x60000000;
	doSync(ptr);
}

