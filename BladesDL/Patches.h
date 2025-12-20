#pragma once
#include "stdafx.h"

#ifndef _PATCHES_H
#define _PATCHES_H

VOID PatchUpdStrings(VOID);
VOID ApplyPingPatch(VOID);

#define PING_PATCH_ADDR_6770 0x81947D38
#define PING_PATCH_ADDR_1888 0x819B9048

#endif // _PATCHES_H
