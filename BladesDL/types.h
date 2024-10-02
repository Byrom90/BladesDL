// 
// data type defs for easy cross-processor support
// 

#ifndef _COMMON_TYPES_
#define _COMMON_TYPES_


typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned __int64	u64;
typedef unsigned __int64	QWORD;

typedef signed char			s8;
typedef signed short		s16;
typedef signed int			s32;
typedef signed __int64		s64;

#ifndef NULL
#define NULL	0
#endif // NULL

typedef enum {
	XNCALLER_INVALID = 0x0,
	XNCALLER_TITLE = 0x1,
	XNCALLER_SYSAPP = 0x2,
	XNCALLER_XBDM = 0x3,
	XNCALLER_TEST = 0x4,
	NUM_XNCALLER_TYPES = 0x4,
} XNCALLER_TYPE;

#endif // _COMMON_TYPES_


