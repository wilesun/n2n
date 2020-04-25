#ifndef __C_TYPE_H__
#define __C_TYPE_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;

enum C_NAT_TYPE
{
	UNKNOWN_NAT_TYPE = 0,	// ??,???
	CONE_NAT_TYPE,			// ??NAT
	SYMMETRICAL_NAT_TYPE,	// ??NAT
	NIUBILITY_NAT_TYPE,		// IP???IP
};

#endif
