#ifndef __MEM_H__
#define __MEM_H__

#include "stdlib.h"
#include "string.h"

static inline void* mem_malloc(__u32 size)
{
	void* temp = malloc(size);
	if(temp)
	{
		memset(temp, 0, size);
	}

	return temp;
}

static inline void* mem_realloc(void* ptr, __u32 size)
{
	void* temp;
	if(ptr)
	{
		temp = realloc(ptr, size);
	}
	else
	{
		temp = mem_malloc(size);
	}

	return temp;
}


static inline void mem_free(void* ptr)
{
	if(ptr)
		free(ptr);
}

#endif
