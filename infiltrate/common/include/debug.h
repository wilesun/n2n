#ifndef __DEBUG_H__
#define __DEBUG_H__

#define LV_QUIET	0
#define LV_PANIC	1
#define LV_FATAL	2
#define LV_ERROR	3
#define LV_WARNING	4
#define LV_INFO		5
#define LV_VERBOSE	6
#define LV_DEBUG	7

extern int debug_level;
void _cym_log(char const * format, ...);

#define CYM_LOG(n, s, ...) do{\
				if(debug_level > n) {\
					printf(s,##__VA_ARGS__);\
					_cym_log(s,##__VA_ARGS__);\
				}\
			}while(0)

#endif

