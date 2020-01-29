#ifndef __INFILTRATE_H__
#define __INFILTRATE_H__

#define DEFULAT_MAGIC 0x74a9c6f8

typedef struct infp_head_s
{
	__u32 magic;	// 头标识(配置文件读取)

	__u32 data_len;	// 负载数据长度
	__u8 data[0];	// (加密)负载数据->放json
}infp_head_t;

#endif
