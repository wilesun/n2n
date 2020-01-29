/*
Copyright 2020 chseasipder

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __SERVER_H__
#define __SERVER_H__

#include "list.h"
#include "timer.h"
#include "sock.h"

#define INFP_HASH_MAX 0x100
#define INFP_HASH_MASK 0xff

/* 存放一些全局变量 */
typedef struct infp_s
{
	__u16 main_port;		// 监听的主端口, 主连接用
	__u16 back_port;		// 监听的副端口, 用于检测NAT类型

	sock_t main_sock;		// 对应main_port
	sock_t back_sock;		// 对应back_port

	struct list_head dev_list;
	struct hlist_head dev_hash[INFP_HASH_MAX];
	struct timer_list timer;	// 1秒1次的timer
}infp_t;

typedef struct infp_port_s
{
	__u16 src_port;
	__u16 nat_port;
}infp_port_t;

typedef struct infp_cli_s
{
	char ip[32];		// 终端的内网IP地址
	char name[32];		// 终端名称(自定义/系统获取)
	char des[64];		// 终端标识(IP地址+终端名称)

	__u32 nat_ip;		// 公网IP地址(网络序)

	infp_port_t main_port;	// 与服务器主连接的端口信息
	infp_port_t guess[2];	// 用于端口预测(仅支持等差数列的情况)
	__u32 guess_port;	/* 猜测的下一个端口(nat_type 为 SYMMETRICAL_NAT_TYPE才使用)
							其他情况,使用guess[0].nat_port
						*/

	__u8 nat_type;		// nat类型 @see C_NAT_TYPE
	__u8 mode;			// 0: 客户端 1: PC端
	__u8 failed_count;	// 打洞失败次数
	__u8 connected;		// 有木有连人

	__u32 uptime;		// 更新时间 jiffies

	struct list_head list_to;	// 关联infp_t.dev_list
	struct hlist_node hash_to;	// 关联infp_t.dev_hash ip+name作为hash值
}infp_cli_t;

extern infp_t gl_infp;

#endif // __SERVER_H__
