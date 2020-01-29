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

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "list.h"
#include "timer.h"
#include "sock.h"

#define INFP_DEFAFULT_PORT 45124 // TODO: 配置文件获取

#define INFP_HASH_MAX 0x100
#define INFP_HASH_MASK 0xff

enum CLI_INFP_STATE
{
	CLI_INFP_INIT = 0,		// 初始化
	CLI_INFP_LOGIN,			// 已登陆
};

typedef struct inf_proxy_s
{
	char  name[32];		// 标识(MAC地址)
	struct sockaddr_in addr;// 对端公网地址
	int  fd;			// 本地与对端通信用fd
	__u32 uptime;		// 最后收到对方数据包时间 jiffies -> 暂定60秒超时, 销毁该隧道
	__u32 connected;	// 是否已连接

	struct list_head list_to; // 关联 cli_infp_t->proxy_list
	struct hlist_node hash_to; // 关联 cli_infp_t->proxy_hash
}inf_proxy_t;

/* 存放一些全局变量 */
typedef struct cli_infp_s
{
	__u32 server_ip;		// 服务器ip (网络序)
	__u16 svr_m_port;		// 服务器主端口 (网络序)
	__u16 svr_b_port;		// 服务器副端口 (网络序)

	__u16 main_port;		// 与服务器连接的主端口, 主连接用
	__u16 proxy_port[3];	// 准备的代理端口

	sock_t main_sock;		// 对应main_port
	sock_t proxy_sock[3];	// 对应proxy_port (代理主连接)

	__u32 nat_type;			// @see C_NAT_TYPE
	char  name[32];			// 客户端标识 (MAC地址)
	__u8  mode;				// 客户端模式 0:host, 1:client
	__u8  pad[3];

	__u32 state;			// @see CLI_INFP_STATE
	__u32 next_login;		// 下次登陆
	__u32 next_hb;			// 下次心跳

	struct list_head proxy_list;	// NAT穿透的对端设备链表 -> inf_proxy_t
	struct hlist_head proxy_hash[INFP_HASH_MAX];// proxy_list的hash

	struct timer_list timer;	// 1秒1次的timer (所有timer可以统一扔这里)
}cli_infp_t;

#define INFP_POLL_MAX 20		// 随手写的

extern cli_infp_t gl_cli_infp;
extern struct pollfd poll_arr[];
extern int curfds;

#endif // __SERVER_H__
