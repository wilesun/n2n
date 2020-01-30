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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#else
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#endif

#include "c_type.h"
#include "sock.h"

#include "debug.h"
#include "client.h"
#include "work.h"

int debug_level = 10;


cli_infp_t gl_cli_infp = {0};
struct pollfd poll_arr[INFP_POLL_MAX];
int curfds = 0;	// 当前pollfd中最大有效下标

void infp_timeout(unsigned long data)
{
	cli_infp_t *infp = (cli_infp_t*)data;

	switch(infp->state)
	{
	case CLI_INFP_INIT:
		if(jiffies > infp->next_login)
		{
			cli_infp_send_login(&infp->main_sock, infp);
			infp->next_login = jiffies + 60 * HZ;
		}
		break;
	case CLI_INFP_LOGIN:
		if(jiffies > infp->next_hb)
		{
			cli_infp_send_heart(&infp->main_sock, infp);
			infp->next_login = jiffies + 60 * HZ;
			infp->state = CLI_INFP_INIT;// 60秒未收到心跳则重新登录
		}
		break;
	default:
		CYM_LOG(LV_ERROR, "???\n");
	}

	CYM_LOG(LV_FATAL, "jiffies = %lu\n", jiffies);

	if(!list_empty(&infp->proxy_list))
	{
		cli_infp_check_proxy_list();
	}

	CYM_LOG(LV_FATAL, "check proxy done\n");

	// 5秒进来一次算了
	mod_timer(&gl_cli_infp.timer, jiffies + 5*HZ);
}

int infp_init(const char *server_addr, __u8 *device_mac)
{
	int try_times = 0;
	int i = 0;
	char server_ipstr[32];
	sscanf(server_addr, "%[^:]", server_ipstr);

	// 初始化jiffies
	init_timer_module();

	INIT_LIST_HEAD(&gl_cli_infp.proxy_list);
	for (i = 0; i < INFP_HASH_MAX; i++)
	{
		INIT_HLIST_HEAD(&gl_cli_infp.proxy_hash[i]);
	}

	snprintf(gl_cli_infp.name, sizeof(gl_cli_infp.name), "%02X:%02X:%02X:%02X:%02X:%02X"
		, device_mac[0], device_mac[1], device_mac[2], device_mac[3], device_mac[4], device_mac[5]);

	// TODO: support dynamic domain
	gl_cli_infp.server_ip = StrToIp(server_ipstr);
	gl_cli_infp.svr_m_port = htons(INFP_DEFAFULT_PORT);
	gl_cli_infp.svr_b_port = htons(INFP_DEFAFULT_PORT+1);

	init_timer(&gl_cli_infp.timer);
	gl_cli_infp.timer.function = infp_timeout;
	gl_cli_infp.timer.data = (unsigned long)&gl_cli_infp;
	add_timer(&gl_cli_infp.timer);

	//初始化sock
	gl_cli_infp.main_sock.fd = INVALID_SOCKET;
	gl_cli_infp.main_port = (rand() % 35535) + 12000;
	try_times = 0;
	while(create_udp(&gl_cli_infp.main_sock, 0, htons(gl_cli_infp.main_port)) < 0)
	{
		CYM_LOG(LV_WARNING, "bind port %d failed\n", gl_cli_infp.main_port);
		if(try_times++ > 50)
		{
			CYM_LOG(LV_ERROR, "out of udp port???\n");
			return -1;
		}

		gl_cli_infp.main_port = (rand() % 35535) + 12000;
	}
	// 设置非阻塞
	set_sock_nonblock(gl_cli_infp.main_sock.fd);

	return 0;
}

int init_poll(void)
{
	int i;
	memset(poll_arr, 0, sizeof(poll_arr));
	for(i = 0; i < INFP_POLL_MAX; i++)
	{
		poll_arr[i].fd = INVALID_SOCKET;
	}

	curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &gl_cli_infp.main_sock);
	if(curfds < 0)
	{
		return -1;
	}

	CYM_LOG(LV_FATAL, "main fd = %d\n", gl_cli_infp.main_sock.fd);

	return 0;
}

int infp_main_recv(sock_t* sock)
{
	struct sockaddr_in addr;
	int ret = 0;
	// 总会收包报错的
	while(udp_sock_recv(sock, &addr) > 0)
	{
		cli_infp_recv_do(sock, &addr);
		ret = 1;
	}

	return ret;
}

int infp_proxy_recv(sock_t* sock)
{
	struct sockaddr_in addr;
	int ret = 0;
	// 总会收包报错的
	while(udp_sock_recv(sock, &addr) > 0)
	{
		cli_infp_proxy_do(sock, &addr);
		ret = 1;
	}

	return ret;
}

int infp_poll_run(int timeout)
{
	int ret = -1;
	int nready = 0, i = 0;
	nready = poll(poll_arr, curfds, timeout);
	if (nready == -1)
	{
		perror("poll error:");
		abort();
	}

	for(i = 0; i < curfds; i++)
	{
		if(poll_arr[i].fd == gl_cli_infp.main_sock.fd)
		{
			if(poll_arr[i].events & POLLIN)
			{
				sock_t *sock = &gl_cli_infp.main_sock;

				if(infp_main_recv(sock))
				{
					if(--nready <= 0)
						break;
				}
			}
		}
		else
		{
			if(poll_arr[i].events & POLLIN)
			{
				int index = 0;
				for(index = 0; index < GUESE_PORT_MAX; index++)
				{
					if(gl_cli_infp.proxy_sock[index].poll_i == i)
						break;
				}
				sock_t *sock = &gl_cli_infp.proxy_sock[index];

				if(infp_proxy_recv(sock))
				{
					if(--nready <= 0)
						break;
				}
			}
		}

		if(poll_arr[i].events & POLLERR)
		{
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

int infp_cli_init(const char *sn_addr, __u8 *device_mac)
{
	int ret = -1;
	gl_cli_infp.mode = 0;

	CYM_LOG(LV_QUIET, "start\n");

	if(infp_init(sn_addr, device_mac))
	{
		printf("infp_init failed\n");
		goto FUNC_OUT;
	}

	if(init_poll())
	{
		printf("init_poll failed\n");
		goto FUNC_OUT;
	}

	// 第一个timer里发
	//cli_infp_send_login(&gl_cli_infp.main_sock, &gl_cli_infp);

	CYM_LOG(LV_QUIET, "init ok\n");
	#if 0
	while(1)
	{
		if(infp_poll_run(30))
			break;

		run_timer_list();
	}
	#endif
	ret = 0;
FUNC_OUT:
	return ret;
}

