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
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <signal.h>

#include "c_type.h"
#include "sock.h"

#include "server.h"
#include "work.h"
#include "debug.h"

int debug_level = 10;

#define INFP_DEFAFULT_PORT 45124 // TODO: 配置文件获取
#define INFP_POLL_MAX 32		// 随手写的, 目前只监听32个

infp_t gl_infp = {};
struct pollfd poll_arr[INFP_POLL_MAX];
int curfds = 0;	// 当前pollfd中最大有效下标

void infp_timeout(unsigned long data)
{
	infp_cli_t *cli;
	struct list_head *pos, *n;
	__u32 now_time = jiffies;

	list_for_each_safe(pos, n, &gl_infp.dev_list)
	{
		cli = list_entry(pos, infp_cli_t, list_to);
		if(now_time - cli->uptime > 180 * HZ)
		{
			infp_del_cli(cli);
		}
	}

	mod_timer(&gl_infp.timer, jiffies + HZ);
}

int infp_init(void)
{
	int i = 0;

	// 初始化jiffies
	init_timer_module();

	init_timer(&gl_infp.timer);
	gl_infp.timer.function = infp_timeout;
	add_timer(&gl_infp.timer);

	//初始化链表
	INIT_LIST_HEAD(&gl_infp.dev_list);
	for(i = 0; i < INFP_HASH_MAX; i++)
	{
		INIT_HLIST_HEAD(&gl_infp.dev_hash[i]);
	}

	//初始化端口表
	gl_infp.main_port = INFP_DEFAFULT_PORT;
	gl_infp.back_port = INFP_DEFAFULT_PORT + 1;

	//初始化sock
	if(create_udp(&gl_infp.main_sock, 0, htons(gl_infp.main_port)) < 0)
		return -1;
	// 设置非阻塞
	set_sock_nonblock(gl_infp.main_sock.fd);

	if(create_udp(&gl_infp.back_sock, 0, htons(gl_infp.back_port)) < 0)
		return -1;
	// 设置非阻塞
	set_sock_nonblock(gl_infp.back_sock.fd);

	if(create_tcp(&gl_infp.tcp_sock, 0, htons(gl_infp.main_port), 1) < 0)
		return -1;

	return 0;
}

int init_poll(void)
{
	int i;
	memset(poll_arr, 0, sizeof(poll_arr));

	for(i = 0; i < INFP_POLL_MAX; i++)
	{
		poll_arr[i].fd = -1;
	}

	curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &gl_infp.main_sock);
	if(curfds < 0)
	{
		return -1;
	}

	curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &gl_infp.back_sock);
	if(curfds < 0)
	{
		return -1;
	}

	curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &gl_infp.tcp_sock);
	if(curfds < 0)
	{
		return -1;
	}
	return 0;
}

int infp_main_recv(sock_t* sock)
{
	struct sockaddr_in addr;
	int ret = 0;
	// ???????
	while((ret = udp_sock_recv(sock, &addr)) > 0)
	{
		infp_recv_do(sock, &addr);
		ret = 1;
	}

	return ret;
}

int infp_poll_run(int timeout)
{
	int ret = -1;
	int nready = 0, i = 0;
	nready = poll(poll_arr, curfds, timeout);
	if (nready < 0)
	{
		perror("poll error:");
		abort();
	}
	else if(nready == 0)
	{
		return 0;
	}

	for(i = 0; i < curfds; i++)
	{
		if(poll_arr[i].fd == gl_infp.main_sock.fd
			|| poll_arr[i].fd == gl_infp.back_sock.fd)
		{
			if(poll_arr[i].revents & POLLIN)
			{
				sock_t *sock = NULL;
				if(poll_arr[i].fd == gl_infp.main_sock.fd)
					sock = &gl_infp.main_sock;
				else if(poll_arr[i].fd == gl_infp.back_sock.fd)
					sock = &gl_infp.back_sock;
				else
					goto out;	// ?????

				if(infp_main_recv(sock))
				{
					if(--nready <= 0)
						break;
				}
			}

			// ??POLLOUT????, ??sendto
			if(poll_arr[i].revents & POLLERR)
			{
				goto out;
			}
		}
		else if(poll_arr[i].fd == gl_infp.tcp_sock.fd)
		{
			if(poll_arr[i].revents & POLLIN)
			{
				sock_t* sock = tcp_accept(&gl_infp.tcp_sock);
				if(sock)
				{
					int ret = sock_add_poll(poll_arr, INFP_POLL_MAX, sock);
					if(ret < 0)
					{
						close_sock(sock);
						if(--nready <= 0)
							break;

						continue;
					}
					curfds = ret;
					printf("accept fd [%d] ok\n", sock->fd);
				}
				if(--nready <= 0)
					break;
			}

			// ??POLLOUT????, ??sendto
			if(poll_arr[i].revents & POLLERR)
			{
				goto out;
			}
		}
		else if(poll_arr[i].fd != -1)
		{
			sock_t* sock = sock_find_fd(poll_arr[i].fd);
			if(!sock)
			{
				close(poll_arr[i].fd);
				poll_arr[i].fd = INVALID_SOCKET;
				if(--nready <= 0)
					break;

				continue;
			}

			if(poll_arr[i].revents & POLLIN)
			{
				int ret = infp_main_recv(sock);
				if(ret > 0)
				{
					if(--nready <= 0)
						break;
				}
				else if(ret == 0)
				{
					sock_del_poll(poll_arr, INFP_POLL_MAX, sock);
					close_sock(sock);
				}
				else
				{
				// TODO: ????????
				}
			}

			// TODO: ??
			if(poll_arr[i].revents & POLLOUT)
			{
				if(--nready <= 0)
					break;
			}

			if(poll_arr[i].revents & POLLERR)
			{
				goto out;
			}
		}
	}

	ret = 0;
out:
	return ret;
}

int infp_svr_init(void)
{
	int ret = -1;
	CYM_LOG(LV_QUIET, "start\n");

	signal(SIGPIPE, SIG_IGN);

	if(infp_init())
	{
		printf("infp_init failed\n");
		goto OUT;
	}

	if(init_poll())
	{
		printf("init_poll failed\n");
		goto OUT;
	}

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
OUT:
	return ret;
}

