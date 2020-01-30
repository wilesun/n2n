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
#include <string.h>

#include "sock.h"
#include "mem.h"
#include "debug.h"

#define SOCK_BUF_LEN 102400
#define GET_GATEWAY_CMD "route | grep 'default' | awk '{print $8}'"

#if 0
int get_gateway_devname(char *gate)
{
	FILE *fp = NULL;
	char temp[20] = {0};
	int i = 0;

	fp = popen(GET_GATEWAY_CMD, "r");
	if (fp == NULL)
	{
		perror("popen:");
		return -1;
	}
	else
	{
		if (fread(temp, sizeof(char), sizeof(temp), fp) == -1)
		{
			perror("fread:");
		}
	}

	pclose(fp);

	while (temp[i] != '\n') {
		i++;
	}
	temp[i] = '\0';

	memcpy(gate, temp, strlen(temp));

	return 0;
}
#endif

__u32 get_default_local_ip(void)
{
#if 0
	static __u32 ip = 0;
	char dev[32] = {0};
	int inet_sock;
	struct ifreq ifr = {};

	if(ip)
		return ip;

	if(get_gateway_devname(dev))
		return 0;

	inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, dev);
	ioctl(inet_sock, SIOCGIFADDR, &ifr);

	memcpy(&ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(ip));

	close(inet_sock);
	return ip;
#else
	return 0;
#endif
}

int sock_add_poll(struct pollfd* _poll, int max, sock_t* sock)
{
	int curfd = 0;
	int i, found = 0;
	for(i = curfd; i < max; i++)
	{
		if(_poll[i].fd == INVALID_SOCKET)
		{
			_poll[i].fd = sock->fd;
			sock->poll_i = i;
			poll_add_read(&_poll[i]);
			found = 1;
			break;
		}
	}

	if(found)
	{
		for(i = max - 1; i >= 0; i--)
		{
			if(_poll[i].fd != INVALID_SOCKET)
			{
				curfd = i;
				break;
			}
		}
	}
	else
	{
		printf("poll is full\n");
	}

	return found ? curfd+1 : -1;
}

int sock_del_poll(struct pollfd* _poll, int max, sock_t* sock)
{
	int curfd = 0;
	int i;

	memset(&_poll[sock->poll_i], 0, sizeof(_poll[sock->poll_i]));
	_poll[sock->poll_i].fd = INVALID_SOCKET;

	for(i = max; i >= 0; i--)
	{
		if(_poll[i].fd != INVALID_SOCKET)
		{
			curfd = i;
			break;
		}
	}

	CYM_LOG(LV_FATAL, "poll fd:");
	for (i = 0; i < curfd; i++)
	{
		CYM_LOG(LV_FATAL, "[%d]:%d ", i, _poll[i].fd);
	}
	CYM_LOG(LV_FATAL, "\n");

	return curfd;
}

// IP ÍøÂçÐò, PORT ÍøÂçÐò
void set_sockaddr_in(struct sockaddr_in *addr, __u32 ip, __u16 port)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = ip;
	addr->sin_port = port;
}

int udp_sock_send(sock_t *sock, void* data, int data_len, __u32 ip, __u16 port)
{
	int ret = 0;
	struct sockaddr_in addr; 
	socklen_t addr_len = sizeof(addr);

	if(!data || !data_len)
	{
		printf("data is null or data_len is zero\n");
		return 0;
	}

	set_sockaddr_in(&addr, ip, port);

	ret = sendto(sock->fd, data, data_len, 0, (struct sockaddr *)&addr, addr_len);
	if(ret <= 0)
		return ret;

	if(ret < data_len)
	{
		int len = data_len - ret;
		while(sock->send_buf_len < len)
		{
			sock->send_buf = mem_realloc(sock->send_buf, sock->send_buf_len + SOCK_BUF_LEN);
			if(!sock->send_buf)
			{
				printf("realloc failed\n");
				abort();
			}

			sock->send_buf_len += SOCK_BUF_LEN;
		}
		memcpy(sock->send_buf+sock->send_len, (char*)data + ret, len);
	}

	return ret;
}

int udp_sock_recv(sock_t *sock, struct sockaddr_in *addr)
{
	int ret = 0;
	socklen_t addr_len = sizeof(*addr);

	while(sock->recv_buf_len - sock->recv_len < SOCK_BUF_LEN)
	{
		sock->recv_buf = mem_realloc(sock->recv_buf, sock->recv_buf_len + SOCK_BUF_LEN);
		if(!sock->recv_buf)
		{
			printf("realloc failed\n");
			abort();
		}

		sock->recv_buf_len += SOCK_BUF_LEN;
	}

	ret = recvfrom(sock->fd, sock->recv_buf+sock->recv_len, SOCK_BUF_LEN, 0, (struct sockaddr *)addr, &addr_len);
	if(ret > 0)
	{
		sock->recv_len += ret;
	}
	return ret;
}


int create_udp(sock_t *sock, __u32 ip, __u16 port)
{
	struct sockaddr_in addr; 
	socklen_t addr_len = sizeof(addr);

	if(!sock)
		return -1;

	if(sock->recv_buf)
		mem_free(sock->recv_buf);

	if(sock->send_buf)
		mem_free(sock->send_buf);

	memset(sock, 0, sizeof(sock_t));

	sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock->fd < 0)
	{
		perror("socket:");
		return -1;
	}

	set_sockaddr_in(&addr, ip, port);

	if(bind(sock->fd, (struct sockaddr *)&addr, addr_len) < 0)
	{
		perror("bind:");
		close(sock->fd);
		sock->fd = INVALID_SOCKET;
		return -1;
	}

	CYM_LOG(LV_FATAL, "bind %s:%d, fd [%d] ok\n", IpToStr(ip), ntohs(port), sock->fd);

	return sock->fd;
}

void close_sock(sock_t *sock)
{
	if (sock->fd > 0)
	{
		close(sock->fd);
		CYM_LOG(LV_FATAL, "close fd = %d\n", sock->fd);
	}

	if(sock->recv_buf)
	{
		mem_free(sock->recv_buf);
		sock->recv_buf = NULL;
	}

	if(sock->send_buf)
	{
		mem_free(sock->send_buf);
		sock->send_buf = NULL;
	}

	memset(sock, 0, sizeof(sock_t));
	sock->fd = INVALID_SOCKET;
}


