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

#ifndef __SOCK_H__
#define __SOCK_H__

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#define poll(a, b, c) WSAPoll(a, b, c)
#define close(a) closesocket(a)
#else
#include <netdb.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif
#include <fcntl.h>
#include <string.h>

#include "timer.h"
#include "list.h"
#include "c_type.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

#define GUESE_PORT_MAX 4

typedef struct sock_s
{
	int fd;
	int poll_i;
	__u32 uptime;		// 最后一次有收包/发包时间 jiffies
	__u8 listen;		// 监听sock
	__u8 malloced;		// 动态创建
	__u16 pad;			//

	__u8* recv_buf;		// 接收缓存
	int recv_buf_len;	// 接收缓存总大小
	int recv_len;		// 当前已接收数据大小

	char* send_buf;		// 发送缓存
	int send_buf_len;	// 发送缓存总大小
	int send_len;		// 当前待发送数据大小

	struct sockaddr_in addr;	// 本地监听的addr信息

	struct hlist_node hash_to;	// fd 作为唯一标识

}sock_t;

static inline void poll_add_write(struct pollfd* _poll)
{
	_poll->events |= POLLOUT;
}

static inline void poll_del_write(struct pollfd* _poll)
{
	_poll->events &= (~POLLOUT);
}

static inline void poll_add_read(struct pollfd* _poll)
{
	_poll->events |= POLLIN;
}

static inline void poll_del_read(struct pollfd* _poll)
{
	_poll->events &= (~POLLIN);
}

static inline int set_sock_block(int fd)
{
	//???????
#ifdef WIN32
	unsigned long ul = 0;
	int ret = ioctlsocket(fd, FIONBIO, (unsigned long *)&ul);
#else
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
#endif
	if(ret == -1)
	{
		perror("set sock block:");
	}

	return ret;
}

static inline int set_sock_nonblock(int fd)
{
	//????????
#ifdef WIN32
	unsigned long ul = 1;
	int ret = ioctlsocket(fd, FIONBIO, (unsigned long *)&ul);
#else
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
	if(ret == -1)
	{
		perror("set sock nonblock:");
	}

	return ret;
}

static inline int set_sock_timeout(int fd, int timeout)
{
	int ret;
	struct timeval _timeout;
	_timeout.tv_sec = (timeout / 1000);
	_timeout.tv_usec = (timeout % 1000) * HZ;
	//??????
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&_timeout, sizeof(struct timeval));
	//??????
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&_timeout, sizeof(struct timeval));

	return ret;
}

static inline int set_sock_ttl(int fd, int* ttl)
{
	socklen_t len = sizeof(*ttl);
	return setsockopt(fd, IPPROTO_IP, IP_TTL, (void*)ttl, len);
}

static inline int get_sock_ttl(int fd, int* ttl)
{
	socklen_t len = sizeof(*ttl);
	return getsockopt(fd, IPPROTO_IP, IP_TTL, (void*)ttl, &len);
}

static inline __u32 StrToIp(const char *str)
{
	union {
		struct in_addr ipaddr;
		__u32 ip;
	}addr;
	memset(&addr, 0, sizeof(addr));
#ifdef WIN32
	inet_pton(AF_INET, str, &addr.ipaddr);
#else
	inet_aton(str, &addr.ipaddr);
#endif
	return addr.ip;
}

static inline char* IpToStr(__u32 ip)
{
	struct in_addr ipaddr;
	memcpy(&ipaddr, &ip, sizeof(ipaddr));
	return inet_ntoa(ipaddr);
}

int sock_add_poll(struct pollfd* _poll, int max, sock_t* sock);
int sock_del_poll(struct pollfd* _poll, int max, sock_t* sock);
int create_udp(sock_t *sock, __u32 ip, __u16 port);
int create_tcp(sock_t *sock, __u32 ip, __u16 port, int _listen);
sock_t *tcp_accept(sock_t *sock);
int tcp_just_connect(int fd, unsigned int addr, unsigned short port, int times);
int udp_sock_recv(sock_t * sock, struct sockaddr_in * addr);
int udp_sock_send(sock_t * sock, void * data, int data_len, __u32 ip, __u16 port);
void set_sockaddr_in(struct sockaddr_in *addr, __u32 ip, __u16 port);
void close_sock(sock_t *sock);
void free_sock(sock_t *sock);
__u32 get_default_local_ip(void);
sock_t* sock_find_fd(int fd);
int infp_try_connect(const char* src, const char* dst, unsigned short sport, unsigned short dport, int ttl);


#endif

