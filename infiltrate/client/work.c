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

#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "work.h"
#include "cJSON.h"
#include "debug.h"
#include "mem.h"

void memxor(unsigned char* data, int len)
{
	int i = 0;
	for(i = 0; i < len; i++)
		data[i] ^= 0x71;
}


static inline struct hlist_head* inf_proxy_get_hash_head(char *str)
{
	return &gl_cli_infp.proxy_hash[(SDBMHash(str) & INFP_HASH_MASK)];
}

void edge_p2p_fd_close(char *macstr);
void edge_p2p_fd_timeout(char *macstr, int timeout);
void inf_proxy_del_cli(inf_proxy_t* del)
{
	if(del)
	{
		CYM_LOG(LV_INFO, "[%s] offline\n", del->name);

		if(del->fd > 0)
		{
			edge_p2p_fd_close(del->name);
			close(del->fd);
			CYM_LOG(LV_FATAL, "close fd 2 = %d\n", del->fd);
			del->fd = INVALID_SOCKET;
		}
		list_del(&del->list_to);
		hlist_del(&del->hash_to);
		mem_free(del);
	}
}

inf_proxy_t *inf_proxy_create_cli(char *str)
{
	inf_proxy_t *temp = mem_malloc(sizeof(inf_proxy_t));
	if(temp)
	{
		list_add_tail(&temp->list_to, &gl_cli_infp.proxy_list);
		hlist_add_head(&temp->hash_to, inf_proxy_get_hash_head(str));

		CYM_LOG(LV_FATAL, "create [%s]\n", str);
		snprintf(temp->name, sizeof(temp->name), "%s", str);
		temp->fd = INVALID_SOCKET;
		temp->uptime = jiffies;	// ´´½¨µÄÊ±ºò¸³Öµ
	}

	return temp;
}

inf_proxy_t *inf_proxy_find_cli(char *str)
{
	struct hlist_node *pos;
	inf_proxy_t *temp;

	hlist_for_each(pos, inf_proxy_get_hash_head(str))
	{
		temp = hlist_entry(pos, inf_proxy_t, hash_to);
		if(!strcmp(temp->name, str))
		{
			return temp;
		}
	}

	return NULL;
}

inf_proxy_t *inf_proxy_find_create_cli(char *str)
{
	inf_proxy_t *temp = inf_proxy_find_cli(str);
	if(temp)
		return temp;

	return inf_proxy_create_cli(str);
}

void cli_infp_check_proxy_list(void)
{
	inf_proxy_t *temp;
	struct list_head *pos, *n;
	__u32 now = jiffies;
	// TODO: thread protect
	list_for_each_safe(pos, n, &gl_cli_infp.proxy_list)
	{
		sock_t sock;
		temp = list_entry(pos, inf_proxy_t, list_to);
		sock.fd = temp->fd;
		if (now - temp->uptime > 15 * HZ)
		{
			inf_proxy_del_cli(temp);
			continue;
		}
		else if(now - temp->uptime > HZ)
		{
			if (!temp->timeout)
			{
				temp->timeout = 1;
				edge_p2p_fd_timeout(temp->name, 1);
			}
		}
		else
		{
			if (temp->timeout)
			{
				temp->timeout = 0;
				edge_p2p_fd_timeout(temp->name, 0);
			}
		}

		if (temp->send_count <= 0)
		{
			int ret = cli_infp_send_stun_hello(&sock, &gl_cli_infp, temp->addr.sin_addr.s_addr, temp->addr.sin_port);
			if(ret > 0)
				temp->send_count++;
			else if (ret == 0)
			{
				inf_proxy_del_cli(temp);
				continue;
			}
		}
	}
}

void inf_proxy_get_fds(int* fds, int* fd_num)
{
	inf_proxy_t *temp;
	struct list_head *pos;
	int fd_nums = 0;
	*fd_num = 0;

	list_for_each(pos, &gl_cli_infp.proxy_list)
	{
		temp = list_entry(pos, inf_proxy_t, list_to);
		if(temp->fd > 0)
		{
			fds[fd_nums++] = temp->fd;
		}
	}

	*fd_num = fd_nums;
}

void inf_get_fds(int* fds, int* fd_num)
{
	int fd_nums = 0;
	*fd_num = 0;
	int i = 0;

	fds[fd_nums++] = gl_cli_infp.main_sock.fd;
	for(i = 0; i < GUESE_PORT_MAX; i++)
	{
		if(gl_cli_infp.proxy_sock[i].fd > 0)
			fds[fd_nums++] = gl_cli_infp.proxy_sock[i].fd;
	}

	*fd_num = fd_nums;
}


int cli_infp_send(__u32 ip, __u16 port, sock_t* sock, char *data, int len)
{
	int ret;
	struct sockaddr_in addr;
	int socklen = sizeof(addr);

	set_sockaddr_in(&addr, ip, port);
	CYM_LOG(LV_DEBUG, "send [%s]\n", data);
	memxor((__u8*)data, len);

	ret = sendto(sock->fd, data, len, 0, (struct sockaddr*)&addr, socklen);
	return ret;
}

int cli_infp_send_login(sock_t* sock, cli_infp_t* infp)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"login\",\"ip\":\"%s\",\"port\":\"%d\","
					"\"mode\":\"%s\",\"name\":\"%s\",\"allow_tcp\":\"%d\"}"
					, IpToStr(local_ip)
					, infp->main_port
					, infp->mode ? "client" : "host"
					, infp->name
					, infp->allow_tcp
					);

	return cli_infp_send(infp->server_ip, infp->svr_m_port, sock, send_buf, len);
}

int cli_infp_send_heart(sock_t* sock, cli_infp_t* infp)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"heart_beat\",\"ip\":\"%s\",\"name\":\"%s\"}"
					, IpToStr(local_ip)
					, infp->name
					);

	return cli_infp_send(infp->server_ip, infp->svr_m_port, sock, send_buf, len);
}

int cli_infp_send_get_nat_type(sock_t* sock, cli_infp_t* infp)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"get_nat_type\",\"ip\":\"%s\",\"port\":\"%d\",\"name\":\"%s\"}"
					, IpToStr(local_ip)
					, infp->main_port
					, infp->name
					);

	return cli_infp_send(infp->server_ip, infp->svr_b_port, sock, send_buf, len);
}

int cli_infp_do_login_ack(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	cJSON* j_value;

	j_value = cJSON_GetObjectItem(root, "next_hb");
	if(!j_value || !j_value->valueint)
	{
		CYM_LOG(LV_ERROR, "parse next_hb failed\n");
		goto out;
	}

	gl_cli_infp.state = CLI_INFP_LOGIN;
	gl_cli_infp.next_hb = jiffies + j_value->valueint * HZ;

	cli_infp_send_get_nat_type(sock, &gl_cli_infp);
	ret = 0;
out:
	return ret;
}

int cli_infp_do_heart_ack(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	cJSON* j_value;

	j_value = cJSON_GetObjectItem(root, "next_hb");
	if(!j_value || !j_value->valueint)
	{
		CYM_LOG(LV_ERROR, "parse next_hb failed\n");
		goto out;
	}

	gl_cli_infp.state = CLI_INFP_LOGIN;
	gl_cli_infp.next_hb = jiffies + j_value->valueint * HZ;

	ret = 0;
out:
	return ret;
}

int cli_infp_send_proxy_request(sock_t* sock, cli_infp_t* infp, char* dst_ip, char* dst_name)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"proxy_request\",\"ip\":\"%s\",\"name\":\"%s\""
						",\"dst_ip\":\"%s\",\"dst_name\":\"%s\"}"
					, IpToStr(local_ip)
					, infp->name
					, dst_ip
					, dst_name
					);

	return cli_infp_send(infp->server_ip, infp->svr_m_port, sock, send_buf, len);
}

int cli_infp_do_nat_type_ack(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	cJSON* j_value;

	j_value = cJSON_GetObjectItem(root, "type");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse type failed\n");
		goto out;
	}

	gl_cli_infp.nat_type = atoi(j_value->valuestring);

	CYM_LOG(LV_INFO, "nat_type = %d\n", gl_cli_infp.nat_type);

	#if 0
	if(gl_cli_infp.mode && strlen(gl_cli_infp.dst.ip))
		cli_infp_send_proxy_request(sock, &gl_cli_infp);
	#endif

	ret = 0;
out:
	return ret;
}

int cli_infp_send_get_tcp_nat_port(sock_t* sock, cli_infp_t* infp, int num, char* dst_ip, char* dst_name)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"get_tcp_nat_port\",\"ip\":\"%s\",\"name\":\"%s\""
						",\"port\":\"%d\",\"num\":\"%d\",\"dst_ip\":\"%s\",\"dst_name\":\"%s\"}"
					, IpToStr(local_ip)
					, infp->name
					, infp->proxy_port[num]
					, num
					, dst_ip
					, dst_name
					);

	// 介个包, 只能扔主端口
	return cli_infp_send(infp->server_ip, infp->svr_m_port, sock, send_buf, len);
}

int cli_infp_send_get_nat_port(sock_t* sock, cli_infp_t* infp, int num, char* dst_ip, char* dst_name)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"get_nat_port\",\"ip\":\"%s\",\"name\":\"%s\""
						",\"port\":\"%d\",\"num\":\"%d\",\"dst_ip\":\"%s\",\"dst_name\":\"%s\"}"
					, IpToStr(local_ip)
					, infp->name
					, infp->proxy_port[num]
					, num
					, dst_ip
					, dst_name
					);

	// 介个包, 姑且扔副端口
	return cli_infp_send(infp->server_ip, infp->svr_b_port, sock, send_buf, len);
}

int cli_infp_send_proxy_task_ack(sock_t* sock, cli_infp_t* infp, int ret, char* dst_ip, char* dst_name)
{
	char send_buf[1024];
	__u32 local_ip = get_default_local_ip();

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"proxy_task_ack\",\"ip\":\"%s\",\"name\":\"%s\""
						",\"dst_ip\":\"%s\",\"dst_name\":\"%s\",\"ret\":\"%d\"}"
					, IpToStr(local_ip)
					, infp->name
					, dst_ip
					, dst_name
					, ret
					);

	// 介个包, 姑且扔副端口
	return cli_infp_send(infp->server_ip, infp->svr_b_port, sock, send_buf, len);
}

int cli_infp_get_nat_port(sock_t* sock, cli_infp_t* infp, char* dst_ip, char* dst_name, int tcp_mode)
{
	int try_times = 0;
	int i = 0;
	__u16 port = 0;

	for(i = 0; i < GUESE_PORT_MAX; i++)
	{
		if(gl_cli_infp.proxy_sock[i].fd > 0)
		{
			sock_del_poll(poll_arr, INFP_POLL_MAX, &gl_cli_infp.proxy_sock[i]);
			close_sock(&gl_cli_infp.proxy_sock[i]);
		}
	}

	try_times = 0;
try_bind:
	if(try_times++ > 50)
	{
		CYM_LOG(LV_ERROR, "out of udp port???\n");
		return -1;
	}

	port = (rand() % 35535) + 12000;
	for(i = 0; i < GUESE_PORT_MAX; i++)
	{
		gl_cli_infp.proxy_port[i] = port + i;
		if(tcp_mode)
		{
			if(create_tcp(&gl_cli_infp.proxy_sock[i], 0, htons(gl_cli_infp.proxy_port[i]), 0) < 0)
				goto try_bind;
		}
		else
		{
			if(create_udp(&gl_cli_infp.proxy_sock[i], 0, htons(gl_cli_infp.proxy_port[i])) < 0)
				goto try_bind;
			set_sock_nonblock(gl_cli_infp.proxy_sock[i].fd);
		}
	}

	if(tcp_mode)
	{
		if(tcp_just_connect(gl_cli_infp.proxy_sock[0].fd, gl_cli_infp.server_ip, gl_cli_infp.svr_m_port, 3))
			goto try_bind;
		cli_infp_send_get_tcp_nat_port(&gl_cli_infp.proxy_sock[0], infp, 0, dst_ip, dst_name);
	}
	else
	{
		cli_infp_send_get_nat_port(&gl_cli_infp.proxy_sock[0], infp, 0, dst_ip, dst_name);
		cli_infp_send_get_nat_port(&gl_cli_infp.proxy_sock[1], infp, 1, dst_ip, dst_name);
	}
// 需统计与服务器延迟, 然后在此处进行回应包的收取
	return 0;
}

int cli_infp_do_proxy_ack(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	cJSON* j_value = NULL;
	int tcp_mode = 0;
	char dst_ip[32] = {0};
	char dst_name[32] = {0};
	inf_proxy_t *proxy = NULL;

	j_value = cJSON_GetObjectItem(root, "dst_ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "not dst_ip!\n");
		goto FUNC_OUT;
	}
	snprintf(dst_ip, sizeof(dst_ip), "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "dst_name");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "not dst_ip!\n");
		goto FUNC_OUT;
	}
	snprintf(dst_name, sizeof(dst_name), "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "mode");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "not mode!\n");
		goto FUNC_OUT;
	}
	if(!strcmp(j_value->valuestring, "tcp"))
		tcp_mode = 1;

	proxy = inf_proxy_find_cli(dst_name);
	if (proxy)
	{
		if (proxy->inited)
		{
			// ¸Õ´´½¨2ÃëÄÚ²»ÈÃÖØÁ¬
			if(jiffies - proxy->uptime < 2 * HZ)
				return 0;
		}

		proxy->inited = 1;
	}
	else
	{
		inf_proxy_find_create_cli(dst_name);
	}

FUNC_OUT:
	return cli_infp_get_nat_port(sock, &gl_cli_infp, dst_ip, dst_name, tcp_mode);
}

int cli_infp_send_stun_hello(sock_t* sock, cli_infp_t* infp, __u32 ip, __u16 port)
{
	char send_buf[1024];

	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"name\":\"%s\",\"opt\":\"hello\"}"
					, infp->name
					);

	return cli_infp_send(ip, port, sock, send_buf, len);
}

int cli_infp_send_stun_world(sock_t* sock, cli_infp_t* infp, __u32 ip, __u16 port)
{
	char send_buf[1024];

	int len = snprintf(send_buf, sizeof(send_buf)
		, "{\"name\":\"%s\",\"opt\":\"world\"}"
		, infp->name
	);

	return cli_infp_send(ip, port, sock, send_buf, len);
}

void cli_infp_recv_print(sock_t* sock)
{
	struct sockaddr_in addr;
	// ×Ü»áÊÕ°ü±¨´íµÄ
	while(udp_sock_recv(sock, &addr) > 0)
	{
		memxor(sock->recv_buf, sock->recv_len);
		printf("%s\n",sock->recv_buf);
		memset(sock->recv_buf, 0, sock->recv_buf_len);
		sock->recv_len = 0;
	}
	printf("%d done\n", sock->fd);
}

int cli_infp_recv_udp_accept(sock_t* sock, struct sockaddr_in *addr)
{
	while(udp_sock_recv(sock, addr) > 0)
	{
		printf("[%d] recv sth!\n", sock->fd);
		memset(sock->recv_buf, 0, sock->recv_buf_len);
		sock->recv_len = 0;
		return 1;
	}

	printf("[%d] recv nothing\n", sock->fd);
	return 0;
}

int cli_infp_do_stun_hello(cli_infp_t* infp, int offset, int mode, __u32 ip, __u16 port, int listen, char *ipstr, char *name)
{
	int i = 0;

	if(listen)
	{
		if(mode)
		{
			for(i = 0; i < offset; i++)
			{
				printf("sendto %s:%d\n", IpToStr(ip), port+i);
				cli_infp_send_stun_hello(&infp->proxy_sock[0], infp, ip, htons(port+i));
			}
			cli_infp_send_proxy_task_ack(&infp->main_sock, infp, 3, ipstr, name);
			curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[0]);
			if(curfds < 0)
			{
				return -1;
			}
		}
		else
		{
			for(i = 0; i < offset; i++)
			{
				printf("sendto %s:%d\n", IpToStr(ip), port);
				cli_infp_send_stun_hello(&infp->proxy_sock[i], infp, ip, htons(port));
			}
			cli_infp_send_proxy_task_ack(&infp->main_sock, infp, 3, ipstr, name);
			for(i = 0; i < (offset > GUESE_PORT_MAX ? GUESE_PORT_MAX : offset); i++)
			{
				curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[i]);
				if(curfds < 0)
				{
					return -1;
				}
			}
		}
	}
	else
	{
		if(mode)
		{
			for(i = 0; i < (offset > GUESE_PORT_MAX ? GUESE_PORT_MAX : offset); i++)
			{
				printf("sendto %s:%d\n", IpToStr(ip), port);
				cli_infp_send_stun_hello(&infp->proxy_sock[0], infp, ip, htons(port+i));
			}

			curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[0]);
			if(curfds < 0)
			{
				return -1;
			}
		}
		else
		{
			for(i = 0; i < (offset > GUESE_PORT_MAX ? GUESE_PORT_MAX : offset); i++)
			{
				printf("sendto %s:%d\n", IpToStr(ip), port);
				cli_infp_send_stun_hello(&infp->proxy_sock[i], infp, ip, htons(port));
			}

			for(i = 0; i < (offset > GUESE_PORT_MAX ? GUESE_PORT_MAX : offset); i++)
			{
				curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[i]);
				if(curfds < 0)
				{
					return -1;
				}
			}
		}
	}

	return 0;
}

int cli_infp_do_tcp_stun_hello(cli_infp_t* infp, int offset, int mode, __u32 ip, __u16 port, int listen, char *ipstr, char *name)
{
	int i = 0;
	int ttl = 10;

	// 作服务端的
	if(listen)
	{
		if(mode)
		{
			for(i = 0; i < offset; i++)
			{
				// 第二个端口开始连
				infp_try_connect(gl_cli_infp.ip, IpToStr(ip), infp->proxy_port[1], port+i, ttl);
			}
		}
		else
		{
			for(i = 0; i < offset; i++)
			{
				// 同样第二个端口开连
				infp_try_connect(gl_cli_infp.ip, IpToStr(ip), infp->proxy_port[i+1], port, ttl);
			}
		}

		for(i = 0; i < 4; i++)
		{
			close_sock(&infp->proxy_sock[i]);
		}

		if(mode)
		{
			create_tcp(&infp->proxy_sock[1], 0, 0, 1);
			curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[1]);
			if(curfds < 0)
			{
				return -1;
			}
		}
		else
		{
			for(i = 0; i < offset; i++)
			{
				create_tcp(&infp->proxy_sock[i+1], 0, 0, 1);
				curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[i+1]);
				if(curfds < 0)
				{
					return -1;
				}
			}
		}

		cli_infp_send_proxy_task_ack(&infp->main_sock, infp, 2, ipstr, name);
	}
	else
	{
		// 客户端, 瞎连就完事儿
		if(mode)
		{
			for(i = 0; i < offset; i++)
			{
				if(!tcp_just_connect(infp->proxy_sock[1].fd, ip, htons(port+i), 0))
				{
					curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[1]);
					if(curfds < 0)
					{
						return -1;
					}
				}
			}
		}
		else
		{
			for(i = 0; i < offset; i++)
			{
				if(!tcp_just_connect(infp->proxy_sock[i+1].fd, ip, htons(port), 0))
				{
					curfds = sock_add_poll(poll_arr, INFP_POLL_MAX, &infp->proxy_sock[i+1]);
					if(curfds < 0)
					{
						return -1;
					}
				}
			}
		}
	}

	return 0;
}


int cli_infp_do_proxy_task(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	int mode = -1;
	int offset = 0;
	int listen = 0;
	__u32 ip = 0;
	__u16 port = 0;
	cJSON* j_value;
	char ip_str[32];
	char name[32];

	j_value = cJSON_GetObjectItem(root, "mode");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse mode failed\n");
		goto out;
	}
	mode = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "offset");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse offset failed\n");
		goto out;
	}
	offset = atoi(j_value->valuestring);

	if(offset > 3)
	{
		CYM_LOG(LV_ERROR, "offset [%d] is too big\n", offset);
		goto out;
	}

	j_value = cJSON_GetObjectItem(root, "dst_ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse dst_ip failed\n");
		goto out;
	}
	ip = StrToIp(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "guess_port");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse offset failed\n");
		goto out;
	}
	port = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "main");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse main failed\n");
		goto out;
	}
	listen = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse ip failed\n");
		goto out;
	}
	sprintf(ip_str, "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "name");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse name failed\n");
		goto out;
	}
	sprintf(name, "%s", j_value->valuestring);

	// 尝试打通NAT
	cli_infp_do_stun_hello(&gl_cli_infp, offset, mode, ip, port, listen, ip_str, name);

	ret = 0;
out:
	return ret;
}

int cli_infp_do_proxy_tcp_task(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	int mode = -1;
	int offset = 0;
	__u32 ip = 0;
	__u16 port = 0;
	int listen = 0;
	cJSON* j_value;
	char ip_str[32];
	char name[32];

	j_value = cJSON_GetObjectItem(root, "mode");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse mode failed\n");
		goto out;
	}
	mode = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "offset");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse offset failed\n");
		goto out;
	}
	offset = atoi(j_value->valuestring);

	if(offset > 3)
	{
		CYM_LOG(LV_ERROR, "offset [%d] is too big\n", offset);
		goto out;
	}

	j_value = cJSON_GetObjectItem(root, "dst_ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse dst_ip failed\n");
		goto out;
	}
	ip = StrToIp(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "guess_port");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse guess_port failed\n");
		goto out;
	}
	port = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "main");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse main failed\n");
		goto out;
	}
	listen = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse ip failed\n");
		goto out;
	}
	sprintf(ip_str, "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "name");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse name failed\n");
		goto out;
	}
	sprintf(name, "%s", j_value->valuestring);

	// 尝试打通NAT
	cli_infp_do_tcp_stun_hello(&gl_cli_infp, offset, mode, ip, port, listen, ip_str, name);

	ret = 0;
out:
	return ret;
}


int cli_infp_recv_do(sock_t *sock, struct sockaddr_in *addr)
{
	int ret = -1;

	if(sock->recv_buf && sock->recv_len)
	{
		memxor(sock->recv_buf, sock->recv_len);
		CYM_LOG(LV_DEBUG, "recv [%s]\n", sock->recv_buf);
		cJSON* root = cJSON_Parse((char*)sock->recv_buf);
		if(root)
		{
			cJSON* j_value = cJSON_GetObjectItem(root, "ret");
			if(!j_value || j_value->valueint != 0)
			{
				CYM_LOG(LV_WARNING, "ret error, data:\n%s\n", sock->recv_buf);
				goto next;
			}

			j_value = cJSON_GetObjectItem(root, "cmd");
			if(j_value && j_value->valuestring)
			{
				if(!strcmp(j_value->valuestring, "login_ack"))
					ret = cli_infp_do_login_ack(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "heart_ack"))
					ret = cli_infp_do_heart_ack(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "nat_type_ack"))
					ret = cli_infp_do_nat_type_ack(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "proxy_ack"))
					ret = cli_infp_do_proxy_ack(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "proxy_task"))
					ret = cli_infp_do_proxy_task(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "proxy_tcp_task"))
					ret = cli_infp_do_proxy_tcp_task(root, addr, sock);
				else
				{
					CYM_LOG(LV_WARNING,"unknown cmd [%s]\n", j_value->valuestring);
				}
			}
		next:
			cJSON_Delete(root);
		}
		else
		{
			CYM_LOG(LV_WARNING, "json parse error, data:\n%s\n", sock->recv_buf);
		}
	}

	memset(sock->recv_buf, 0, sock->recv_buf_len);
	sock->recv_len = 0;
	return ret;
}

void edge_try_decode_mac(__u8 *buf, __u32 recv_len, char *name);
int cli_infp_check_ping(__u8 *buf, __u32 recv_len, struct sockaddr_in *addr)
{
	cJSON* root = NULL;
	__u32 now = 0;
	int ping = 0;
	memxor(buf, recv_len);
	root = cJSON_Parse((char*)buf);
	if (root)
	{
		inf_proxy_t *proxy = NULL;
		char name[32] = { 0 };
		char opt[32] = { 0 };
		cJSON* json_value = cJSON_GetObjectItem(root, "name");
		if (json_value && json_value->valuestring)
		{
			snprintf(name, sizeof(name), "%s", json_value->valuestring);
		}
		json_value = cJSON_GetObjectItem(root, "opt");
		if (json_value && json_value->valuestring)
		{
			snprintf(opt, sizeof(opt), "%s", json_value->valuestring);
		}
		cJSON_Delete(root);

		proxy = inf_proxy_find_cli(name);
		if (!proxy)
		{
			CYM_LOG(LV_FATAL, "check ping proxy recv do not found [%s]", name);
			return 1;
		}

		now = jiffies;
		if (now > proxy->uptime + HZ)
			ping = now - proxy->uptime - HZ;
		else
			ping = 1;

		if(ping)
			CYM_LOG(LV_FATAL, "%s ping %d ms\n", IpToStr(proxy->addr.sin_addr.s_addr), ping);
		proxy->uptime = now;
		if (memcmp(&proxy->addr, addr, sizeof(proxy->addr)))
		{
			CYM_LOG(LV_FATAL, "%s:%d changed->", IpToStr(proxy->addr.sin_addr.s_addr), ntohs(proxy->addr.sin_port));
			memcpy(&proxy->addr, addr, sizeof(proxy->addr));
			CYM_LOG(LV_FATAL, "%s:%d\n", IpToStr(proxy->addr.sin_addr.s_addr), ntohs(proxy->addr.sin_port));
		}

		if (!strcmp(opt, "hello"))
		{
			sock_t sock;
			sock.fd = proxy->fd;
			if(!cli_infp_send_stun_world(&sock, &gl_cli_infp, proxy->addr.sin_addr.s_addr, proxy->addr.sin_port))
				inf_proxy_del_cli(proxy);
		}
		else
		{
			proxy->send_count--;
		}
		return 1;
	}

	return 0;
}

int cli_infp_proxy_do(sock_t *sock, struct sockaddr_in *addr)
{
	int ret = -1;

	if(sock->recv_buf && sock->recv_len)
	{
		inf_proxy_t *proxy = NULL;
		int i = 0;
		char name[32] = {0};
		memxor(sock->recv_buf, sock->recv_len);
		CYM_LOG(LV_DEBUG, "recv [%s]\n", sock->recv_buf);
		cJSON* root = cJSON_Parse((char*)sock->recv_buf);
		if(root)
		{
			cJSON* json_value = cJSON_GetObjectItem(root, "name");
			if(json_value && json_value->valuestring)
			{
				snprintf(name, sizeof(name), "%s", json_value->valuestring);
			}
			cJSON_Delete(root);
		}
		else
		{
			CYM_LOG(LV_WARNING, "json parse error\n");
			// »¹Ô­Ò»ÏÂ
			memxor(sock->recv_buf, sock->recv_len);
			CYM_LOG(LV_FATAL, "sock->recv_buf = %02X %02X %02X %02X\n"
				, sock->recv_buf[0], sock->recv_buf[1], sock->recv_buf[2], sock->recv_buf[3]);
			edge_try_decode_mac(sock->recv_buf, sock->recv_len, name);
		}
		
		if (name[0] == 0)
			goto next;

		proxy = inf_proxy_find_cli(name);
		// ²»´æÔÚ->À¬»ø°ü
		if (!proxy)
		{
			CYM_LOG(LV_FATAL, "proxy recv do not found [%s]", name);
			goto next;
		}

		if (proxy)
		{
			memcpy(&proxy->addr, addr, sizeof(proxy->addr));
			proxy->fd = sock->fd;	// fd ½»¸øproxy½Ó¹Ü
			CYM_LOG(LV_FATAL, "p2p fd = %d, poll_i = %d\n", proxy->fd, sock->poll_i);
			sock_del_poll(poll_arr, INFP_POLL_MAX, sock);
			sock->fd = INVALID_SOCKET;
			proxy->uptime = jiffies;
		}

		for (i = 0; i < GUESE_PORT_MAX; i++)
		{
			if (gl_cli_infp.proxy_sock[i].fd > 0)
			{
				sock_del_poll(poll_arr, INFP_POLL_MAX, &gl_cli_infp.proxy_sock[i]);
				close_sock(&gl_cli_infp.proxy_sock[i]);
			}
		}
	}

next:
	memset(sock->recv_buf, 0, sock->recv_buf_len);
	sock->recv_len = 0;
	if(sock->fd == INVALID_SOCKET)
		close_sock(sock);

	ret = 0;
	return ret;
}


/**********n2n*************/
typedef struct n2n_sock
{
    __u8     family;         /* AF_INET or AF_INET6; or 0 if invalid */
    __u16    port;           /* host order */
    union
    {
    __u8     v6[16];  /* byte sequence */
    __u8     v4[4];  /* byte sequence */
    } addr;
} n2n_sock_t;

int inf_proxy_check_exist(void* p_mac, void* p_addr, int* fd, void* real_addr)
{
	inf_proxy_t* proxy = NULL;
	char mac_str[32];
	__u8 *mac = p_mac;
	n2n_sock_t* addr = p_addr;
	n2n_sock_t* new_addr = real_addr;

	snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
		mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

	proxy = inf_proxy_find_cli(mac_str);
	if (proxy)
	{
		//CYM_LOG(LV_FATAL, "found proxy [%s] fd = %d uptime = %d\n", mac_str, proxy->fd, jiffies - proxy->uptime);
		if (proxy->fd > 0)
		{
			if (real_addr)
			{
				proxy->addr.sin_family = new_addr->family;
				proxy->addr.sin_port = htons(new_addr->port);
				memcpy(&proxy->addr.sin_addr.s_addr, new_addr->addr.v4, sizeof(proxy->addr.sin_addr.s_addr));
			}
			addr->family = (__u8)proxy->addr.sin_family;
			addr->port = ntohs(proxy->addr.sin_port);
			memcpy(addr->addr.v4, &proxy->addr.sin_addr.s_addr, sizeof(addr->addr.v4));
			*fd = proxy->fd;
			return 1;
		}
	}
	else
	{
		//CYM_LOG(LV_FATAL, "not found proxy [%s]\n", mac_str);
	}

	return 0;
}

int inf_proxy_check_send(void* p_mac, void* p_addr, int* fd)
{
	inf_proxy_t* proxy = NULL;
	char mac_str[32];
	__u8 *mac = p_mac;
	n2n_sock_t* addr = p_addr;

	snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
	   mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
	   mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

	proxy = inf_proxy_find_cli(mac_str);

	if(proxy)
	{
		if(proxy->fd > 0)
		{
			addr->family = (__u8)proxy->addr.sin_family;
			addr->port = ntohs(proxy->addr.sin_port);
			memcpy(addr->addr.v4, &proxy->addr.sin_addr.s_addr, sizeof(addr->addr.v4));
			*fd = proxy->fd;
			return 1;
		}
		else
		{
			return INVALID_SOCKET;
		}
	}

	if(!proxy)
		proxy = inf_proxy_find_create_cli(mac_str);

	cli_infp_send_proxy_request(&gl_cli_infp.main_sock, &gl_cli_infp, "0.0.0.0", mac_str);
	return 0;
}


