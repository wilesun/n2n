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

#include "work.h"

#include "debug.h"
#include "mem.h"
#include "cJSON.h"

#define INFP_NO_OFFSET 1
#define INFP_DEF_OFFSET 3

void memxor(unsigned char* data, int len)
{
	int i = 0;
	for(i = 0; i < len; i++)
		data[i] ^= 0x71;
}

void inf_get_fds(int* fds, int* fd_num)
{
	int fd_nums = 0, i;
	*fd_num = 0;

	for(i = 0; i < INFP_POLL_MAX; i++)
	{
		if(poll_arr[i].fd > 0)
			fds[fd_nums++] = poll_arr[i].fd;
	}

	*fd_num = fd_nums;
}

int infp_server_send(infp_cli_t *cli, sock_t* sock, char *data, int len)
{
	struct sockaddr_in addr;
	int socklen = sizeof(addr);

	set_sockaddr_in(&addr, cli->nat_ip, htons(cli->main_port.nat_port));
	CYM_LOG(LV_DEBUG, "send to %s:%d\n", IpToStr(cli->nat_ip), cli->main_port.nat_port);
	CYM_LOG(LV_DEBUG, "send [%s]\n", data);
	memxor((__u8*)data, len);

	return sendto(gl_infp.main_sock.fd, data, len, 0, (struct sockaddr*)&addr, socklen);
}

static inline struct hlist_head* infp_get_hash_head(char *str)
{
	return &gl_infp.dev_hash[(SDBMHash(str) & INFP_HASH_MASK)];
}

void infp_del_cli_des(infp_cli_des_t* del)
{
	if(del)
	{
		list_del(&del->list_to);
		mem_free(del);
	}
}

void infp_clear_cli_des(struct list_head* list)
{
	struct list_head *pos, *n;
	infp_cli_des_t *temp;

	list_for_each_safe(pos, n, list)
	{
		temp = list_entry(pos, infp_cli_des_t, list_to);
		infp_del_cli_des(temp);
	}
}

infp_cli_des_t *infp_create_cli_des(char *str, struct list_head* list)
{
	infp_cli_des_t *temp = mem_malloc(sizeof(infp_cli_des_t));
	if(temp)
	{
		list_add_tail(&temp->list_to, list);

		snprintf(temp->des, sizeof(temp->des), "%s", str);
	}

	return temp;
}

infp_cli_des_t *infp_find_cli_des(char *str, struct list_head* list)
{
	struct list_head *pos, *n;
	infp_cli_des_t *temp;

	list_for_each_safe(pos, n, list)
	{
		temp = list_entry(pos, infp_cli_des_t, list_to);
		// 5秒以上, 删了再说
		if(jiffies - temp->uptime > 5 * HZ)
		{
			infp_del_cli_des(temp);
		}
		else if(!strcmp(temp->des, str))
		{
			return temp;
		}
	}

	return NULL;
}

infp_cli_des_t *infp_find_create_cli_des(char *str, struct list_head* list)
{
	infp_cli_des_t *temp = infp_find_cli_des(str, list);
	if(temp)
		return temp;

	return infp_create_cli_des(str, list);
}


void infp_del_cli(infp_cli_t* del)
{
	if(del)
	{
		CYM_LOG(LV_INFO, "[%s:%s] offline\n", del->ip, del->name);

		infp_clear_cli_des(&del->p2p_list);

		list_del(&del->list_to);
		hlist_del(&del->hash_to);
		mem_free(del);
	}
}

infp_cli_t *infp_create_cli(char *str)
{
	infp_cli_t *temp = mem_malloc(sizeof(infp_cli_t));
	if(temp)
	{
		INIT_LIST_HEAD(&temp->p2p_list);
		list_add_tail(&temp->list_to, &gl_infp.dev_list);
		hlist_add_head(&temp->hash_to, infp_get_hash_head(str));

		snprintf(temp->des, sizeof(temp->des), "%s", str);
	}

	return temp;
}

infp_cli_t *infp_find_cli(char *str)
{
	struct hlist_node *pos;
	infp_cli_t *temp;

	hlist_for_each(pos, infp_get_hash_head(str))
	{
		temp = hlist_entry(pos, infp_cli_t, hash_to);
		if(!strcmp(temp->des, str))
		{
			return temp;
		}
	}

	return NULL;
}

infp_cli_t *infp_find_create_cli(char *str)
{
	infp_cli_t *temp = infp_find_cli(str);
	if(temp)
		return temp;

	return infp_create_cli(str);
}

infp_cli_t *infp_find_cli_json(cJSON *root, int dst)
{
	char ip[32];
	char name[32];
	char des[64];	// ip + name
	cJSON *j_value;

	const char* ip_key = "ip";
	const char* name_key = "name";
	if(dst)
	{
		ip_key = "dst_ip";
		name_key = "dst_name";
	}

	j_value = cJSON_GetObjectItem(root, ip_key);
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse ip failed\n");
		return NULL;
	}
	snprintf(ip, sizeof(ip), "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, name_key);
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse name failed\n");
		return NULL;
	}
	snprintf(name, sizeof(name), "%s", j_value->valuestring);

	snprintf(des, sizeof(des), "%s%s", ip, name);

	return infp_find_cli(des);
}


int cli_parse_mode(char *mode)
{
	if(!strcmp(mode, "host"))
		return 1;

	return 0;
}

void init_cli_info(infp_cli_t *cli, char *ip, int port
					, char *mode, char *name, struct sockaddr_in *addr, int allow_tcp)
{
	snprintf(cli->ip, sizeof(cli->ip), "%s", ip);
	cli->main_port.src_port = port;
	cli->main_port.nat_port = ntohs(addr->sin_port);
	cli->mode = cli_parse_mode(mode);
	snprintf(cli->name, sizeof(cli->name), "%s", name);
	cli->nat_ip = addr->sin_addr.s_addr;
	cli->uptime = jiffies;
	cli->allow_tcp = allow_tcp;
}

int cli_send_login_ack(infp_cli_t* cli, sock_t *sock)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf), "{\"cmd\":\"login_ack\",\"next_hb\":60,\"ret\":0,\"msg\":\"ok\"}");

	return infp_server_send(cli, sock, send_buf, len);
}

int cli_send_heart_ack(infp_cli_t* cli, sock_t *sock)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf), "{\"cmd\":\"heart_ack\",\"next_hb\":60,\"ret\":0,\"msg\":\"ok\"}");

	return infp_server_send(cli, sock, send_buf, len);
}

int cli_send_nat_type_ack(infp_cli_t* cli, sock_t *sock, __u16 port)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					, "{\"cmd\":\"nat_type_ack\",\"ip\":\"%s\",\"port\":\"%d\","
					"\"type\":\"%d\",\"ret\":0,\"msg\":\"ok\"}"
					, IpToStr(cli->nat_ip)
					, port, cli->nat_type
					);

	return infp_server_send(cli, sock, send_buf, len);
}

// mode: 0:udp 1:tcp
int cli_send_proxy_ack(infp_cli_t* cli, infp_cli_t* dst, sock_t *sock, int ret, const char *msg, int mode)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					,"{\"cmd\":\"proxy_ack\",\"ret\":%d,\"msg\":\"%s\","
					"\"dst_ip\":\"%s\",\"dst_name\":\"%s\",\"mode\":\"%s\"}"
					, ret, msg, dst ? dst->ip : "", dst ? dst->name : ""
					, mode ? "tcp" : "udp"
					);

	if(mode == 0)
	{
		memset(cli->guess, 0, sizeof(cli->guess));
		cli->guess_port = 0;
		cli->guess_tcp = 0;
	}
	else
	{
		cli->nat_tcp = 0;
	}

	return infp_server_send(cli, sock, send_buf, len);
}

// mode: 0:自身是固定端口, 对端端口自增, 1:自身端口自增, 对端端口固定
// offset: 自增次数(越大,命中率越高,但容易被防火墙拦截, 为1表示不用自增, 1以下无意义)
int cli_send_proxy_task(infp_cli_t* cli, sock_t *sock, infp_cli_t* dst, int mode, int offset, int main)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					,"{\"cmd\":\"proxy_task\",\"dst_ip\":\"%s\",\"ip\":\"%s\",\"name\":\"%s\""
					",\"guess_port\":\"%d\",\"mode\":\"%d\",\"offset\":\"%d\",\"ret\":0"
					",\"main\":\"%d\"}"
					, IpToStr(dst->nat_ip)
					, dst->ip
					, dst->name
					, dst->guess_port
					, mode
					, offset
					, main
					);

	return infp_server_send(cli, sock, send_buf, len);
}

// 其余参数见↑
// main: 1:修改ttl并listen, 0:对端已准备好,请直接connect
int cli_send_proxy_tcp_task(infp_cli_t* cli, sock_t *sock, infp_cli_t* dst, int mode, int offset, int main)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					,"{\"cmd\":\"proxy_tcp_task\",\"dst_ip\":\"%s\",\"ip\":\"%s\",\"name\":\"%s\""
					",\"guess_port\":\"%d\",\"mode\":\"%d\",\"offset\":\"%d\",\"ret\":0"
					",\"main\":\"%d\"}"
					, IpToStr(dst->nat_ip)
					, dst->ip
					, dst->name
					, dst->guess_port
					, mode
					, offset
					, main
					);

	return infp_server_send(cli, sock, send_buf, len);
}


int infp_do_login(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	char ip[32];
	int port;
	int allow_tcp;
	char mode[16];
	char name[32];
	char des[64];	// ip + name
	cJSON* j_value;
	infp_cli_t *cli;

	j_value = cJSON_GetObjectItem(root, "ip");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse ip failed\n");
		goto out;
	}
	snprintf(ip, sizeof(ip), "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "port");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse port failed\n");
		goto out;
	}
	port = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "allow_tcp");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse allow_tcp failed\n");
		allow_tcp = 0;
	}
	else
	{
		allow_tcp = atoi(j_value->valuestring);
	}

	j_value = cJSON_GetObjectItem(root, "mode");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse mode failed\n");
		goto out;
	}
	snprintf(mode, sizeof(mode), "%s", j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "name");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse name failed\n");
		goto out;
	}
	snprintf(name, sizeof(name), "%s", j_value->valuestring);

	snprintf(des, sizeof(des), "%s%s", ip, name);
	cli = infp_find_create_cli(des);
	if(!cli)
	{
		CYM_LOG(LV_FATAL, "find create cli failed\n");
		goto out;
	}

	init_cli_info(cli, ip, port, mode, name, addr, allow_tcp);

	cli_send_login_ack(cli, sock);
	ret = 0;
out:
	return ret;
}

int infp_do_heart_beat(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	infp_cli_t *cli;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}

	cli->uptime = jiffies;
	cli_send_heart_ack(cli, sock);
	ret = 0;
out:
	return ret;
}

int infp_do_get_nat_type(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	int port;
	infp_cli_t *cli;

	if(sock->fd != gl_infp.back_sock.fd)
	{
		CYM_LOG(LV_ERROR, "wrong destination packet\n");
		goto out;
	}

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}

	port = ntohs(addr->sin_port);

	cli->uptime = jiffies;
	if(cli->main_port.nat_port == port)
	{
		if(cli->nat_ip == StrToIp(cli->ip))
			cli->nat_type = NIUBILITY_NAT_TYPE;
		else
			cli->nat_type = CONE_NAT_TYPE;
	}
	else
	{
		cli->nat_type = SYMMETRICAL_NAT_TYPE;
	}

	cli_send_nat_type_ack(cli, sock, port);
	ret = 0;
out:
	return ret;
}

int infp_do_proxy_request(cJSON* root, struct sockaddr_in *addr, sock_t *sock, int mode)
{
	int ret = -1;
	infp_cli_t *cli, *dst;
	infp_cli_des_t *cli_des, *dst_des;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}
	cli->uptime = jiffies;

	dst = infp_find_cli_json(root, 1);
	if(!dst)
	{
		cli_send_proxy_ack(cli, dst, sock, 1, "not found", mode);
	}
	else
	{
		// TODO: 记录请求, 5秒仅回一次
		cli_des = infp_find_create_cli_des(cli->des, &dst->p2p_list);
		dst_des = infp_find_create_cli_des(dst->des, &cli->p2p_list);
		if(cli_des && dst_des)
		{
			if(!cli_des->uptime && !dst_des->uptime)
			{
				cli_send_proxy_ack(cli, dst, sock, 0, "ok", mode);
				cli_send_proxy_ack(dst, cli, sock, 0, "ok", mode);

				cli_des->uptime = dst_des->uptime = jiffies;
			}
			else
			{
				CYM_LOG(LV_WARNING, "[%s] & [%s] already do proxy\n", cli_des->des, dst_des->des);
			}
		}
	}

	ret = 0;
out:
	return ret;
}

void infp_guess_port(infp_cli_t *cli)
{
	// TODO: UNKNOWN_NAT_TYPE
	if(cli->nat_type == SYMMETRICAL_NAT_TYPE)
	{
		// TODO: 除了等差数列, 还要支持别的
		int temp = (int)((int)cli->guess[1].nat_port - (int)cli->guess[0].nat_port);
		cli->guess_port = cli->guess[1].nat_port + (temp * 2);	// TODO: optmize
		cli->guess_tcp = (temp*2);
		CYM_LOG(LV_INFO, "0: %d, 1: %d, guess: %d\n"
			, cli->guess[0].nat_port, cli->guess[1].nat_port, cli->guess_port);
	}
	else
	{
		cli->guess_port = cli->guess[0].nat_port;
		cli->guess_tcp = 1;
	}
}

int infp_do_get_nat_port(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	cJSON* j_value;
	infp_cli_t *cli, *dst;
	int num = -1;
	int port = 0;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}
	cli->uptime = jiffies;

	j_value = cJSON_GetObjectItem(root, "port");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse port failed\n");
		goto out;
	}
	port = atoi(j_value->valuestring);

	j_value = cJSON_GetObjectItem(root, "num");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse num failed\n");
		goto out;
	}
	num = atoi(j_value->valuestring);

	cli->guess[num].src_port = port;
	cli->guess[num].nat_port = ntohs(addr->sin_port);

	dst = infp_find_cli_json(root, 1);
	if(!dst)
	{
		CYM_LOG(LV_WARNING, "find dst cli failed\n");
		goto out;
	}

	if(cli->guess[0].src_port && cli->guess[1].src_port)
	{
		infp_guess_port(cli);
		if(dst->guess_port)
		{
			if(cli->allow_tcp && dst->allow_tcp)
			{
				cli_send_proxy_ack(cli, dst, sock, 0, "ok", 1);
				cli_send_proxy_ack(dst, cli, sock, 0, "ok", 1);
			}
			else
			{
				if(cli->nat_type == SYMMETRICAL_NAT_TYPE && dst->nat_type == SYMMETRICAL_NAT_TYPE)
				{
					cli_send_proxy_task(cli, sock, dst, 1, INFP_DEF_OFFSET, 1);
					//cli_send_proxy_task(dst, sock, cli, 0, INFP_DEF_OFFSET);
				}
				else if(cli->nat_type == SYMMETRICAL_NAT_TYPE)
				{
					//cli_send_proxy_task(cli, sock, dst, 0, INFP_DEF_OFFSET);
					cli_send_proxy_task(dst, sock, cli, 1, INFP_DEF_OFFSET, 1);
				}
				else if(dst->nat_type == SYMMETRICAL_NAT_TYPE)
				{
					cli_send_proxy_task(cli, sock, dst, 1, INFP_DEF_OFFSET, 1);
					//cli_send_proxy_task(dst, sock, cli, 0, INFP_DEF_OFFSET);
				}
				else
				{
					cli_send_proxy_task(cli, sock, dst, 0, INFP_NO_OFFSET, 1);
					//cli_send_proxy_task(dst, sock, cli, 0, INFP_NO_OFFSET);
				}
			}
		}
	}

	ret = 0;
out:
	return ret;
}

int infp_do_get_tcp_nat_port(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	infp_cli_t *cli, *dst;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}

	cli->uptime = jiffies;
	cli->nat_tcp = ntohs(sock->addr.sin_port);

	dst = infp_find_cli_json(root, 1);
	if(!dst)
	{
		CYM_LOG(LV_WARNING, "find dst cli failed\n");
		goto out;
	}

	if(cli->nat_tcp)
	{
		cli->guess_port = cli->guess_tcp + cli->nat_tcp;	// tcp猜测端口
		if(dst->nat_tcp)
		{
			// 优先反向打洞(1.非对称 syn -> 对称 2.非对称listen 3.对称 syn -> 非对称)
			// 此处处理1
			if(cli->nat_type == SYMMETRICAL_NAT_TYPE && dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_tcp_task(cli, sock, dst, 1, INFP_DEF_OFFSET, 1);
			}
			else if(cli->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_tcp_task(dst, sock, cli, 1, INFP_DEF_OFFSET, 1);
			}
			else if(dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_tcp_task(cli, sock, dst, 1, INFP_DEF_OFFSET, 1);
			}
			else
			{
				cli_send_proxy_tcp_task(cli, sock, dst, 0, INFP_NO_OFFSET, 1);
			}
		}
	}

	ret = 0;
out:
	return ret;
}

int infp_do_proxy_task_ack(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	int j_ret = 0;
	cJSON* j_value;
	infp_cli_t *cli, *dst;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}
	cli->uptime = jiffies;

	dst = infp_find_cli_json(root, 1);
	if(!dst)
	{
		CYM_LOG(LV_WARNING, "find dst cli failed\n");
		goto out;
	}

	j_value = cJSON_GetObjectItem(root, "ret");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse num failed\n");
		goto out;
	}
	j_ret = atoi(j_value->valuestring);

	if(j_ret)
	{
		if(j_ret == 2)
		{
			CYM_LOG(LV_INFO, "成了一半\n");
			// 优先反向打洞(1.非对称 syn -> 对称 2.非对称listen 3.对称 syn -> 非对称)
			// 此处处理3
			if(cli->nat_type == SYMMETRICAL_NAT_TYPE || dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_tcp_task(dst, sock, cli, 0, INFP_DEF_OFFSET, 0);
			}
			else
			{
				cli_send_proxy_tcp_task(dst, sock, cli, 0, INFP_NO_OFFSET, 0);
			}
		}
		else if(j_ret == 3)
		{
			CYM_LOG(LV_INFO, "成了一半\n");
			// 优先反向打洞(1.非对称 syn -> 对称 2.非对称listen 3.对称 syn -> 非对称)
			// 此处处理3
			if(cli->nat_type == SYMMETRICAL_NAT_TYPE || dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_task(dst, sock, cli, 0, INFP_DEF_OFFSET, 0);
			}
			else
			{
				cli_send_proxy_task(dst, sock, cli, 0, INFP_NO_OFFSET, 0);
			}
		}
		else
		{
			CYM_LOG(LV_INFO, "成了\n");
		}
	}
	else
	{
		j_value = cJSON_GetObjectItem(root, "msg");
		if(j_value && j_value->valuestring)
			CYM_LOG(LV_ERROR, "proxy failed [%s]\n", j_value->valuestring);
		else
			CYM_LOG(LV_ERROR, "proxy failed\n");
	}

	ret = 0;
out:
	return ret;
}

int infp_recv_do(sock_t *sock, struct sockaddr_in *addr)
{
	int ret = -1;

	if(sock->recv_buf && sock->recv_len)
	{
		memxor(sock->recv_buf, sock->recv_len);
		CYM_LOG(LV_DEBUG, "recv [%s]\n", sock->recv_buf);
		cJSON* root = cJSON_Parse((char*)sock->recv_buf);
		if(root)
		{
			cJSON* j_value;
			j_value = cJSON_GetObjectItem(root, "cmd");
			if(j_value && j_value->valuestring)
			{
				if(!strcmp(j_value->valuestring, "login"))
					ret = infp_do_login(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "heart_beat"))
					ret = infp_do_heart_beat(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "get_nat_type"))
					ret = infp_do_get_nat_type(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "proxy_request"))
					ret = infp_do_proxy_request(root, addr, sock, 0);	// 默认先让走udp
				else if(!strcmp(j_value->valuestring, "get_nat_port"))
					ret = infp_do_get_nat_port(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "get_tcp_nat_port"))
					ret = infp_do_get_tcp_nat_port(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "proxy_task_ack"))
					ret = infp_do_proxy_task_ack(root, addr, sock);
				else
				{
					CYM_LOG(LV_WARNING,"unknown cmd [%s]\n", j_value->valuestring);
				}
			}

			cJSON_Delete(root);
		}
	}

	memset(sock->recv_buf, 0, sock->recv_buf_len);
	sock->recv_len = 0;
	return ret;
}

