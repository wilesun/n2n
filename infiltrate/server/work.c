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


void memxor(char* data, int len)
{
	int i = 0;
	for(i = 0; i < len; i++)
		data[i] ^= 0x71;
}

void inf_get_fds(int* fds, int* fd_num)
{
	int fd_nums = 0;
	*fd_num = 0;

	fds[fd_nums++] = gl_infp.main_sock.fd;
	fds[fd_nums++] = gl_infp.back_sock.fd;

	*fd_num = fd_nums;
}

int infp_server_send(infp_cli_t *cli, sock_t* sock, char *data, int len)
{
	struct sockaddr_in addr;
	int socklen = sizeof(addr);

	set_sockaddr_in(&addr, cli->nat_ip, htons(cli->main_port.nat_port));
	CYM_LOG(LV_DEBUG, "send to %s:%d\n", IpToStr(cli->nat_ip), cli->main_port.nat_port);
	CYM_LOG(LV_DEBUG, "send [%s]\n", data);
	memxor(data, len);

	return sendto(gl_infp.main_sock.fd, data, len, 0, (struct sockaddr*)&addr, socklen);
}

static inline struct hlist_head* infp_get_hash_head(char *str)
{
	return &gl_infp.dev_hash[(SDBMHash(str) & INFP_HASH_MASK)];
}

void infp_del_cli(infp_cli_t* del)
{
	if(del)
	{
		CYM_LOG(LV_INFO, "[%s:%s] offline\n", del->ip, del->name);

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
					, char *mode, char *name, struct sockaddr_in *addr)
{
	snprintf(cli->ip, sizeof(cli->ip), "%s", ip);
	cli->main_port.src_port = port;
	cli->main_port.nat_port = ntohs(addr->sin_port);
	cli->mode = cli_parse_mode(mode);
	snprintf(cli->name, sizeof(cli->name), "%s", name);
	cli->nat_ip = addr->sin_addr.s_addr;
	cli->uptime = jiffies;
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

int cli_send_proxy_ack(infp_cli_t* cli, infp_cli_t* dst, sock_t *sock, int ret, const char *msg)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					,"{\"cmd\":\"proxy_ack\",\"ret\":%d,\"msg\":\"%s\",\"dst_ip\":\"%s\",\"dst_name\":\"%s\"}"
					, ret, msg, dst ? dst->ip : "", dst ? dst->name : ""
					);

	memset(cli->guess, 0, sizeof(cli->guess));
	cli->guess_port = 0;

	return infp_server_send(cli, sock, send_buf, len);
}

int cli_send_proxy_task(infp_cli_t* cli, sock_t *sock, infp_cli_t* dst, int mode)
{
	char send_buf[1024];
	int len = snprintf(send_buf, sizeof(send_buf)
					,"{\"cmd\":\"proxy_task\",\"dst_ip\":\"%s\",\"guess_port\":\"%d\""
					",\"mode\":\"%d\",\"offset\":\"%d\",\"ret\":0}"
					, IpToStr(dst->nat_ip)
					, dst->guess_port
					, mode
					, GUESE_PORT_MAX
					);

	return infp_server_send(cli, sock, send_buf, len);
	
}

int infp_do_login(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	char ip[32];
	int port;
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

	init_cli_info(cli, ip, port, mode, name, addr);

	cli_send_login_ack(cli, sock);
	ret = 0;
out:
	return ret;
}

int infp_do_heart_beat(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
{
	int ret = -1;
	infp_cli_t *cli;

	#if 0
	int connected;
	cJSON* j_value;
	j_value = cJSON_GetObjectItem(root, "connected");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse connected failed\n");
		goto out;
	}
	connected = atoi(j_value->valuestring);
	#endif

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}

	cli->uptime = jiffies;
	//cli->connected = connected;
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

int infp_do_proxy_request(cJSON* root, struct sockaddr_in *addr, sock_t *sock)
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

	dst = infp_find_cli_json(root, 1);
	if(!dst)
	{
		cli_send_proxy_ack(cli, dst, sock, 1, "not found");
	}
	else
	{
		// TODO: same nat ip support
		if(cli->nat_ip != dst->nat_ip)
		{
			cli_send_proxy_ack(cli, dst, sock, 0, "ok");
			cli_send_proxy_ack(dst, cli, sock, 0, "ok");
		}
		else
		{
			cli_send_proxy_ack(cli, dst, sock, 1, "same nat ip");
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
		CYM_LOG(LV_INFO, "0:%d->%d, 1:%d->%d, guess: %d\n"
			, cli->guess[0].src_port, cli->guess[0].nat_port
			, cli->guess[1].src_port, cli->guess[1].nat_port
			, cli->guess_port);
	}
	else
	{
		CYM_LOG(LV_INFO, "0:%d->%d, 1:%d->%d, do not guess\n"
			, cli->guess[0].src_port, cli->guess[0].nat_port
			, cli->guess[1].src_port, cli->guess[1].nat_port);
		cli->guess_port = cli->guess[0].nat_port;
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
			if(cli->nat_type == SYMMETRICAL_NAT_TYPE && dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_task(cli, sock, dst, 1);
				cli_send_proxy_task(dst, sock, cli, 0);
			}
			else if(cli->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_task(cli, sock, dst, 0);
				cli_send_proxy_task(dst, sock, cli, 1);
			}
			else if(dst->nat_type == SYMMETRICAL_NAT_TYPE)
			{
				cli_send_proxy_task(cli, sock, dst, 1);
				cli_send_proxy_task(dst, sock, cli, 0);
			}
			else
			{
				cli_send_proxy_task(cli, sock, dst, 0);
				cli_send_proxy_task(dst, sock, cli, 0);
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
	infp_cli_t *cli;

	cli = infp_find_cli_json(root, 0);
	if(!cli)
	{
		CYM_LOG(LV_WARNING, "find cli failed\n");
		goto out;
	}
	cli->uptime = jiffies;

	j_value = cJSON_GetObjectItem(root, "ret");
	if(!j_value || !j_value->valuestring)
	{
		CYM_LOG(LV_ERROR, "parse num failed\n");
		goto out;
	}
	j_ret = atoi(j_value->valuestring);

	if(j_ret)
		CYM_LOG(LV_INFO, "成了\n");
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
		cJSON* root = cJSON_Parse(sock->recv_buf);
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
					ret = infp_do_proxy_request(root, addr, sock);
				else if(!strcmp(j_value->valuestring, "get_nat_port"))
					ret = infp_do_get_nat_port(root, addr, sock);
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

