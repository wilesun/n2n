#ifndef __WORK_H__
#define __WORK_H__

#include "client.h"

int cli_infp_send_login(sock_t* sock, cli_infp_t* infp);
int cli_infp_send_heart(sock_t* sock, cli_infp_t* infp);
int cli_infp_recv_do(sock_t *sock, struct sockaddr_in *addr);
int cli_infp_proxy_do(sock_t *sock, struct sockaddr_in *addr);
void cli_infp_check_proxy_list(void);

int cli_infp_send_stun_hello(sock_t* sock, cli_infp_t* infp, __u32 ip, __u16 port);
int infp_cli_init(const char *sn_addr, __u8 *device_mac, __u32 tcp_ip, __u32 allow_p2p);
int cli_infp_check_ping(__u8 *buf, __u32 recv_len, struct sockaddr_in *addr);
int inf_proxy_check_exist(void* p_mac, void* p_addr, int* fd, void* real_addr);
void inf_proxy_del_cli_by_fd(int fd);
int inf_proxy_check_send(void* p_mac, void* p_addr, int* fd);
void inf_proxy_get_fds(int* fds, int* fd_num);
void inf_get_fds(int* fds, int* fd_num);
int infp_poll_run(int timeout);

#endif

