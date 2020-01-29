#ifndef __WORK_H__
#define __WORK_H__

#include "server.h"

void infp_del_cli(infp_cli_t * del);
int infp_recv_do(sock_t * sock, struct sockaddr_in * addr);
int infp_poll_run(int timeout);
int infp_svr_init(void);


#endif

