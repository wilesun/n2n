/**
 * (C) 2007-18 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "../n2n.h"

#ifdef __ANDROID_NDK__
#include "edge_android.h"
#include <tun2tap/tun2tap.h>

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

typedef struct n2n_priv_config {
  char                tuntap_dev_name[N2N_IFNAMSIZ];
  char                ip_mode[N2N_IF_MODE_SIZE];
  char                ip_addr[N2N_NETMASK_STR_SIZE];
  char                netmask[N2N_NETMASK_STR_SIZE];
  char                device_mac[N2N_MACNAMSIZ];
  int                 mtu;
} n2n_priv_config_t;


/* *************************************************** */

#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */

static char gratuitous_arp[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest mac */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x08, 0x06, /* ARP */
  0x00, 0x01, /* Ethernet */
  0x08, 0x00, /* IP */
  0x06, /* Hw Size */
  0x04, /* Protocol Size */
  0x00, 0x01, /* ARP Request */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x00, 0x00, 0x00, 0x00, /* Src IP */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target mac */
  0x00, 0x00, 0x00, 0x00 /* Target IP */
};

/* ************************************** */

/** Build a gratuitous ARP packet for a /24 layer 3 (IP) network. */
static int build_gratuitous_arp(char *buffer, uint16_t buffer_len) {
  if(buffer_len < sizeof(gratuitous_arp)) return(-1);

  memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
  memcpy(&buffer[6], device.mac_addr, 6);
  memcpy(&buffer[22], device.mac_addr, 6);
  memcpy(&buffer[28], &device.ip_addr, 4);

  /* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
   * for /24 IPv4 networks. */
  buffer[31] = 0xFF; /* Use a faked broadcast address */
  memcpy(&buffer[38], &device.ip_addr, 4);
  return(sizeof(gratuitous_arp));
}

/* ************************************** */

/** Called from update_supernode_reg to periodically send gratuitous ARP
 *  broadcasts. */
static void send_grat_arps(n2n_edge_t * eee,) {
  char buffer[48];
  size_t len;

  traceEvent(TRACE_NORMAL, "Sending gratuitous ARP...");
  len = build_gratuitous_arp(buffer, sizeof(buffer));
  send_packet2net(eee, buffer, len);
  send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}

#endif /* #if defined(DUMMY_ID_00001) */

/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.
 *
 *  ip_add and ip_mode are NULL terminated if modified.
 *
 *  return 0 on success and -1 on error
 */
static int scan_address(char * ip_addr, size_t addr_size,
			char * ip_mode, size_t mode_size,
			const char * s) {
  int retval = -1;
  char * p;

  if((NULL == s) || (NULL == ip_addr))
    {
      return -1;
    }

  memset(ip_addr, 0, addr_size);

  p = strpbrk(s, ":");

  if(p)
    {
      /* colon is present */
      if(ip_mode)
        {
	  size_t end=0;

	  memset(ip_mode, 0, mode_size);
	  end = MIN(p-s, (ssize_t)(mode_size-1)); /* ensure NULL term */
	  strncpy(ip_mode, s, end);
	  strncpy(ip_addr, p+1, addr_size-1); /* ensure NULL term */
	  retval = 0;
        }
    }
  else
    {
      /* colon is not present */
      strncpy(ip_addr, s, addr_size);
    }

  return retval;
}

/* *************************************************** */
int locaFromCMD(n2n_edge_conf_t* conf, n2n_priv_config_t* ec, const n2n_edge_cmd_t* cmd)
{
	int ret = -1;
	int i;
	char ip_mode[N2N_IF_MODE_SIZE]="static";
	char ip_addr[N2N_NETMASK_STR_SIZE] = "";
	char netmask[N2N_NETMASK_STR_SIZE]="255.255.255.0";

	if (cmd->enc_key)
	{
	    conf->encrypt_key = strdup(cmd->enc_key);
	    traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", cmd->enc_key);
	}

	if (cmd->ip_addr[0] != '\0')
	{
	    scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
	                 ip_mode, N2N_IF_MODE_SIZE,
	                 cmd->ip_addr);
	}
	else
	{
	    traceEvent(TRACE_ERROR, "Ip address is not set.");
	    goto out;
	}

	if (cmd->ip_netmask[0] != '\0')
	{
	    strncpy(netmask, cmd->ip_netmask, N2N_NETMASK_STR_SIZE);
	}

	snprintf(ec->ip_addr, sizeof(ec->ip_addr), "%s", ip_addr);
	snprintf(ec->ip_mode, sizeof(ec->ip_mode), "%s", ip_mode);
	snprintf(ec->netmask, sizeof(ec->netmask), "%s", netmask);

	if (cmd->community[0] != '\0')
	{
	    strncpy((char *)conf->community_name, cmd->community, N2N_COMMUNITY_SIZE);
	}
	else
	{
	    traceEvent(TRACE_ERROR, "Community is not set.");
	    goto out;
	}

	conf->drop_multicast = cmd->drop_multicast == 0 ? 0 : 1;
	if (cmd->mac_addr[0] != '\0')
	{
	    strncpy(ec->device_mac, cmd->mac_addr, N2N_MACNAMSIZ);
	}

	conf->allow_routing = cmd->allow_routing == 0 ? 0 : 1;
	for (i = 0; i < N2N_EDGE_NUM_SUPERNODES && i < EDGE_CMD_SUPERNODES_NUM; ++i)
	{
	    if (cmd->supernodes[i][0] != '\0')
	    {
	        strncpy(conf->sn_ip_array[conf->sn_num], cmd->supernodes[i], N2N_EDGE_SN_HOST_SIZE);
	        traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s\n"
				, (unsigned int)conf->sn_num, (conf->sn_ip_array[conf->sn_num]));
	        ++conf->sn_num;
	    }
	}

	ec->mtu = cmd->mtu;

	ret = 0;
out:
	if(ret < 0)
	{
		if(conf->encrypt_key)
			free(conf->encrypt_key);
	}

	return ret;
}

int start_edge(const n2n_edge_cmd_t* cmd)
{
	int keep_on_running = 0;
	int trace_level = 0;
	int rc;
	int local_port = 0 /* any port */;
	char tuntap_dev_name[N2N_IFNAMSIZ] = "tun0";
	char device_mac[N2N_MACNAMSIZ]="";

	tuntap_dev tuntap;    /* a tuntap device */
	n2n_edge_t *eee;      /* single instance for this program */
	n2n_edge_conf_t conf; /* generic N2N edge config */
	n2n_priv_config_t ec; /* config used for standalone program execution */

	keep_on_running = 0;
	pthread_mutex_lock(&status.mutex);
	status.is_running = keep_on_running;
	pthread_mutex_unlock(&status.mutex);
	report_edge_status();

	if (!cmd) {
		traceEvent( TRACE_ERROR, "Empty cmd struct" );
		return 1;
	}

	trace_level = cmd->trace_vlevel;
	trace_level = trace_level < 0 ? 0 : trace_level;   /* TRACE_ERROR */
	trace_level = trace_level > 4 ? 4 : trace_level;   /* TRACE_DEBUG */
	setTraceLevel(trace_level);

	/* Random seed */
	srand(time(NULL));

	/* Defaults */
	edge_init_conf_defaults(&conf);
	memset(&ec, 0, sizeof(ec));
	ec.mtu = DEFAULT_MTU;

	snprintf(ec.tuntap_dev_name, sizeof(ec.tuntap_dev_name), "%s", tuntap_dev_name);

	if (cmd->vpn_fd < 0) {
	    traceEvent(TRACE_ERROR, "VPN socket is invalid.");
	    return 1;
	}
	tuntap.fd = cmd->vpn_fd;

	if(locaFromCMD(&conf, &ec, cmd) < 0) {
		traceEvent(TRACE_ERROR, "locaFromCMD failed.");
		return 1;
	}

	if(edge_verify_conf(&conf) != 0) {
		traceEvent(TRACE_ERROR, "edge_verify_conf failed.");
		return 1;
	}


	traceEvent(TRACE_NORMAL, "Starting n2n edge %s %s", PACKAGE_VERSION, PACKAGE_BUILDDATE);

	/* Random seed */
	srand(time(NULL));

	if(0 == strcmp("dhcp", ec.ip_mode)) {
		traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");

		conf.dyn_ip_mode = 1;
	} else
		traceEvent(TRACE_NORMAL, "ip_mode='%s'", ec.ip_mode);

	if(!(
#ifdef __linux__
		(ec.tuntap_dev_name[0] != 0) &&
#endif
		(ec.ip_addr[0] != 0)
		))
	{
		traceEvent(TRACE_ERROR, "tuntap_dev_name = [%s] ec.ipaddr = [%s]."
			, ec.tuntap_dev_name, ec.ip_addr);
		return 1;
	}

	if(tuntap_open(&tuntap, ec.tuntap_dev_name, ec.ip_mode, ec.ip_addr, ec.netmask, ec.device_mac, ec.mtu) < 0)
		return(-1);

	if(conf.encrypt_key && !strcmp((char*)conf.community_name, conf.encrypt_key))
		traceEvent(TRACE_WARNING, "Community and encryption key must differ, otherwise security will be compromised");

	if((eee = edge_init(&tuntap, &conf, &rc)) == NULL) {
		traceEvent(TRACE_ERROR, "Failed in edge_init");
		exit(1);
	}

	/* set host addr, netmask, mac addr for UIP and init arp*/
    {
        int i;
		uint32_t ip;
        uip_ipaddr_t ipaddr;
        struct uip_eth_addr eaddr;

		ip = inet_addr(ec.ip_addr);
		memcpy(ipaddr, &ip, sizeof(ipaddr));
        uip_sethostaddr(ipaddr);
		ip = inet_addr(ec.netmask);
		memcpy(ipaddr, &ip, sizeof(ipaddr));
        uip_setnetmask(ipaddr);
        for (i = 0; i < 6; ++i) {
            eaddr.addr[i] = tuntap.mac_addr[i];
        }
        uip_setethaddr(eaddr);

        uip_arp_init();
    }

	keep_on_running = 1;
    pthread_mutex_lock(&status.mutex);
    status.is_running = keep_on_running;
    pthread_mutex_unlock(&status.mutex);
    report_edge_status();
	traceEvent(TRACE_NORMAL, "edge started");
	rc = run_edge_loop(eee, &keep_on_running);
	print_edge_stats(eee);

	/* Cleanup */
	edge_term(eee);
	tuntap_close(&tuntap);

	if(conf.encrypt_key) free(conf.encrypt_key);

	return(rc);
}

int stop_edge(void)
{
    // quick stop
    int fd = open_socket(0, 0 /* bind LOOPBACK*/ );
    if (fd < 0) {
        return 1;
    }

    struct sockaddr_in peer_addr;
    peer_addr.sin_family = PF_INET;
    peer_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer_addr.sin_port = htons(N2N_EDGE_MGMT_PORT);
    sendto(fd, "stop", 4, 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
	close(fd);

    pthread_mutex_lock(&status.mutex);
    status.is_running = 0;
    pthread_mutex_unlock(&status.mutex);
    report_edge_status();

    return 0;
}
#endif /* #ifdef __ANDROID_NDK__ */

/* ************************************** */
