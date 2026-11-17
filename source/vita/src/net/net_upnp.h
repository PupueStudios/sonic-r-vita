#ifndef NET_UPNP_H
#define NET_UPNP_H

#define NET_UPNP_IDLE    0
#define NET_UPNP_WORKING 1
#define NET_UPNP_OK      2
#define NET_UPNP_FAILED  3

int  net_upnp_open_port(int port);
int  net_upnp_status(void);
void net_upnp_close_port(int port);

#endif
