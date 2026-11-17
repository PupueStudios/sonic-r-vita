#include "net_upnp.h"

#if defined(SONICR_VITA) && defined(SONICR_MATCHMAKER)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <psp2/net/netctl.h>

extern void DebugLog(const char *fmt, ...);

#define UPNP_SSDP_WAIT_US   2500000
#define UPNP_TCP_TIMEOUT_US 3000000
#define UPNP_DESC_SIZE      16384
#define UPNP_RESP_SIZE      4096

typedef struct {
    char host[128];
    char port[8];
    char path[256];
} UrlParts;

static char s_controlUrl[512];
static char s_serviceType[128];
static int  s_portOpen = 0;
static int  s_openedPort = 0;

static int parse_http_url(const char *url, UrlParts *out)
{
    memset(out, 0, sizeof(*out));
    const char *after = strstr(url, "//");
    if (!after) return 0;
    after += 2;

    const char *slash = strchr(after, '/');
    const char *colon = strchr(after, ':');

    if (colon && (!slash || colon < slash)) {
        int hlen = (int)(colon - after);
        if (hlen >= (int)sizeof(out->host)) hlen = (int)sizeof(out->host) - 1;
        memcpy(out->host, after, hlen);
        const char *pstart = colon + 1;
        const char *pend = slash ? slash : pstart + strlen(pstart);
        int plen = (int)(pend - pstart);
        if (plen >= (int)sizeof(out->port)) plen = (int)sizeof(out->port) - 1;
        memcpy(out->port, pstart, plen);
    } else {
        const char *hend = slash ? slash : after + strlen(after);
        int hlen = (int)(hend - after);
        if (hlen >= (int)sizeof(out->host)) hlen = (int)sizeof(out->host) - 1;
        memcpy(out->host, after, hlen);
        strcpy(out->port, "80");
    }

    if (slash) {
        strncpy(out->path, slash, sizeof(out->path) - 1);
    } else {
        strcpy(out->path, "/");
    }
    return 1;
}

static int get_local_ip(char *out, int maxlen)
{
    SceNetCtlInfo info;
    memset(&info, 0, sizeof(info));
    if (sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info) < 0) {
        return 0;
    }
    if (!info.ip_address[0] || strcmp(info.ip_address, "0.0.0.0") == 0) {
        return 0;
    }
    snprintf(out, maxlen, "%s", info.ip_address);
    return 1;
}

static void set_timeouts(int s, int usec)
{
    int t = usec;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
}

static int tcp_connect(const UrlParts *parts)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(parts->host, parts->port, &hints, &res) != 0 || !res) {
        return -1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        freeaddrinfo(res);
        return -1;
    }
    set_timeouts(s, UPNP_TCP_TIMEOUT_US);

    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(s);
        return -1;
    }
    freeaddrinfo(res);
    return s;
}

static int send_all(int s, const char *data, int len)
{
    int total = 0;
    while (total < len) {
        int n = (int)send(s, data + total, len - total, 0);
        if (n <= 0) return 0;
        total += n;
    }
    return 1;
}

static int recv_all(int s, char *buf, int bufsize)
{
    int len = 0;
    while (len < bufsize - 1) {
        int n = (int)recv(s, buf + len, bufsize - len - 1, 0);
        if (n <= 0) break;
        len += n;
    }
    buf[len] = '\0';
    return len;
}

static int http_get_body(const char *url, char *buf, int bufsize)
{
    UrlParts parts;
    if (!parse_http_url(url, &parts)) return -1;

    int s = tcp_connect(&parts);
    if (s < 0) return -1;

    char req[512];
    int reqlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n",
        parts.path, parts.host, parts.port);

    if (!send_all(s, req, reqlen)) {
        close(s);
        return -1;
    }

    int len = recv_all(s, buf, bufsize);
    close(s);

    char *body = strstr(buf, "\r\n\r\n");
    if (body) {
        body += 4;
        int bodylen = len - (int)(body - buf);
        memmove(buf, body, bodylen);
        buf[bodylen] = '\0';
        return bodylen;
    }
    return len;
}

static const char *const s_searchTargets[] = {
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
};

static const char *find_header(const char *buf, const char *name)
{
    int nlen = (int)strlen(name);
    const char *p = buf;
    while (p && *p) {
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return NULL;
}

static int ssdp_find_location(char *location, int maxlen)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return 0;

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = 0;
    bind(s, (struct sockaddr *)&local, sizeof(local));

    set_timeouts(s, 500000);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.250", &addr.sin_addr);

    int sentAny = 0;
    for (int round = 0; round < 2; round++) {
        for (unsigned i = 0; i < sizeof(s_searchTargets) / sizeof(s_searchTargets[0]); i++) {
            char msg[256];
            int mlen = snprintf(msg, sizeof(msg),
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: %s\r\n"
                "MX: 2\r\n"
                "\r\n", s_searchTargets[i]);
            if (sendto(s, msg, mlen, 0, (struct sockaddr *)&addr, sizeof(addr)) > 0) {
                sentAny = 1;
            }
        }
    }
    if (!sentAny) {
        DebugLog("UPnP: SSDP sendto failed\n");
        close(s);
        return 0;
    }

    int found = 0;
    int waited = 0;
    int packets = 0;
    while (!found && waited < UPNP_SSDP_WAIT_US && packets < 32) {
        char buf[2048];
        int n = (int)recv(s, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            waited += 500000;
            continue;
        }
        buf[n] = '\0';
        packets++;

        const char *loc = find_header(buf, "LOCATION");
        if (!loc) continue;

        const char *end = loc;
        while (*end && *end != '\r' && *end != '\n') end++;
        int len = (int)(end - loc);
        while (len > 0 && loc[len - 1] == ' ') len--;
        if (len <= 0 || len >= maxlen) continue;

        memcpy(location, loc, len);
        location[len] = '\0';
        found = 1;
    }
    close(s);

    if (!found) {
        DebugLog("UPnP: no SSDP response\n");
    }
    return found;
}

static int find_service(const char *xml, const char *type, const char *base_url,
                        char *control_url, int maxlen)
{
    const char *svc = strstr(xml, type);
    if (!svc) return 0;

    const char *ctrl = strstr(svc, "<controlURL>");
    if (!ctrl) return 0;
    ctrl += 12;
    while (*ctrl == ' ' || *ctrl == '\r' || *ctrl == '\n' || *ctrl == '\t') ctrl++;

    const char *ctrl_end = strstr(ctrl, "</controlURL>");
    if (!ctrl_end) return 0;
    int ctrl_len = (int)(ctrl_end - ctrl);
    while (ctrl_len > 0 && (ctrl[ctrl_len - 1] == ' ' || ctrl[ctrl_len - 1] == '\r'
                            || ctrl[ctrl_len - 1] == '\n' || ctrl[ctrl_len - 1] == '\t')) {
        ctrl_len--;
    }
    if (ctrl_len <= 0) return 0;

    if (strncmp(ctrl, "http", 4) == 0) {
        if (ctrl_len >= maxlen) return 0;
        memcpy(control_url, ctrl, ctrl_len);
        control_url[ctrl_len] = '\0';
    } else {
        int base_len = (int)strlen(base_url);
        int need_slash = (ctrl[0] != '/');
        if (base_len + need_slash + ctrl_len >= maxlen) return 0;
        memcpy(control_url, base_url, base_len);
        if (need_slash) control_url[base_len++] = '/';
        memcpy(control_url + base_len, ctrl, ctrl_len);
        control_url[base_len + ctrl_len] = '\0';
    }
    return 1;
}

static int upnp_discover(void)
{
    static char desc_xml[UPNP_DESC_SIZE];
    static const char *const services[] = {
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    };
    char location[512];

    if (!ssdp_find_location(location, sizeof(location))) {
        return 0;
    }
    DebugLog("UPnP: LOCATION %s\n", location);

    char base_url[256];
    const char *after = strstr(location, "//");
    if (!after) return 0;
    const char *slash = strchr(after + 2, '/');
    int blen = slash ? (int)(slash - location) : (int)strlen(location);
    if (blen >= (int)sizeof(base_url)) return 0;
    memcpy(base_url, location, blen);
    base_url[blen] = '\0';

    int xml_len = http_get_body(location, desc_xml, sizeof(desc_xml));
    if (xml_len <= 0) {
        DebugLog("UPnP: failed to fetch device description\n");
        return 0;
    }

    const char *ub = strstr(desc_xml, "<URLBase>");
    if (ub) {
        ub += 9;
        const char *ue = strstr(ub, "</URLBase>");
        if (ue) {
            int ulen = (int)(ue - ub);
            while (ulen > 0 && ub[ulen - 1] == '/') ulen--;
            if (ulen > 0 && ulen < (int)sizeof(base_url)) {
                memcpy(base_url, ub, ulen);
                base_url[ulen] = '\0';
            }
        }
    }

    for (unsigned i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (find_service(desc_xml, services[i], base_url,
                         s_controlUrl, sizeof(s_controlUrl))) {
            snprintf(s_serviceType, sizeof(s_serviceType), "%s", services[i]);
            DebugLog("UPnP: control URL %s (%s)\n", s_controlUrl, s_serviceType);
            return 1;
        }
    }

    DebugLog("UPnP: no WAN connection service in device description\n");
    return 0;
}

static int soap_request(const char *action, const char *args,
                        char *resp_buf, int resp_size)
{
    UrlParts parts;
    if (!parse_http_url(s_controlUrl, &parts)) return -1;

    char body[1280];
    int bodylen = snprintf(body, sizeof(body),
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
        "<s:Body>\r\n"
        "<u:%s xmlns:u=\"%s\">\r\n"
        "%s"
        "</u:%s>\r\n"
        "</s:Body>\r\n"
        "</s:Envelope>\r\n",
        action, s_serviceType, args, action);
    if (bodylen <= 0 || bodylen >= (int)sizeof(body)) return -1;

    char hdr[768];
    int hdrlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%s\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "SOAPAction: \"%s#%s\"\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        parts.path, parts.host, parts.port, s_serviceType, action, bodylen);
    if (hdrlen <= 0 || hdrlen >= (int)sizeof(hdr)) return -1;

    int s = tcp_connect(&parts);
    if (s < 0) return -1;

    if (!send_all(s, hdr, hdrlen) || !send_all(s, body, bodylen)) {
        close(s);
        return -1;
    }

    recv_all(s, resp_buf, resp_size);
    close(s);

    const char *sp = strstr(resp_buf, "HTTP/");
    if (!sp) return -1;
    sp = strchr(sp, ' ');
    if (!sp) return -1;
    return atoi(sp + 1);
}

static int add_mapping(int port, const char *local_ip, const char *lease, char *resp, int resp_size)
{
    char args[640];
    snprintf(args, sizeof(args),
        "<NewRemoteHost></NewRemoteHost>\r\n"
        "<NewExternalPort>%d</NewExternalPort>\r\n"
        "<NewProtocol>UDP</NewProtocol>\r\n"
        "<NewInternalPort>%d</NewInternalPort>\r\n"
        "<NewInternalClient>%s</NewInternalClient>\r\n"
        "<NewEnabled>1</NewEnabled>\r\n"
        "<NewPortMappingDescription>SonicR Vita</NewPortMappingDescription>\r\n"
        "<NewLeaseDuration>%s</NewLeaseDuration>\r\n",
        port, port, local_ip, lease);
    return soap_request("AddPortMapping", args, resp, resp_size);
}

static void delete_mapping(int port)
{
    static char resp[UPNP_RESP_SIZE];
    char args[256];
    snprintf(args, sizeof(args),
        "<NewRemoteHost></NewRemoteHost>\r\n"
        "<NewExternalPort>%d</NewExternalPort>\r\n"
        "<NewProtocol>UDP</NewProtocol>\r\n",
        port);
    soap_request("DeletePortMapping", args, resp, sizeof(resp));
}

int net_upnp_open_port(int port)
{
    static char resp[UPNP_RESP_SIZE];
    char local_ip[64];

    if (s_portOpen && s_openedPort == port) {
        return 1;
    }

    if (!get_local_ip(local_ip, sizeof(local_ip))) {
        DebugLog("UPnP: couldn't determine local IP\n");
        return 0;
    }
    DebugLog("UPnP: local IP = %s\n", local_ip);

    if (!upnp_discover()) {
        return 0;
    }

    int status = add_mapping(port, local_ip, "3600", resp, sizeof(resp));
    if (status == 500 && strstr(resp, "718")) {
        DebugLog("UPnP: port %d already mapped, replacing\n", port);
        delete_mapping(port);
        status = add_mapping(port, local_ip, "3600", resp, sizeof(resp));
    }
    if (status == 500 && strstr(resp, "725")) {
        DebugLog("UPnP: router rejected lease=3600, retrying with lease=0\n");
        status = add_mapping(port, local_ip, "0", resp, sizeof(resp));
    }

    if (status == 200) {
        DebugLog("UPnP: port %d opened\n", port);
        s_portOpen = 1;
        s_openedPort = port;
        return 1;
    }

    DebugLog("UPnP: AddPortMapping failed (HTTP %d)\n", status);
    return 0;
}

void net_upnp_close_port(int port)
{
    if (!s_portOpen || s_openedPort != port) return;
    delete_mapping(port);
    s_portOpen = 0;
    s_openedPort = 0;
    DebugLog("UPnP: port %d closed\n", port);
}

#else

int  net_upnp_open_port(int port)  { (void)port; return 0; }
void net_upnp_close_port(int port) { (void)port; }

#endif
