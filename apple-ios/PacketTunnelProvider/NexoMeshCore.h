#ifndef NEXOMESH_CORE_H
#define NEXOMESH_CORE_H

#include <stdint.h>

void nexomesh_init(void);
int32_t nexomesh_configure_session(
    const char *local_vip,
    const char *peer_vip,
    const char *local_key,
    const char *peer_key,
    const char *peer_endpoint
);
int32_t nexomesh_connect(const char *pubkey, const char *endpoint);
int32_t nexomesh_push_outbound_ip(const uint8_t *pkt, int32_t pkt_len);
int32_t nexomesh_poll_inbound_ip(uint8_t *out, int32_t out_cap);
int32_t nexomesh_rebind_network(void);
void nexomesh_disconnect(void);
const char *nexomesh_status_json(void);
const char *nexomesh_netcheck_json(void);

#endif
