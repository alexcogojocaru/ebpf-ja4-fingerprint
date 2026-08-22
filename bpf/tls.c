#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_UNSPEC (-1)
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define MAX_HELLO_LEN 1024

struct tls_event
{
    __u32 len;
    __u8 truncated;
    __u8 data[MAX_HELLO_LEN];
};

struct tls_event *unused_tls_event __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int capture_tls(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_UNSPEC;
    }

    /* IPv4 header length: low nibble of byte 0, counted in 32-bit words. */
    __u8 ip_vhl = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_vhl, 1) < 0)
    {
        return TC_ACT_UNSPEC;
    }

    __u32 ip_hlen = (ip_vhl & 0x0f) * 4;
    if (ip_hlen < 20)
    {
        return TC_ACT_UNSPEC;
    }

    /* Protocol: byte 9 of the IPv4 header. */
    __u8 protocol = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &protocol, 1) < 0)
    {
        return TC_ACT_UNSPEC;
    }

    if (protocol != IPPROTO_TCP)
    {
        return TC_ACT_UNSPEC;
    }

    /* TCP header length: high nibble of byte 12, counted in 32-bit words. */
    __u32 tcp_off = ETH_HLEN + ip_hlen;
    __u8 tcp_doff = 0;
    if (bpf_skb_load_bytes(skb, tcp_off + 12, &tcp_doff, 1) < 0)
    {
        return TC_ACT_UNSPEC;
    }

    __u32 tcp_hlen = (tcp_doff >> 4) * 4;
    if (tcp_hlen < 20)
    {
        return TC_ACT_UNSPEC;
    }

    __u32 payload = tcp_off + tcp_hlen;

    /* TLS record header (5 bytes) plus the first byte of the handshake. */
    __u8 hdr[6];
    if (bpf_skb_load_bytes(skb, payload, hdr, sizeof(hdr)) < 0)
    {
        return TC_ACT_UNSPEC;
    }

    /* 0x16 = handshake record, 0x03 = TLS major, 0x01 = client_hello. */
    if (hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[5] != 0x01)
    {
        return TC_ACT_UNSPEC;
    }

    __u64 len = ((__u64)hdr[3] << 8) | hdr[4];

    __u8 truncated = 0;
    if (len > MAX_HELLO_LEN)
    {
        len = MAX_HELLO_LEN;
        truncated = 1;
    }

    if (len == 0)
    {
        return TC_ACT_UNSPEC;
    }

    struct tls_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        return TC_ACT_UNSPEC;
    }

    e->len = len;
    e->truncated = truncated;
    if (bpf_skb_load_bytes(skb, payload + 5, e->data, len) < 0)
    {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_UNSPEC;
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int capture_egress_tls(struct __sk_buff *skb)
{
    return capture_tls(skb);
}
