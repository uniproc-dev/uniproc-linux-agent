// Socket traffic probes.
//
// Hooks:
//   tp_btf/sock_send_length — accounts TX bytes for all socket families
//   tp_btf/sock_recv_length — accounts RX bytes for all socket families
//   kretprobe/p9_client_rpc — accounts 9P virtio traffic (WSL2 /mnt)
//
// References:
//   https://github.com/microsoft/WSL2-Linux-Kernel/.../net/socket.c (sock_sendmsg_nosec)
//   https://github.com/microsoft/WSL2-Linux-Kernel/.../net/9p/client.c#L582

#include "include/socket.h"
#include <bpf/bpf_tracing.h>

#define MSG_PEEK 2

SEC("tp_btf/sock_send_length")
int BPF_PROG(socket_send, struct sock *sk, int ret, int flags) {
    if (ret <= 0 || !sk) return 0;
    handle_socket_stats(sk, (__u64)ret, TRAFFIC_TX, get_pid());
    return 0;
}

SEC("tp_btf/sock_recv_length")
int BPF_PROG(socket_recv, struct sock *sk, int ret, int flags) {
    if (ret <= 0 || !sk || (flags & MSG_PEEK)) return 0;
    handle_socket_stats(sk, (__u64)ret, TRAFFIC_RX, get_pid());
    return 0;
}

SEC("kretprobe/p9_client_rpc")
int BPF_KRETPROBE(p9_client_rpc_kretprobe, struct p9_req_t *req_ptr) {
    if (!req_ptr || (unsigned long)req_ptr > (unsigned long)(-4096L)) return 0;
    __u32 pid     = get_pid();
    __u64 tx_size = BPF_CORE_READ(req_ptr, tc.size);
    __u64 rx_size = BPF_CORE_READ(req_ptr, rc.size);
    if (tx_size > 0) update_p9_stats(pid, tx_size, TRAFFIC_TX);
    if (rx_size > 0) update_p9_stats(pid, rx_size, TRAFFIC_RX);
    return 0;
}