#pragma once

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/socket.h#L188
#define AF_UNSPEC     0
#define AF_UNIX       1   /* Unix domain sockets          */
#define AF_LOCAL      1   /* POSIX name for AF_UNIX       */
#define AF_INET       2   /* Internet IP Protocol         */
#define AF_AX25       3   /* Amateur Radio AX.25          */
#define AF_IPX        4   /* Novell IPX                   */
#define AF_APPLETALK  5   /* AppleTalk DDP                */
#define AF_NETROM     6   /* Amateur Radio NET/ROM        */
#define AF_BRIDGE     7   /* Multiprotocol bridge         */
#define AF_ATMPVC     8   /* ATM PVCs                     */
#define AF_X25        9   /* Reserved for X.25 project    */
#define AF_INET6      10  /* IP version 6                 */
#define AF_ROSE       11  /* Amateur Radio X.25 PLP       */
#define AF_DECnet     12  /* Reserved for DECnet project  */
#define AF_NETBEUI    13  /* Reserved for 802.2LLC project*/
#define AF_SECURITY   14  /* Security callback pseudo AF  */
#define AF_KEY        15  /* PF_KEY key management API    */
#define AF_NETLINK    16
#define AF_ROUTE      AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET     17  /* Packet family                */
#define AF_ASH        18  /* Ash                          */
#define AF_ECONET     19  /* Acorn Econet                 */
#define AF_ATMSVC     20  /* ATM SVCs                     */
#define AF_RDS        21  /* RDS sockets                  */
#define AF_SNA        22  /* Linux SNA Project (nutters!) */
#define AF_IRDA       23  /* IRDA sockets                 */
#define AF_PPPOX      24  /* PPPoX sockets                */
#define AF_WANPIPE    25  /* Wanpipe API Sockets          */
#define AF_LLC        26  /* Linux LLC                    */
#define AF_IB         27  /* Native InfiniBand address    */
#define AF_MPLS       28  /* MPLS                         */
#define AF_CAN        29  /* Controller Area Network      */
#define AF_TIPC       30  /* TIPC sockets                 */
#define AF_BLUETOOTH  31  /* Bluetooth sockets            */
#define AF_IUCV       32  /* IUCV sockets                 */
#define AF_RXRPC      33  /* RxRPC sockets                */
#define AF_ISDN       34  /* mISDN sockets                */
#define AF_PHONET     35  /* Phonet sockets               */
#define AF_IEEE802154 36  /* IEEE802154 sockets           */
#define AF_CAIF       37  /* CAIF sockets                 */
#define AF_ALG        38  /* Algorithm sockets            */
#define AF_NFC        39  /* NFC sockets                  */
#define AF_VSOCK      40  /* vSockets                     */
#define AF_KCM        41  /* Kernel Connection Multiplexor*/
#define AF_QIPCRTR    42  /* Qualcomm IPC Router          */
#define AF_SMC        43  /* smc sockets (reserve PF_SMC) */
#define AF_XDP        44  /* XDP sockets                  */
#define AF_MCTP       45  /* Management component transport protocol */
#define AF_MAX        46

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L64
#define SOCK_STREAM    1
#define SOCK_DGRAM     2
#define SOCK_RAW       3
#define SOCK_RDM       4
#define SOCK_SEQPACKET 5
#define SOCK_DCCP      6
#define SOCK_PACKET    10

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/uapi/linux/in.h#L29
#define IPPROTO_IP       0   /* Dummy protocol for TCP               */
#define IPPROTO_ICMP     1   /* Internet Control Message Protocol    */
#define IPPROTO_IGMP     2   /* Internet Group Management Protocol   */
#define IPPROTO_IPIP     4   /* IPIP tunnels (older KA9Q tunnels)    */
#define IPPROTO_TCP      6   /* Transmission Control Protocol        */
#define IPPROTO_EGP      8   /* Exterior Gateway Protocol            */
#define IPPROTO_PUP      12  /* PUP protocol                         */
#define IPPROTO_UDP      17  /* User Datagram Protocol               */
#define IPPROTO_IDP      22  /* XNS IDP protocol                     */
#define IPPROTO_TP       29  /* SO Transport Protocol Class 4        */
#define IPPROTO_DCCP     33  /* Datagram Congestion Control Protocol */
#define IPPROTO_IPV6     41  /* IPv6-in-IPv4 tunnelling              */
#define IPPROTO_RSVP     46  /* RSVP Protocol                        */
#define IPPROTO_GRE      47  /* Cisco GRE tunnels (rfc 1701,1702)    */
#define IPPROTO_ESP      50  /* Encapsulation Security Payload       */
#define IPPROTO_AH       51  /* Authentication Header protocol       */
#define IPPROTO_MTP      92  /* Multicast Transport Protocol         */
#define IPPROTO_BEETPH   94  /* IP option pseudo header for BEET     */
#define IPPROTO_ENCAP    98  /* Encapsulation Header                 */
#define IPPROTO_PIM      103 /* Protocol Independent Multicast       */
#define IPPROTO_COMP     108 /* Compression Header Protocol          */
#define IPPROTO_L2TP     115 /* Layer 2 Tunnelling Protocol          */
#define IPPROTO_SCTP     132 /* Stream Control Transport Protocol    */
#define IPPROTO_UDPLITE  136 /* UDP-Lite (RFC 3828)                  */
#define IPPROTO_MPLS     137 /* MPLS in IP (RFC 4023)                */
#define IPPROTO_ETHERNET 143 /* Ethernet-within-IPv6 Encapsulation   */
#define IPPROTO_RAW      255 /* Raw IP packets                       */
#define IPPROTO_MPTCP    262 /* Multipath TCP connection             */
#define IPPROTO_MAX      263

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/uapi/linux/stat.h#L9
#define S_IFMT   0170000 /* bit mask for the file type bit field */
#define S_IFSOCK 0140000 /* socket                               */
#define S_IFLNK  0120000 /* symbolic link                        */
#define S_IFREG  0100000 /* regular file                         */
#define S_IFBLK  0060000 /* block device                         */
#define S_IFDIR  0040000 /* directory                            */
#define S_IFCHR  0020000 /* character device                     */
#define S_IFIFO  0010000 /* FIFO                                 */
#define S_ISUID  0004000 /* set-user-ID bit                      */
#define S_ISGID  0002000 /* set-group-ID bit (see below)         */
#define S_ISVTX  0001000 /* sticky bit (see below)               */

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/mm_types_task.h#L31
#define MM_FILEPAGES  0 /* Resident file mapping pages  */
#define MM_ANONPAGES  1 /* Resident anonymous pages     */
#define MM_SWAPENTS   2 /* Anonymous swap entries       */
#define MM_SHMEMPAGES 3 /* Resident shared memory pages */
#define NR_MM_COUNTERS 4

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/uapi/asm-generic/errno-base.h#L21
#define EEXIST 17 /* File exists */
