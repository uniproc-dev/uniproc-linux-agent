cmake_minimum_required(VERSION 3.16)
project(uniproc-linux-agent-ebpf C)

set(CMAKE_C_STANDARD 11)

include_directories(uniproc-linux-agent-ebpf/src /usr/include)

add_definitions(-D__BPF_TRACING__ -D__x86_64__)

add_executable(ebpf_prog
        uniproc-linux-agent-ebpf/src/prog.bpf.c
        uniproc-linux-agent-ebpf/src/include/constants.h
        uniproc-linux-agent-ebpf/src/include/maps.h
        uniproc-linux-agent-ebpf/src/vmlinux.h
        uniproc-linux-agent-ebpf/src/include/common.h
        uniproc-linux-agent-ebpf/src/include/loopback.h
        uniproc-linux-agent-ebpf/src/include/socket.h
        uniproc-linux-agent-ebpf/src/include/disk.h
        uniproc-linux-agent-ebpf/src/include/process.h
        uniproc-linux-agent-ebpf/src/include/snapshot.h
        uniproc-linux-agent-ebpf/src/probes/sockets.bpf.c
        uniproc-linux-agent-ebpf/src/probes/disk.bpf.c
        uniproc-linux-agent-ebpf/src/probes/process.bpf.c
        uniproc-linux-agent-ebpf/src/probes/seed.bpf.c
        uniproc-linux-agent-ebpf/src/probes/snapshot.bpf.c)