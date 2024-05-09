/*
Copyright 2018 VMware, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


/// This file contains all functions and definitions necessary for the kernel target C
/// code to compile. It must be included with any file generated by the p4c-ebpf kernel
/// compiler.
#ifndef BACKENDS_EBPF_RUNTIME_EBPF_KERNEL_H_
#define BACKENDS_EBPF_RUNTIME_EBPF_KERNEL_H_

#include "ebpf_common.h"

#include <bpf/bpf_endian.h> // definitions for bpf_ntohs etc...

#undef htonl
#undef htons
#define htons(d) bpf_htons(d)
#define htonl(d) bpf_htonl(d)
#define htonll(d) bpf_cpu_to_be64(d)
#define ntohll(x) bpf_be64_to_cpu(x)
#ifndef bpf_htonll
#define bpf_htonll(x) htonll(x)
#endif

#define load_byte(data, b) (*(((u8*)(data)) + (b)))
#define load_half(data, b) bpf_ntohs(*(u16 *)((u8*)(data) + (b)))
#define load_word(data, b) bpf_ntohl(*(u32 *)((u8*)(data) + (b)))
#define load_dword(data, b) bpf_be64_to_cpu(*(u64 *)((u8*)(data) + (b)))

/// If we operate in user space we only need to include bpf.h and
/// define the userspace API macros.
/// For kernel programs we need to specify a list of kernel helpers. These are
/// taken from here: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/bpf_helpers.h
#ifdef CONTROL_PLANE // BEGIN EBPF USER SPACE DEFINITIONS

#include <bpf/bpf.h> // bpf_obj_get/pin, bpf_map_update_elem

#define BPF_USER_MAP_UPDATE_ELEM(index, key, value, flags)\
    bpf_map_update_elem(index, key, value, flags)
#define BPF_OBJ_PIN(table, name) bpf_obj_pin(table, name)
#define BPF_OBJ_GET(name) bpf_obj_get(name)

#else // BEGIN EBPF KERNEL DEFINITIONS

#include <linux/pkt_cls.h>  // TC_ACT_OK, TC_ACT_SHOT
#include "linux/bpf.h"  // types, and general bpf definitions
// This file contains the definitions of all the kernel bpf essentials
#include <bpf/bpf_helpers.h>

/// A helper structure used by an eBPF C program
/// to describe map attributes for the elf_bpf loader
/// FIXME: We only need this because we are loading with iproute2
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

/// Simple descriptor which replaces the kernel sk_buff structure.
#define SK_BUFF struct __sk_buff

/// From iproute2, annotate table with BTF which allows to read types at runtime.
#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)  \
    struct ____btf_map_##name {                         \
        type_key key;                                   \
        type_val value;                                 \
    };                                                  \
    struct ____btf_map_##name                           \
        __attribute__ ((section(".maps." #name), used)) \
        ____btf_map_##name = {};

#define REGISTER_START()
#ifndef BTF
/// Note: pinning exports the table name globally, do not remove.
#define REGISTER_TABLE(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES) \
struct bpf_elf_map SEC("maps") NAME = {          \
    .type        = TYPE,               \
    .size_key    = sizeof(KEY_TYPE),   \
    .size_value  = sizeof(VALUE_TYPE), \
    .max_elem    = MAX_ENTRIES,        \
    .pinning     = 2,                  \
    .flags       = 0,                  \
};
#define REGISTER_TABLE_INNER(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, ID, INNER_IDX) \
struct bpf_elf_map SEC("maps") NAME = {          \
    .type        = TYPE,               \
    .size_key    = sizeof(KEY_TYPE),   \
    .size_value  = sizeof(VALUE_TYPE), \
    .max_elem    = MAX_ENTRIES,        \
    .pinning     = 2,                  \
    .flags       = 0,                  \
    .id          = ID,                 \
    .inner_idx   = INNER_IDX,          \
};
#define REGISTER_TABLE_OUTER(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, INNER_ID, INNER_NAME) \
struct bpf_elf_map SEC("maps") NAME = {          \
    .type        = TYPE,               \
    .size_key    = sizeof(KEY_TYPE),   \
    .size_value  = sizeof(VALUE_TYPE), \
    .max_elem    = MAX_ENTRIES,        \
    .pinning     = 2,                  \
    .flags       = 0,                  \
    .inner_id    = INNER_ID,           \
};
#define REGISTER_TABLE_FLAGS(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, FLAGS) \
struct bpf_elf_map SEC("maps") NAME = {          \
    .type        = TYPE,               \
    .size_key    = sizeof(KEY_TYPE),   \
    .size_value  = sizeof(VALUE_TYPE), \
    .max_elem    = MAX_ENTRIES,        \
    .pinning     = 2,                  \
    .flags       = FLAGS,              \
};
#else
#define REGISTER_TABLE(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES) \
struct {                                 \
    __uint(type, TYPE);                  \
    KEY_TYPE *key;                       \
    VALUE_TYPE *value;                   \
    __uint(max_entries, MAX_ENTRIES);    \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
} NAME SEC(".maps");
#define REGISTER_TABLE_FLAGS(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, FLAGS) \
struct {                                 \
    __uint(type, TYPE);                  \
    KEY_TYPE *key;                       \
    VALUE_TYPE *value;                   \
    __uint(max_entries, MAX_ENTRIES);    \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
    __uint(map_flags, FLAGS);            \
} NAME SEC(".maps");
#define REGISTER_TABLE_INNER(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, ID, INNER_IDX) \
struct NAME {                            \
    __uint(type, TYPE);                  \
    KEY_TYPE *key;                       \
    VALUE_TYPE *value;                   \
    __uint(max_entries, MAX_ENTRIES);    \
} NAME SEC(".maps");
#define REGISTER_TABLE_OUTER(NAME, TYPE, KEY_TYPE, VALUE_TYPE, MAX_ENTRIES, INNER_ID, INNER_NAME) \
struct {                                 \
    __uint(type, TYPE);                  \
    KEY_TYPE *key;                       \
    VALUE_TYPE *value;                   \
    __uint(max_entries, MAX_ENTRIES);    \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
    __array(values, struct INNER_NAME);  \
} NAME SEC(".maps");
#define REGISTER_TABLE_NO_KEY_TYPE(NAME, TYPE, KEY_SIZE, VALUE_TYPE, MAX_ENTRIES) \
struct {                                 \
    __uint(type, TYPE);                  \
    __uint(key_size, KEY_SIZE);          \
    VALUE_TYPE *value;                   \
    __uint(max_entries, MAX_ENTRIES);    \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
} NAME SEC(".maps");
#endif
#define REGISTER_END()

#define BPF_MAP_LOOKUP_ELEM(table, key) \
    bpf_map_lookup_elem(&table, key)
#define BPF_MAP_UPDATE_ELEM(table, key, value, flags) \
    bpf_map_update_elem(&table, key, value, flags)
#define BPF_MAP_DELETE_ELEM(table, key) \
    bpf_map_delete_elem(&table, key)
#define BPF_USER_MAP_UPDATE_ELEM(index, key, value, flags)\
    bpf_update_elem(index, key, value, flags)
#define BPF_OBJ_PIN(table, name) bpf_obj_pin(table, name)
#define BPF_OBJ_GET(name) bpf_obj_get(name)

#endif // END EBPF KERNEL DEFINITIONS

#endif  // BACKENDS_EBPF_RUNTIME_EBPF_KERNEL_H_
