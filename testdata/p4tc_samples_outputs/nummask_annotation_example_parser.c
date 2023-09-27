
#include "nummask_annotation_example_parser.h";
#include <stdbool.h>
#include <linux/if_ether.h>
#include "pna.h"

REGISTER_START()
REGISTER_TABLE(hdr_md_cpumap, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct hdr_md, 2)
BPF_ANNOTATE_KV_PAIR(hdr_md_cpumap, u32, struct hdr_md)
REGISTER_END()

static __always_inline int run_parser(struct __sk_buff *skb, struct headers_t *hdr, struct pna_global_metadata *compiler_meta__)
{
    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;

    struct metadata_t *meta;
    struct hdr_md *hdrMd;

    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return TC_ACT_SHOT;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    hdr = &(hdrMd->cpumap_hdr);
    meta = &(hdrMd->cpumap_usermeta);
    {
        goto start;
        parse_ipv4: {
/* extract(hdr->ipv4) */
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

            __builtin_memcpy(&hdr->ipv4.version, pkt + (BYTES(ebpf_packetOffsetInBits) >> 4 & EBPF_MASK(u8, 4)), sizeof(hdr->ipv4.version));
            ebpf_packetOffsetInBits += 4;

            __builtin_memcpy(&hdr->ipv4.ihl, pkt + (BYTES(ebpf_packetOffsetInBits) & EBPF_MASK(u8, 4)), sizeof(hdr->ipv4.ihl));
            ebpf_packetOffsetInBits += 4;

            __builtin_memcpy(&hdr->ipv4.diffserv, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.diffserv));
            ebpf_packetOffsetInBits += 8;

            __builtin_memcpy(&hdr->ipv4.totalLen, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.totalLen));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->ipv4.identification, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.identification));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->ipv4.flags, pkt + (BYTES(ebpf_packetOffsetInBits) >> 5 & EBPF_MASK(u8, 3)), sizeof(hdr->ipv4.flags));
            ebpf_packetOffsetInBits += 3;

            __builtin_memcpy(&hdr->ipv4.fragOffset, pkt + (BYTES(ebpf_packetOffsetInBits) & EBPF_MASK(u16, 13)), sizeof(hdr->ipv4.fragOffset));
            ebpf_packetOffsetInBits += 13;

            __builtin_memcpy(&hdr->ipv4.ttl, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.ttl));
            ebpf_packetOffsetInBits += 8;

            __builtin_memcpy(&hdr->ipv4.protocol, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.protocol));
            ebpf_packetOffsetInBits += 8;

            __builtin_memcpy(&hdr->ipv4.hdrChecksum, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.hdrChecksum));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->ipv4.srcAddr, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.srcAddr));
            ebpf_packetOffsetInBits += 32;

            __builtin_memcpy(&hdr->ipv4.dstAddr, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->ipv4.dstAddr));
            ebpf_packetOffsetInBits += 32;

            hdr->ipv4.ebpf_valid = 1;

;
            u8 select_0;
            select_0 = hdr->ipv4.protocol;
            if (select_0 == 6)goto parse_tcp;
            if ((select_0 & 0x0) == (0x0 & 0x0))goto accept;
            else goto reject;
        }
        parse_tcp: {
/* extract(hdr->tcp) */
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

            __builtin_memcpy(&hdr->tcp.srcPort, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.srcPort));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->tcp.dstPort, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.dstPort));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->tcp.seqNo, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.seqNo));
            ebpf_packetOffsetInBits += 32;

            __builtin_memcpy(&hdr->tcp.ackNo, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.ackNo));
            ebpf_packetOffsetInBits += 32;

            __builtin_memcpy(&hdr->tcp.dataOffset, pkt + (BYTES(ebpf_packetOffsetInBits) >> 4 & EBPF_MASK(u8, 4)), sizeof(hdr->tcp.dataOffset));
            ebpf_packetOffsetInBits += 4;

            __builtin_memcpy(&hdr->tcp.res, pkt + (BYTES(ebpf_packetOffsetInBits) & EBPF_MASK(u8, 4)), sizeof(hdr->tcp.res));
            ebpf_packetOffsetInBits += 4;

            __builtin_memcpy(&hdr->tcp.flags, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.flags));
            ebpf_packetOffsetInBits += 8;

            __builtin_memcpy(&hdr->tcp.window, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.window));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->tcp.checksum, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.checksum));
            ebpf_packetOffsetInBits += 16;

            __builtin_memcpy(&hdr->tcp.urgentPtr, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->tcp.urgentPtr));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.ebpf_valid = 1;

;
             goto accept;
        }
        start: {
/* extract(hdr->eth) */
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
                ebpf_errorCode = PacketTooShort;
                goto reject;
            }

            __builtin_memcpy(&hdr->eth.dstAddr, pkt + (BYTES(ebpf_packetOffsetInBits) >> 16 & EBPF_MASK(u64, 48)), sizeof(hdr->eth.dstAddr));
            ebpf_packetOffsetInBits += 48;

            __builtin_memcpy(&hdr->eth.srcAddr, pkt + (BYTES(ebpf_packetOffsetInBits) >> 16 & EBPF_MASK(u64, 48)), sizeof(hdr->eth.srcAddr));
            ebpf_packetOffsetInBits += 48;

            __builtin_memcpy(&hdr->eth.etherType, pkt + BYTES(ebpf_packetOffsetInBits), sizeof(hdr->eth.etherType));
            ebpf_packetOffsetInBits += 16;

            hdr->eth.ebpf_valid = 1;

;
            u16 select_1;
            select_1 = hdr->eth.etherType;
            if (select_1 == 0x800)goto parse_ipv4;
            if ((select_1 & 0x0) == (0x0 & 0x0))goto accept;
            else goto reject;
        }

        reject: {
            if (ebpf_errorCode == 0) {
                return TC_ACT_SHOT;
            }
            goto accept;
        }

    }

    accept:
    return -1;
}

SEC("classifier/tc-parse")
int tc_parse_func(struct __sk_buff *skb) {
    struct hdr_md *hdrMd;
    struct headers_t *hdr;
    int ret = -1;
    ret = run_parser(skb, (struct headers_t *) hdr, compiler_meta__);
    if (ret != -1) {
        return ret;
    }
    return TC_ACT_PIPE;
    }
char _license[] SEC("license") = "GPL";
