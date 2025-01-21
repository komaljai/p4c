/*
Copyright 2024 Cisco Systems, Inc.

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

#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

struct headers_t {
    ethernet_t    ethernet;
}

struct metadata_t {
}

parser parserImpl(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control verifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply { }
}

action foo1() { }

@name("foo2") action topa2() { }

@name("foo3") action topa3() { }

// Action topa4's control plane name should conflict with the control
// plane name of action topa3, and cause a compile-time error message,
// if you enable P4Info file generation.
@name(".foo3") action topa4() { }

@name(".ingressImpl.foo5") action topa5() { }

control c1(
    inout headers_t hdr,
    inout bit<8> tmp1,
    inout bit<8> tmp2)
{
    // Action suba1's control plane name should conflict with the name
    // of top-level action foo1, and cause a compile-time error
    // message, if you enable P4Info file generation.
    @name(".foo1") action suba1 (bit<8> x, bit<8> y) { tmp1 = x; tmp2 = y >> 1; }

    // Action suba2's control plane name should conflict with the
    // control plane name of topa2, and cause a compile-time error
    // message, if you enable P4Info file generation.
    @name(".foo2") action suba2 (bit<8> x, bit<8> y) { tmp1 = x; tmp2 = y >> 2; }

    @name("bar1") action suba3 (bit<8> x, bit<8> y) { tmp1 = x; tmp2 = y >> 3; }

    table t2 {
        actions = {
            suba1;
            suba2;
            suba3;
        }
        key = { hdr.ethernet.srcAddr: exact; }
        size = 32;
    }
    apply {
        t2.apply();
    }
}

control ingressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)

{
    bit<8> tmp1;
    bit<8> tmp2;

    // Action a1's control plane name should conflict with the name of
    // top-level action foo1, and cause a compile-time error message,
    // if you enable P4Info file generation.
    @name(".foo1") action a1 (bit<8> x, bit<8> y) { tmp1 = x >> 1; tmp2 = y; }

    // Action a2's control plane name should conflict with the control
    // plane name of topa2, and cause a compile-time error message, if
    // you enable P4Info file generation.
    @name(".foo2") action a2 (bit<8> x, bit<8> y) { tmp1 = x >> 2; tmp2 = y; }

    // Action a5's control plane name should conflict with the control
    // plane name of topa5, and cause a compile-time error message, if
    // you enable P4Info file generation.
    @name("foo5") action a5 (bit<8> x, bit<8> y) { tmp1 = x >> 5; tmp2 = y; }

    // Action a6's control plane name should conflict with the
    // control plane name of suba3, and cause a compile-time error
    // message, if you enable P4Info file generation.
    @name("c1.bar1") action a6 (bit<8> x, bit<8> y) { tmp1 = x >> 6; tmp2 = y; }

    table t1 {
        actions = {
            NoAction;
            a1;
            a2;
            a5;
            a6;
            foo1;
            topa2;
            topa3;
            topa4;
            topa5;
        }
        key = { hdr.ethernet.etherType: exact; }
        default_action = NoAction();
        size = 512;
    }
    apply {
        tmp1 = hdr.ethernet.srcAddr[7:0];
        tmp2 = hdr.ethernet.dstAddr[7:0];
        c1.apply(hdr, tmp1, tmp2);
        t1.apply();
        // This is here simply to ensure that the compiler cannot
        // optimize away the effects of t1 and t2, which can only
        // assign values to variables tmp1 and tmp2.
        hdr.ethernet.etherType = (bit<16>) (tmp1 - tmp2);
    }
}

control egressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    apply { }
}

control updateChecksum(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply { }
}

control deparserImpl(
    packet_out pkt,
    in headers_t hdr)
{
    apply {
        pkt.emit(hdr.ethernet);
    }
}

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
