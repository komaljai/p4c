#include <core.p4>
#include <v1model.p4>

struct H {
}

struct M {
    bit<32> hash1;
}

parser ParserI(packet_in pk, out H hdr, inout M meta, inout standard_metadata_t smeta) {
    state start {
        transition accept;
    }
}

control IngressI(inout H hdr, inout M meta, inout standard_metadata_t smeta) {
    @name(".NoAction") action NoAction_0() {
    }
    @name(".NoAction") action NoAction_3() {
    }
    @name("IngressI.c1.drop") action c1_drop_0() {
        mark_to_drop();
    }
    @name(".t0") table _t0 {
        key = {
            smeta.ingress_port: exact @name("smeta.ingress_port") ;
        }
        actions = {
            c1_drop_0();
            NoAction_0();
        }
        const default_action = NoAction_0();
    }
    @name("IngressI.c2.drop") action c2_drop_0() {
        mark_to_drop();
    }
    @name(".t0") table _t0_0 {
        key = {
            smeta.ingress_port: exact @name("smeta.ingress_port") ;
        }
        actions = {
            c2_drop_0();
            NoAction_3();
        }
        const default_action = NoAction_3();
    }
    apply {
        _t0.apply();
        _t0_0.apply();
    }
}

control EgressI(inout H hdr, inout M meta, inout standard_metadata_t smeta) {
    apply {
    }
}

control DeparserI(packet_out pk, in H hdr) {
    apply {
    }
}

control VerifyChecksumI(inout H hdr, inout M meta) {
    apply {
    }
}

control ComputeChecksumI(inout H hdr, inout M meta) {
    apply {
    }
}

V1Switch<H, M>(ParserI(), VerifyChecksumI(), IngressI(), EgressI(), ComputeChecksumI(), DeparserI()) main;
