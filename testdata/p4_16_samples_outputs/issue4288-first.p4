#include <core.p4>

control Deparser(packet_out packet);
package SimpleArch(Deparser dep);
header hdr_t {
    bit<8> f0;
}

control MyDeparser(packet_out packet)(hdr_t h) {
    apply {
        packet.emit<hdr_t>(h);
    }
}

SimpleArch(MyDeparser({ 8w0 })) main;
