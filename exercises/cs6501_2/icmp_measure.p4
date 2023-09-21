/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_ICMP = 0x01;

#define MAX_FLOWS   1024


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

struct metadata {
    bit<32> hash1;
    bit<32> hash2;
    bit<48> diff;
    bit<48> cur_time;
    bit<48> last_time;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    icmp_t          icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    // Register for keeping timestamp
    register<bit<48>>(MAX_FLOWS) echo_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table forward_tbl {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            l2_forward;
            drop;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = drop();
    }

    table debug {
        key ={
            meta.cur_time: exact;
            meta.last_time: exact;
        }
        actions = {}
    }

    apply {
        // Get this packet's timestamp when it entered the ingress pipeline
        bit<48> cur_time = standard_metadata.ingress_global_timestamp;

        bit<48> last_time;
        bit<48> diff;
        
        // For debugging
        meta.cur_time = cur_time;

        if (hdr.icmp.isValid()) {

            // If this packet is from host 1, hash with fields ordered like: srcAddr, dstAddr
            if (standard_metadata.ingress_port == 1) {
                hash(meta.hash1, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)MAX_FLOWS);
            }
            // Else, this packet is from host 2. Hash with fields ordered like: dstAddr, srcAddr
            // We do this so that we can look up the right entry even when the packet's direction is the opposite.
            else {
                hash(meta.hash1, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr}, (bit<32>)MAX_FLOWS);
            }

            // Ping echo request came in. 
            // 1. Write this packet's timestamp ("cur_time") to register "echo_reg".
            // Hint: one line should do.
            if (hdr.icmp.typeCode == 0x0800) {
                ##### YOUR CODE HERE 1 - START #####


                ##### YOUR CODE HERE 1 - END   #####
            }

            // Ping echo reply came in. 
            //  1. You already know this packet's ingress timestamp.
            //  2. Lookup the register for the matching echo request packet, read the timestamp from the register, then save to variable "last_time". 
            //  3. Calculate time difference.
            //  4. Overwrite the IPv4 header's identification field with this diff value.
            //    3.1. Hint: IPv4 header's identification field is only 16 bits. But the diff is 48 bits. 
            //      Thus, you need to add a typecast in C style. E.g., "16bit_variable = (bit<16>) 48bit_variable"
            //  Hint: Just several lines should do.
            else if (hdr.icmp.typeCode == 0x0000) {
                ##### YOUR CODE HERE 2 - START #####


                ##### YOUR CODE HERE 2 - END   #####

                // for debugging
                meta.last_time = last_time;
            }
        }

        // Apply forwarding table so that packets are forwarded.
        // This table is used for installing forwarding rules.
        // If interested, look at "s1-runtime.json", which installs rules
        //  in the table at startup.
        forward_tbl.apply();

        // For debugging
        debug.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
