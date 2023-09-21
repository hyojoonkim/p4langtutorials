/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> RPS_ETYPE = 0x1234;

const bit<8>  HAND_ROCK     = 0x01;
const bit<8>  HAND_PAPER    = 0x02;
const bit<8>  HAND_SCISSORS = 0x03;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header rps_t {

    ##### YOUR CODE HERE 1 - START #####

    // Define how the RPS header is structured.
    // There are four fields, each with a specific bit size. 
    // You will use these field names later in your code.
    // Hint: You need four lines here (without comments)
    // Don't use "error" or "switch" as field names. These are reserved terms. 
    // Maybe use "err" or "sw" instead, or something like that.

    ##### YOUR CODE HERE 1 - END #####

}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    rps_t        rps;
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
	        RPS_ETYPE: parse_rps;
            default: accept;
        }
    }

    state parse_rps {
        packet.extract(hdr.rps);
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_back() {
        bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        if (hdr.rps.isValid()) {


            ##### YOUR CODE HERE 2 - START #####

            // 1. First, check the version value in the rps header.
            // If not 1, set the err value in the rps header as 1. 

            // 2. Else (i.e., if version is 1), decide the switch's choice
            // based on the human's choice (so the switch is cheating, just really fast). 
            // The switch's choice should always win over the human's choice. 
            // So use the extracted (i.e., parsed) human's choice and react accordingly. 
            // Reacting means, setting the winning value in the switch's choice field in the rps header.
            // For values, you can use the 'constants' defined at line 7, 8, and 9.
            
            ##### YOUR CODE HERE 2 - END   #####
            
            // At this point, we assume you set the right value above.
            // So send back the packet with the winning switch's choice. 
            send_back();
        }
        else {
            drop();
        }
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
     apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);

        ##### YOUR CODE HERE 3 - START #####
    
        // Attach the rps header to the outgoing packet.
        // Hint: You just need one line here (without comments)
    
        ##### YOUR CODE HERE 3 - END #####
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
