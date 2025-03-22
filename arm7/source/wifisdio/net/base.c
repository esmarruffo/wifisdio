#include "../wifisdio.h"
#include "base.h"

#include "../wifi.h"
#include "../wmi.h"
#include "../utils.h"

#include "arp.h"
#include "ipv4.h"
#include "net_alloc.h"

#include <string.h>
#include <nds.h>

void net_handle_packet(uint8_t* src_mac, uint8_t* data, uint16_t len) {
    llc_snap_frame_t* frame = (llc_snap_frame_t*)data;
    
    net_address_t source = {0};
    memcpy(source.mac, src_mac, 6);

    if(frame->protocol == htons(PROTO_ARP))
        arp_handle_packet(&source, frame->body, len - sizeof(llc_snap_frame_t));
    else if(frame->protocol == htons(PROTO_IPv4))
        ipv4_handle_packet(&source, frame->body, len - sizeof(llc_snap_frame_t));
    else
        print("net: Unknown proto %x\n", htons(frame->protocol));
}

void net_send_packet(uint16_t proto, net_address_t* target, uint8_t* data, uint16_t len) {
    typedef struct {
        wmi_mbox_data_send_header_t header;
        llc_snap_frame_t llc;
    } __attribute__((packed)) frame_t;

    len = 84;

    frame_t* frame = net_malloc(sizeof(frame_t) + len);
    if(!frame)
        panic("net_send_packet(): Malloc failed\n");
    memset(frame, 0, sizeof(frame_t) + len);

    frame->llc.llc_snap[0] = 0xAA;
    frame->llc.llc_snap[1] = 0xAA;
    frame->llc.llc_snap[2] = 0x3;

    // frame->llc.protocol = htons(proto);
    frame->llc.protocol = 0x0008;

    memcpy(frame->llc.body, data, len);

    memset(frame->llc.body, 0, len);
    print_array_hex("frame: ", (uint8_t*)frame, sizeof(frame_t) + len);
    print("len: %i\n", len);
    print_array_hex("target->mac: ", target->mac, 6);
    sdio_tx_packet(target->mac, &frame->header, sizeof(frame_t) + len);
}