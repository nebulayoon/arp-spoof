#pragma once
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "ethhdr.h"

typedef struct IpHdr {
	uint8_t ver_headerlen;		
	uint8_t tos;		
	uint16_t total_len;
	uint16_t id;		
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	struct in_addr src,dst;
}IpHdr;

typedef struct EthIpPacket{
	EthHdr eth_;
	IpHdr ip_;
}EthIpPacket;