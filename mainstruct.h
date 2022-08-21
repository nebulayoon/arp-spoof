#pragma once
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct MultiArgv {
	pcap_t* handle;
	char* sender_ip;
	char* target_ip;
	char* attacker_ip;
	uint8_t* attacker_mac;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ArpTableThreadArgv {
	pcap_t* handle;
	Ip sender_ip;
	Mac sender_mac;
	Ip target_ip;
	Mac target_mac;
	Ip attacker_ip;
	Mac attacker_mac;
};
#pragma pack(pop)