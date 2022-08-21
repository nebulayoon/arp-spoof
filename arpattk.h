#pragma once

#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>


#include "mainstruct.h"
#include "util.h"
#include "iphdr.h"

typedef struct infect_argv{
    pcap_t* handle;
    size_t size_;
    ArpTableThreadArgv* arp_table_;
}infect_argv;

void arp_request(pcap_t* handle, Ip sender_ip, Ip attacker_ip, Mac attacker_mac);
void send_arp(pcap_t* handle, EthArpPacket packet);
EthArpPacket set_arp_packet(EthArpPacket packet, char* sender_ip, Mac sender_mac, char* target_ip, char* attacker_ip, uint8_t* attacker_mac);
uint32_t set_arp_packet2(EthArpPacket* packet, Ip sender_ip, Mac sender_mac, Ip target_ip, Ip attacker_ip, Mac attacker_mac);
void* arp_send_attack(void* thread_argv); // thread function
void arp_spoof_flow(pcap_t* handle, pcap_pkthdr* pkt_header, const u_char* packet,  ArpTableThreadArgv* attack_data);
void* arp_infect_thread(void* thread_argv);

