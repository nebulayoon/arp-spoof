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


uint8_t* get_host_mac(ifreq ifr, ifconf ifc, char* interface_name);
char* get_host_ip(ifreq ifr, char* interface_name);
Mac get_sender_mac(pcap_t* handle, Ip sender_ip, Ip attacker_ip, Mac attacker_mac);
