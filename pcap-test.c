#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test ens33\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        if(*(packet+23) == 0x6){
            printf("%u bytes captured\n", header->caplen);
		
            printf("Ethernet_source = %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet+6), *(packet+7), *(packet+8), *(packet+9), *(packet+10), *(packet+11));
            printf("Ethernet_destination = %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet), *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
		
            printf("IP_source = %u.%u.%u.%u\n", *(packet+26), *(packet+27), *(packet+28), *(packet+29));
            printf("IP_destination = %u.%u.%u.%u\n", *(packet+30), *(packet+31), *(packet+32), *(packet+33));
		
            printf("TCP_source = %u\n", (((*(packet+34))<<8)+(*(packet+35))));
            printf("TCP_destination = %u\n", (((*(packet+36))<<8)+(*(packet+37))));
		
            int i;
	    for(i=1;i<8;i++){
            printf("%02x ", *(packet+(53+i)));
    }
        }
    }
}
