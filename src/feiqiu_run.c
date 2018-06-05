#include "feiqiu.c"

int
main(int argc, char const *argv[])
{
	const char filter[] = "dst host 192.168.19.49";
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *pcap_file = "f.pcap";

	pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
	if (!handle) {
		fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
		exit(1);
	}

	// compile filter
	struct bpf_program fcode;

	if (-1 == pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
		fprintf(stderr, "Pcap_compile(): %s\n", pcap_geterr(handle));
		pcap_close(handle);
		exit(1);
	}
	if (strlen(filter) != 0) {
		printf("Filter: %s\n", filter);
	}

	int total_amount = 0;
	int total_bytes = 0;
	void *feiqiu_handle;
	void *userdata;

	const char *protodata;   // tcp data
	int len;
	feiqiu_file_proto_init(&feiqiu_handle, userdata);
	while (1) {
		struct pcap_pkthdr *cap_header = NULL;
		const u_char *packet = NULL;
		int ret = pcap_next_ex(handle, &cap_header, &packet);
		if (ret == 1) {
			if (pcap_offline_filter(&fcode, cap_header, packet) != 0) {
				total_amount++;
				total_bytes += cap_header->caplen;

				// real work begin.
				caught_packet(cap_header, packet, &protodata, &len);
				feiqiu_file_proto_run((feiqiu **)&feiqiu_handle, protodata,len);
			} // end if 
		} //end if sucess
		else if (ret == 0) {
			printf("Timeout\n");
		} // end if timeout
		else if (ret == -1) {
			fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
		}
		else if (ret == -2) {
			printf("No more packet from file\n");
			break;
		}
	}
	printf("%d\n", total_amount);
}

