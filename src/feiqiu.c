#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "../include/feiqiu_types.h"

int new_file_fill_handle(feiqiu **handle, const char *protodata);
void feiqiu_file_proto_done_callback(feiqiu **handle, char *filename, char *filepath, void *userdata);
void caught_packet(const struct pcap_pkthdr *cap_header, const u_char *packet, const char **protodata, int *len);
void dump(const char *data_buffer, const unsigned int length);
int decode_tcp(const u_char *header_start);


int 
feiqiu_file_proto_init(void **handle, void *userdata)
{
	*handle = malloc(sizeof(feiqiu));

	strcpy((*(feiqiu **)handle)->filepath, "/dev/temp");
	(*(feiqiu **)handle)->userdata = userdata;
	if (!*handle) {
		return (-1);
	} else {
		memset(*handle, 0, sizeof(feiqiu)); // set all 0
		return (0);
	}
}

void
feiqiu_file_proto_run(feiqiu **handle, const char *protodata, int len)
{	
	int packet_data_len, packet_hdr_len = 0;
	const char *ptr_file_data;

	if (len <= 0) {
		return;
	}

	if ((*handle)->current_state == HEADER) { // fill handle
		printf("calling new file handle\n");
		// if header is filled up, change it to DATA
		packet_hdr_len = new_file_fill_handle(handle, protodata);
		// if not filling up header
		if ((*handle)->current_state == HEADER) {
			return;
		}

		// header filled up. open file
		(*handle)->fd = open((*handle)->filename,
				O_RDWR | O_CREAT | O_APPEND,
				S_IRUSR | S_IWUSR);
		if ((*handle)->fd == -1) {
			printf("handle open filename Fails\n");
			return;
		}
	}

	packet_data_len = len - packet_hdr_len;
	ptr_file_data = protodata + packet_hdr_len;  // point to data
	printf("packet_data_len %d\n", packet_data_len);

	while (packet_data_len > 0 && (*handle)->file_size > (*handle)->file_data_already_writen) {
		write((*handle)->fd, ptr_file_data, 1);
		packet_data_len--;
		ptr_file_data++;  
		(*handle)->file_data_already_writen++;
	}

	// if true. last packet writen. mission complete
	if ((*handle)->file_data_already_writen >= (*handle)->file_size) {
		printf("filled up file\n");
		// prepare for next new file.
		close((*handle)->fd);
		(*handle)->file_size = 0;
		(*handle)->current_state = HEADER;
		(*handle)->current_hdr_field = DATA_HDR_LEN;
		(*handle)->file_data_already_writen = 0;
		// file recovery done. callback
		feiqiu_file_proto_done_callback(handle, (*handle)->filename,
				(*handle)->filepath, (*handle)->userdata);
	}

	if (packet_data_len > 0) { // this packet data portion has new file, not done
		feiqiu_file_proto_run(handle, ptr_file_data, packet_data_len);
	}
}

void
feiqiu_file_proto_done_callback(feiqiu **handle, char *filename, char *filepath, void *userdata)
{
	/* do whatever you like to the file just recoveried. */
	printf("in callback\n");
}

int 
feiqiu_file_proto_destory(void **handle)
{
	if (!*handle) {               // if already NULL.an issue
		return (-1);
	}

	free(*handle);             // free handle.
	*handle = NULL;              // point to NULL.
	
	return (0);
}

int
new_file_fill_handle(feiqiu **handle, const char *protodata)
{
	/* called when packet contains file header.
	 * fill handle with filename, filesize etc just parsed out.
	 * return file header length. */

	dump(protodata, strlen(protodata));
	char *p;
	char *string = strdup(protodata);
	p = strtok(string, ":");
	int header_len = 0;  // return value.
	int p_value;
	
	while (p != NULL) {
		header_len += strlen(p) + 1;
		switch ((*handle)->current_hdr_field)
		{
			case DATA_HDR_LEN:
				break;
			case FILE_NAME:
				strcpy((*handle)->filename, p);
				break;
		        case SIZE:
				sscanf(p, "%x", &p_value);
				(*handle)->file_size = p_value;
				break;
			case M_TIME:
				break;
			case FILE_ATTR_ONE:
				break;
			case FILE_ATTR_TWO:
				(*handle)->current_state = DATA;
				return header_len; // finish
		}
		// just for g++ compile success.
		// or you could write
		// (*handle)->current_hdr_field++.
		// but g++ is stricter. all these is to use gtest.
		(*handle)->current_hdr_field = (Pkt_hdr)((*handle)->current_hdr_field + 1);
		p = strtok(NULL, ":");
	}

	return header_len;
}

void
caught_packet(const struct pcap_pkthdr *cap_header, const u_char *packet, const char **protodata, int *len)
{
	int tcp_header_length, total_header_size, pkt_data_len;
	u_char *pkt_data;

	printf("========Got a %d bytes packet ========\n", cap_header->len);
	
	tcp_header_length = decode_tcp(packet+14+sizeof(struct iphdr));

	total_header_size = 14 + sizeof(struct iphdr) + tcp_header_length;
	pkt_data = (u_char *)packet + total_header_size; // point to data portion.
	pkt_data_len = cap_header->len - total_header_size;

	*protodata = (const char *)pkt_data;

	*len = pkt_data_len;

	if (*len > 0 && *len != 79) {
		dump(*protodata, *len);
	} else {
		printf("\t\tNo packet data\n");
	}
}

int 
decode_tcp(const u_char *header_start)
{
	int header_size;
	const struct tcphdr *tcp_header;

	tcp_header = (const struct tcphdr *)header_start;
	header_size = 4 * tcp_header->th_off;

	return header_size;
}


void
dump(const char *data_buffer, const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;
	for (i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);
		if (((i%16) == 15) || (i == length-1)) {
			for (j = 0; j < 15 - (i % 16); j++) 
				printf("  ");
			printf("| ");
			for (j=(i-(i%16)); j <= i; j++) {
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		} // end if
	} //end for
}

	


		
	


