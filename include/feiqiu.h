/* feiqiu headers */

#ifndef __FEIQIU_H
#define __FEIQIU_H


/* feiqiu handle init */
int
feiqiu_file_proto_init(void **handle, void *userdata);


/* catch packet, do something despending on what's inside */
void
feiqiu_file_proto_run(feiqiu **handle, const char *protodata, int len);

/* if having new file attr, fill new handle */
int
new_file_fill_handle(feiqiu **handle, const char *protodata);


/* done callback. do whatever you want with the file just recoveried */
void
feiqiu_file_proto_done_callback(feiqiu **handle, char *filename, char *filepath, void *userdata);

/* destory handle */
int 
feiqiu_file_proto_destory(void **handle);

/* caught packet, parse it, get some userful portion */
void 
caught_packet(const struct pcap_pkthdr *cap_header, const u_char *packet, const char **protodata, int *len); 

/* according to packet format, decode tcp */
int 
decode_tcp(const u_char *header_start);

/* dump packet data, for debug */
void
dump(const unsigned char *data_buffer, const unsigned int length);


#endif  /* __FEIQIU_H */
