/* feiqiu types */

#ifndef __FEIQIU_TYPES_H
#define __FEIQIU_TYPES_H

typedef enum {
	HEADER,
	DATA
} State;

typedef enum {
	DATA_HDR_LEN,
	FILE_NAME,
	SIZE,
	M_TIME,
	FILE_ATTR_ONE,
	FILE_ATTR_TWO
} Pkt_hdr;

typedef struct feiqiu_handle {
	int file_size;
	int file_data_already_writen;
	char filepath[512];
	char filename[512];
	void *userdata;
	int fd;
	State current_state;
	Pkt_hdr current_hdr_field;
} feiqiu;

#endif   /* __FEIQIU_TYPES_H */
