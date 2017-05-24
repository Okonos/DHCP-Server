#include <libnet.h>


void read_config(char*);

void init_context(libnet_t*);

char* ipaddr_to_str(uint32_t);

void reply(libnet_t*, int, unsigned char*, uint32_t, uint8_t*);
