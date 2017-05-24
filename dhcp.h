#include <libnet.h>


void read_config(char*);

void init_context(libnet_t*);

void send_message(libnet_t*, uint8_t, uint32_t, uint32_t, uint8_t*);
