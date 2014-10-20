#include <arpa/inet.h>

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;

  uint32_t verification_tag;
  uint32_t checksum;
} common_header_t;


typedef struct {
  uint8_t type;
  uint8_t flags;
  uint16_t len;
} chunk_header_t;


typedef struct {
  chunk_header_t header;
  uint32_t init;
  uint32_t a_rwnd;
  uint16_t out_streams;
  uint16_t in_streams;
  uint32_t tsn;
} init_chunk_t;

typedef struct {
  chunk_header_t header;
  uint32_t tsn;
  uint32_t a_rwnd;
  uint16_t num_acks;
  uint16_t num_dups;
} sack_chunk_t;

typedef struct {
  chunk_header_t header;
  uint32_t tsn;
} data_chunk_t;


typedef struct {
  common_header_t common_header;
} message_t;

#define CHUNK_DATA              0
#define CHUNK_INIT              1
#define CHUNK_INIT_ACK          2
#define CHUNK_SACK              3
#define CHUNK_SHUTDOWN          7
#define CHUNK_SHUTDOWN_ACK      8
#define CHUNK_COOKIE_ECHO       10
#define CHUNK_COOKIE_ACK        11
#define CHUNK_SHUTDOWN_COMPLETE 14

struct packet_buffer_t {
  unsigned char data[1024*10];
  int ptr = 0;
  int total;

  packet_buffer_t() {
    //memset(data, 0, sizeof(data));
  }

  unsigned char *get() {
    return data+ptr;
  }

  void skip(int n) {
    ptr += n;
  }

  int get_ptr() {
    return ptr;
  }

 void reset() {
   ptr = 0;
 }
};

