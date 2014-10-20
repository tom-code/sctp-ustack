#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include <thread>
#include <memory>
#include <mutex>
#include <condition_variable>

#include "crc.h"
#include "sctp_defs.h"


static int insert_crc32(unsigned char *buffer, unsigned int length)
{
  message_t *message;
  unsigned long crc32;
  message = (message_t *) buffer;
  message->common_header.checksum = 0L;
  crc32 = generate_crc32c(buffer,length);
  message->common_header.checksum = htonl(crc32);
  return 1;
}

class queue_t {
  static const int max = 200;
  std::shared_ptr<packet_buffer_t> buf[max];
  int first = 0;
  int last = 0;
  int amount = 0;
  std::mutex mutex;
  std::condition_variable cv;

 public:
  bool add(std::shared_ptr<packet_buffer_t> &b) {
    std::unique_lock<std::mutex> lock(mutex);

    if (amount >= max) return false;
    buf[last] = b;
    last++;
    if (last >= max) last = 0;
    amount++;
    cv.notify_one();
    return true;
  }

  std::shared_ptr<packet_buffer_t> get() {
    std::unique_lock<std::mutex> lock(mutex);
    if (amount == 0) cv.wait(lock, [this]{return amount > 0;});

    if (amount == 0) return nullptr;
    std::shared_ptr<packet_buffer_t> ret = buf[first];
    buf[first] = nullptr;
    first++;
    if (first >= max) first = 0;
    amount--;
    return ret;
  }
};

class connection_t
{
 public:
  queue_t queue;
  std::thread serving_thread;

  struct sockaddr_in srv;
  int fd;
  uint32_t verification = 0;
  int local_port;
  int remote_port;

  connection_t() {
  }
  
  void fill_common_pars(packet_buffer_t *buf) {
    message_t *m = (message_t*)buf->get();
    m->common_header.src_port = htons(local_port);
    m->common_header.dst_port = htons(remote_port);
    m->common_header.verification_tag = verification;
    buf->skip(sizeof(common_header_t));
  }

  void send_buf(packet_buffer_t *b) {
    int leno = b->get_ptr();
    insert_crc32(b->data, leno);
    sendto(fd, b->data, leno, 0, (struct sockaddr*)&srv, sizeof(srv));
  }

  void send_cookie_echo(const unsigned char *cookie, int cookie_len) {
    packet_buffer_t bufo;
    fill_common_pars(&bufo);
  
    chunk_header_t *chunk1 = (chunk_header_t*)(bufo.get());
    chunk1->type = CHUNK_COOKIE_ECHO;
    chunk1->flags = 0;
    chunk1->len = htons(sizeof(chunk_header_t)+cookie_len);
    bufo.skip(sizeof(chunk_header_t));
    memcpy(bufo.get(), cookie, cookie_len);
    bufo.skip(cookie_len);
  
    send_buf(&bufo);
  }

  void decode_init_ack(packet_buffer_t *buf) {
    init_chunk_t *ack_chunk = (init_chunk_t*)buf->get();
    int len = htons(ack_chunk->header.len);
    unsigned char cookie[1024*32];
    int cookie_len;
    buf->skip(sizeof(init_chunk_t));
  
    len -= sizeof(init_chunk_t);
    while (len > 0) {
      uint16_t opt_type = htons(*((uint16_t*)buf->get()));
      buf->skip(2);
      uint16_t opt_len = htons(*((uint16_t*)buf->get()));
      buf->skip(2);
      printf("opt type=%d\n", opt_type); 
      if (opt_type == 7) {
        cookie_len = opt_len-4;
        memcpy(cookie, buf->get(), cookie_len);
      }
      buf->skip(opt_len-4);
      len -= opt_len;
    }
  
    verification = ack_chunk->init;
  
    send_cookie_echo(cookie, cookie_len);
  }

  void send_sack(uint32_t tsn) {
    packet_buffer_t bufo;
    fill_common_pars(&bufo);
  
    sack_chunk_t *chunk1 = (sack_chunk_t*)(bufo.get());
    chunk1->header.type = CHUNK_SACK;
    chunk1->header.flags = 0;
    chunk1->header.len = htons(sizeof(sack_chunk_t));
    chunk1->tsn = tsn;
    chunk1->a_rwnd = htonl(1000000);
    chunk1->num_acks = 0;
    chunk1->num_dups = 0;
    bufo.skip(sizeof(sack_chunk_t));
  
    send_buf(&bufo);
  }
  
  void shutdown() {
    printf("shutdown\n");
    packet_buffer_t bufo;
    fill_common_pars(&bufo);
  
    chunk_header_t *chunk1 = (chunk_header_t*)(bufo.get());
    chunk1->type = CHUNK_SHUTDOWN_ACK;
    chunk1->flags = 0;
    chunk1->len = htons(sizeof(chunk_header_t));
    bufo.skip(sizeof(chunk_header_t));
  
    send_buf(&bufo);
  }
  
  int total_data = 0;
  int sck = 0;
  uint32_t last_tsn;
  void decode_data(packet_buffer_t *buf) {
    data_chunk_t *data = (data_chunk_t*)buf->get();
    total_data+=htons(data->header.len);
  
    //if (htonl(data->tsn) != (last_tsn+1)) printf("missing packet %x \n", last_tsn);
    sck++;
    if (sck >2) {
      send_sack(data->tsn);
      sck = 0;
    }
    last_tsn = htonl(data->tsn);
  }
  
  void decode_packet(packet_buffer_t *buf, const int total) {
    buf->skip(sizeof(common_header_t));
  
    int tot = total-sizeof(common_header_t);
    while (tot > 0) {
      chunk_header_t *first_chunk = (chunk_header_t*)buf->get();
      int len = htons(first_chunk->len);

      switch (first_chunk->type) {
        case CHUNK_INIT_ACK          : decode_init_ack(buf);          break;
        case CHUNK_DATA              : decode_data(buf);              break;
        case CHUNK_SHUTDOWN          : shutdown();                    break;
        case CHUNK_SHUTDOWN_COMPLETE : printf("shutdown complete\n"); break;
        case CHUNK_COOKIE_ACK        : printf("cookie ack\n");        break;
        default: printf("unknown chunk type %d\n", first_chunk->type);
      }
  
      buf->skip(len);
      tot = tot-len;
    }
  }
 
  void connect(int local_porti, int remote_porti, const char *host) {
    serving_thread = std::thread([this]() { thr();});
    local_port = local_porti;
    remote_port = remote_porti;
   
    srv.sin_family = AF_INET;
    struct hostent *he = gethostbyname(host);
    memcpy( &srv.sin_addr.s_addr, he->h_addr, he->h_length);
    srv.sin_port = htons(12345);
  
  
    packet_buffer_t buf;
    fill_common_pars(&buf);

    init_chunk_t *chunk1 = (init_chunk_t*)(buf.get());
    chunk1->header.type = CHUNK_INIT;
    chunk1->header.flags = 0;
    chunk1->header.len = htons(sizeof(init_chunk_t));
  
    chunk1->a_rwnd = htonl(100000);
    chunk1->out_streams = htons(10);
    chunk1->in_streams = htons(65535);
    chunk1->init = htonl(100+local_port);
    chunk1->tsn = chunk1->init;
  
    buf.skip(sizeof(init_chunk_t));
    send_buf(&buf);
  }

  void thr() {
    while (true) {
      std::shared_ptr<packet_buffer_t> b = queue.get();
      decode_packet(b.get(), b->total);
    }
  }
};

struct sctp_t {
  int fd;
  connection_t connections[8];

  void init() {
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
  }

  void connect(int local_port, int remote_port, const char *host) {
    connections[local_port].fd = fd;
    connections[local_port].connect(local_port, remote_port, host);
  }

  void read_loop() {
    struct sockaddr_in srv;
    //packet_buffer_t buf;
    int t = time(NULL);
    int skipped = 0;
    int packets = 0;
    while (true) {
      std::shared_ptr<packet_buffer_t> buf = std::make_shared<packet_buffer_t>();
      buf->reset();
      socklen_t slen = sizeof(srv);
      int r = recvfrom(fd, buf->data, sizeof(buf->data), 0, (struct sockaddr*)&srv, &slen);
      packets++;
      buf->skip(20);

      common_header_t *header = (common_header_t*)buf->get();
      int local_port = htons(header->dst_port);
      buf->total = r-20;
      bool added = connections[local_port].queue.add(buf);
      if (!added) skipped++;
      //connections[local_port].decode_packet(buf.get(), r-20);
  
      int t2 = time(NULL);
      if (t != t2) {
        t = t2;
        printf("skipped %d/%d\n", skipped, packets);
        packets = 0;
        int sum = 0;
        for (int i=0; i<8; i++) {
          printf("total[%d]: %d\n", i, connections[i].total_data);
          sum += connections[i].total_data;
          connections[i].total_data = 0;
        }
        printf("sum=%fMB\n", (float)sum/1024/1024);
      }

    }
  }
};

int main()
{
  sctp_t sctp;
  sctp.init();

  sctp.connect(1, 7777, "172.31.31.13");
  sctp.connect(2, 7777, "172.31.31.13");
  sctp.connect(3, 7777, "172.31.31.13");
  sctp.connect(4, 7777, "172.31.31.13");
//  sctp.connect(5, 7777, "172.31.31.13");

  sctp.read_loop();

  sleep(1);
}
