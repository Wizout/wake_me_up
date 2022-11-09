#include <libnet.h>
#include <sys/types.h>
#include <iostream>
#include <cassert>
#include <cstring>

void usage(char *prog) {
  fprintf(stderr, "Usage: %s -d dst_mac_addr [-i interface] [-s src_ip]\n", prog);
  exit(1);
}

void set_target_mac_addr(uint8_t dst[], const char* src) {
  assert(nullptr != dst);
  const size_t mac_addr_len = 2 * 6 + 5;

  if (nullptr == src || mac_addr_len != strnlen(src, mac_addr_len)) {
    std::cerr << "Undefined or Invalid Target MAC Addr Detected!" << std::endl;

    // Set to Default Target MAC Addr: 58:11:22:2d:fe:a5
    uint16_t* p = reinterpret_cast<uint16_t*>(dst);
    *p++ = 0x1158;
    *p++ = 0x2d22;
    *p = 0xa5fe;

    return;
  }

  auto convert_atoi {
    [] (const char c) -> uint8_t {
      if ('0' <= c && c <= '9')
        return c - '0';
      else if ('a' <= c && c <= 'f')
        return c - 'a' + 0x0a;
      else if ('A' <= c && c <= 'F')
        return c - 'A' + 0x0a;
      else
        return 0;
    }
  };

  for (size_t i = 0; i < mac_addr_len; i += 3)
    dst[i / 3] = (convert_atoi(src[i]) << 4) + convert_atoi(src[i + 1]);

  return;
}

int wol(int argc, char *argv[]) {
  char c;
  u_long src_ip = 0, dst_ip = 0xFFFFFFFF;
  libnet_t *l;

  libnet_ptag_t ip;
  libnet_ptag_t ptag4; /* TCP or UDP ptag */
  libnet_ptag_t ethernet;

  char errbuf[LIBNET_ERRBUF_SIZE];
  char payload[256];
  u_short payload_s;

  char* device{ nullptr }, *target_mac{ nullptr };

  /*
   * parse options
   */
  while ((c = getopt(argc, argv, "d:i")) != EOF) {
    switch (c) {
      case 'd':
        target_mac = optarg;
        std::cout << "Received Target MAC Addr: " << target_mac << std::endl;
        break;
      case 'i':
        device = optarg;
        break;
      default:
        exit(EXIT_FAILURE);
    }
  }

  // Parse Target MAC Addr from input
  uint8_t enet_dst[6]{ /* 0x2c, 0xf0, 0x5d, 0x8c, 0xce, 0xdf */ };
  set_target_mac_addr(enet_dst, target_mac);

  std::cout << "Parsed Target MAC Addr: " << std::hex << (int)enet_dst[0];
  for (auto i = 1; i < sizeof enet_dst; ++i)
    std::cout << ':' << (int)enet_dst[i];
  putchar('\n');

  /*
   *  Initialize the library.  Root privileges are required.
   */
  l = libnet_init(
      LIBNET_RAW4,              /* injection type */
      device,                 /* network interface */
      errbuf);                /* error buffer */

  if (nullptr == l) {
    fprintf(stderr, "libnet_init: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (0 == src_ip)
    src_ip = libnet_get_ipaddr4(l);

  /*
   * build WoL payload
   */
  const int sync_stream_len{ 6 }, mac_duplicate_times{ 16 };
  uint8_t enet_brdcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  memset(payload, 0, sizeof payload);

  for (int i = 0; i < sync_stream_len; ++i)
    payload[i] = enet_brdcast[i];
  payload_s = sync_stream_len;

  for (int i = 0; i < mac_duplicate_times; ++i) {
    for (int j = 0; j < sizeof enet_dst; ++j)
      payload[sync_stream_len + i * 6 + j] = enet_dst[j];
  }
  payload_s = payload_s + mac_duplicate_times * sizeof enet_dst;


  uint16_t total_length = payload_s + LIBNET_UDP_H;

  /*
   * build packet
   */

  ptag4 = libnet_build_udp(
    0x6666,                /* source port */
    9,                  /* destination port */
    total_length, /* packet length */
    0,                    /* checksum */
    reinterpret_cast<const uint8_t*>(payload),                   /* payload */
    payload_s,                    /* payload size */
    l,                    /* libnet handle */
    0                     /* libnet id */
  );

  if (ptag4 == -1) {
    fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    return (EXIT_FAILURE);
  }

  total_length += LIBNET_IPV4_H;
  ip = libnet_build_ipv4(
    total_length,/* length */
    0,                      /* TOS */
    242,                    /* IP ID */
    0,                      /* IP Frag */
    64,                     /* TTL */
    IPPROTO_UDP,                /* protocol */
    0,                      /* checksum */
    src_ip,                   /* source IP */
    dst_ip,                   /* destination IP */
    nullptr,                     /* payload */
    0,                      /* payload size */
    l,                      /* libnet handle */
    0                        /* libnet id */
  );

  if (ip == -1) {
    fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
    exit(EXIT_FAILURE);
  }


  ethernet = libnet_build_ethernet(
    enet_brdcast,  // dst
    libnet_get_hwaddr(l)->ether_addr_octet, // src
    IPPROTO_IP, // type
    nullptr, // payload
    0, // payload length
    l, // libnet context handle
    0 // ptag
  );

  /*
   * write to the wire
   */
  int retVal = libnet_write(l);
  if (retVal == -1) {
    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    return (EXIT_FAILURE);
  }
  else
    fprintf(stderr, "Wrote %d byte WoL packet; check the wire.\n", retVal);

  libnet_destroy(l);
  return (EXIT_SUCCESS);
}
