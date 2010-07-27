#ifndef _OLSR_PACKET_H_
#define _OLSR_PACKET_H_

#include <sys/types.h>

#pragma pack(1)

/* 
 * Message Types
 */

#define	HELLO_MESSAGE	1
#define	TC_MESSAGE	2
#define	MID_MESSAGE	3
#define	HNA_MESSAGE	4
#define RA_MESSAGE	5
#define OLSR_MESSAGE_MAX 6

/*
 * TC Message Redundancy
 */

#define TC_REDUNDANCY_BASIC	0
#define TC_REDUNDANCY_EXTENDED	1
#define TC_REDUNDANCY_FULL	2


/*****************
 * Packet Format *
 *****************/

/***********
    Common packet header and message header format

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Packet Length         |    Packet Sequence Number     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Message Type |     Vtime     |         Message Size          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Originator Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Time To Live |   Hop Count   |    Message Sequence Number    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      :                            MESSAGE                            :
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Message Type |     Vtime     |         Message Size          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Originator Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Time To Live |   Hop Count   |    Message Sequence Number    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      :                            MESSAGE                            :
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      :                                                               :

 ***********/

struct olsr_packet_header
{
  u_int16_t length;
  u_int16_t seq;
};

struct olsr_message_header
{
  u_char type;
  u_char vtime;
  u_int16_t size;
  struct in6_addr originator;
  u_char ttl;
  u_char hopcount;
  u_int16_t seq;
};





/***********************
 * Message body format *
 ***********************/

/***********
    MID Message Format

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    OLSR Interface Address                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    OLSR Interface Address                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 ***********/

struct mid_message
{
  struct in6_addr iface_addr;
};




/***********
    Hello Message Format
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Reserved             |     Htime     |  Willingness  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Link Code   |   Reserved    |       Link Message Size       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Neighbor Interface Address                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Neighbor Interface Address                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      :                             .  .  .                           :
      :                                                               :
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Link Code   |   Reserved    |       Link Message Size       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Neighbor Interface Address                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Neighbor Interface Address                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      :                                                               :

 ***********/

#define NOT_NEIGH	0
#define SYM_NEIGH	1
#define MPR_NEIGH	2


struct hello_header
{
  u_int16_t reserved;
  char htime;
  char willingness;
};

struct hello_body
{
  char linkcode;
  char reserved;
  u_int16_t link_message_size;
};




/***********
    TC Message Format

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |              ANSN             |           Reserved            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |               Advertised Neighbor Main Address                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |               Advertised Neighbor Main Address                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 ***********/

struct tc_header
{
  u_int16_t ANSN;
  u_int16_t reserved;
};

struct tc_body
{
  struct in6_addr an_main_addr;
};

/***********
     HNA Message Format for IPv4

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Network Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Netmask                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Network Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Netmask                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The structure below shows the IPv6 version of HNA message.

 ***********/

struct hna_message {
	struct in6_addr	nw_addr;
	u_char		plen;
	u_char		reserved1;
	u_short		reserved2;
};


/***********
    Internet Gateway Advertisement TLV for OLSRv2

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |  Length     |L|  Reserved     |  IGWPrefix    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      .                     IGW Address                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      .                  IGW Prefix (IGW global address)              .
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |               IGW  Prefix Preferred Lifetime                  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The structure below shows the message format for OLSRv1.

 ***********/

struct igw_adv_message {
    u_int16_t reserved1;
    u_int8_t reserved2;
    u_int8_t igw_plen;
    struct in6_addr igw_addr;
    struct in6_addr igw_prefix;
    u_int32_t igw_lifetime;
};



#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO IPV6_RECVPKTINFO
#endif

#define DUPLICATE_STATUS_FALSE	0
#define DUPLICATE_STATUS_TRUE	1

#define DEFAULT_MESSAGE_SIZE	1024
#define OLSR_DEFAULT_TTL	255

#define MAXPACKETSIZE		1500


#define MESSAGE_GET_HEADER(packet_top) \
	(packet_top + sizeof(struct olsr_packet_header))

#define MESSAGE_GET_BODY(msg_top) \
	(msg_top + sizeof(struct olsr_message_header))

#define PACKET_GET_BODY(top) \
	(top + sizeof(struct olsr_packet_header) + sizeof(struct olsr_message_header))

#define MESSAGE_GET_MID_SIZE(cnt) \
	(sizeof(struct olsr_message_header) + (cnt * sizeof(struct in6_addr)))

extern u_short pseq;		/* Packet sequence number */
extern u_short mseq;		/* Message sequence number */

extern u_short ansn;

extern struct olsr_duplicate_set *duplicate_tuple;


static __inline void
olsr_packet_set_header (char *packet, int length)
{
  struct olsr_packet_header *ph;

  ph->length = length;
  ph->seq++;

  return;
}

extern unsigned int packet_debug;
#define IS_OLSR_DEBUG_PACKET (packet_debug)
#define OLSR_DEBUG_PACKET_ON \
  do { packet_debug = 1; } while (0)
#define OLSR_DEBUG_PACKET_OFF \
  do { packet_debug = 0; } while (0)

extern unsigned int message_debug[OLSR_MESSAGE_MAX];
#define IS_OLSR_DEBUG_MESSAGE_TYPE(t) (message_debug[(t)])
#define IS_OLSR_DEBUG_MESSAGE(t) (message_debug[t ## _MESSAGE])
#define OLSR_DEBUG_MESSAGE_ON(t) \
  do { message_debug[t ## _MESSAGE] = 1; } while (0)
#define OLSR_DEBUG_MESSAGE_OFF(t) \
  do { message_debug[t ## _MESSAGE] = 0; } while (0)

char *olsr_message_create (char *, u_char);
void olsr_process_packet (char *, int, struct in6_addr *, struct in6_addr *);
void olsr_sendmsg (struct olsr_interface_tuple *, char *, struct in6_addr, int);

char *neighbor_process_hello_message (char *, struct in6_addr *, struct in6_addr *);
char *olsr_process_tc_message (char *, struct in6_addr *, struct in6_addr *);
char *olsr_process_mid_message (char *, struct in6_addr *, struct in6_addr *);
char *olsr_process_hna_message (char *, struct in6_addr *, struct in6_addr *);
char *olsr_process_igw_adv (char *, struct in6_addr *, struct in6_addr *);

char *neighbor_generate_hello_message (char *, struct olsr_interface_tuple *);
char *olsr_generate_mid_message (char *);

int olsr_message_encode_time (time_t value);
time_t olsr_message_decode_time (int);

int olsr_receive (struct thread *);
int olsr_hello_send_thread ();
int olsr_mid_send_thread ();
int olsr_tc_send_thread ();
int olsr_hna_send_thread ();
int olsr_igwadv_send_thread ();

void olsr_packet_init ();

#endif /* _OLSR_PACKET_H_ */

