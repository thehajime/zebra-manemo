/*
 * OLSR_Packet.c
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "vty.h"
#include "command.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

unsigned int packet_debug;
unsigned int message_debug[OLSR_MESSAGE_MAX];


u_short pseq;
u_short mseq;

char *(*process_message[]) (char *, struct in6_addr *, struct in6_addr *) =
{
  NULL,
  neighbor_process_hello_message,
  olsr_process_tc_message,
  olsr_process_mid_message,
  olsr_process_hna_message,
  olsr_process_igw_adv,
  NULL
};

const double C = 1.0 / 16.0;

int
olsr_message_encode_time (time_t value)
{
  int a;
  int b = 0;

  double afloat;


  if (!(C <= value) && (olsr_message_decode_time (0xff)))
    return 0;

  while ((value / C) >= (1 << (b + 1)))
    b++;

  afloat = 16 * (value / (C * (1 << b)) - 1);

  /* ceil () ? */
  a = (int) afloat;
  if (a < afloat)
    a++;

  if (a == 16)
    {
      b++;
      a = 0;
    }

  if ((a < 0) || (a > 15) || (b < 0) || (b > 15))
    return 0;

  return (a * 16 + b);
}

time_t
olsr_message_decode_time (int value)
{
  int a, b;

  a = value >> 4;
  b = value & 0xf;

  return C * ((16 + a) << b) / 16.0;
}

char *
olsr_message_create (char *msg, u_char type)
{
  struct olsr_message_header *mh;

  mh = (struct olsr_message_header *) msg;
  memset (mh, 0, sizeof (struct olsr_message_header));

  mh->type = type;
  mh->ttl = OLSR_DEFAULT_TTL;
  mh->hopcount = 0;
  mh->seq = htons (mseq++);
  memcpy (&mh->originator, &olsr.main_addr, sizeof (struct in6_addr));

  switch (type)
    {
    case HELLO_MESSAGE:
      mh->vtime = olsr_message_encode_time ((olsr.hello_validity == -1) ? 
                                            olsr.hello_interval * 3 : olsr.hello_validity);
      break;
    case TC_MESSAGE:
      mh->vtime = olsr_message_encode_time ((olsr.tc_validity == -1) ? 
                                            olsr.tc_interval * 3 : olsr.tc_validity);
      break;
    case MID_MESSAGE:
      mh->vtime = olsr_message_encode_time (MID_HOLD_TIME);
      break;
    default:
      mh->vtime = olsr_message_encode_time (OLSR_DEFAULT_VALIDTIME);
      break;
    }

  return MESSAGE_GET_BODY (msg);
}

char *
olsr_process_mid_message (char *msg, struct in6_addr *recv_addr,
			  struct in6_addr *send_addr)
{
  char *top;
  char *limit;
  time_t now;
  time_t valid_time;

  struct listnode *node, *next;
  struct olsr_message_header *mh;
  struct in6_addr *addrlist;
  struct olsr_ifassoc_tuple *assoc, new;
  struct olsr_link_tuple *lt;

  now = time (NULL);
  mh = (struct olsr_message_header *) msg;
  valid_time = olsr_message_decode_time (mh->vtime);

  top = msg + sizeof (struct olsr_message_header);
  limit = msg + ntohs (mh->size);

  node = listhead (olsr.iface_assoc_set);

  while (node)
    {
      assoc = (struct olsr_ifassoc_tuple *) node->data;
      next = node->next;
      if (IN6_IS_ADDR_SAME (mh->originator, assoc->I_iface_addr))
	olsr_assoc_set_delete (olsr.iface_assoc_set, assoc);
      node = next;
    }

  lt = olsr_link_set_lookup (olsr.link_set, *recv_addr ,*send_addr);
  if (! lt || ! olsr_link_is_SYM (lt))
    {
      zlog_warn ("process MID: not symmetric neighbor");
      return limit;
    }

  for (addrlist = (struct in6_addr *) top;
       addrlist < (struct in6_addr *) limit; addrlist++)
    {
      assoc = olsr_assoc_lookup (olsr.iface_assoc_set, mh->originator,
                                 *addrlist);
      if (assoc == NULL)
	{
	  memset (&new, 0, sizeof (new));
	  memcpy (&new.I_iface_addr, addrlist, sizeof (struct in6_addr));
	  memcpy (&new.I_main_addr, &mh->originator, sizeof (struct in6_addr));
	  new.I_time = now + valid_time;

	  olsr_assoc_set_add (olsr.iface_assoc_set, new);
	}
      else
	assoc->I_time = time (NULL) + valid_time;
    }

  return limit;
}

char *
olsr_generate_mid_message (char *msg)
{
  int cnt = 0;
  int addr_size;
  char *top;

  struct in6_addr addr_list[MAX_ADDR_LIST];
  struct listnode *node;
  struct olsr_message_header *mh;
  struct olsr_ifassoc_tuple *iat;


  memset (addr_list, 0, sizeof (addr_list));
  for (node = listhead (olsr.iface_assoc_set); node; nextnode (node))
    {
      iat = (struct olsr_ifassoc_tuple *) node->data;

      if (!IN6_IS_ADDR_SAME (olsr.main_addr, iat->I_main_addr))
	continue;

      addr_list[cnt++] = iat->I_iface_addr;
    }
  if (cnt == 0)
    return msg;


  addr_size = sizeof (struct in6_addr) * cnt;
  top = olsr_message_create (msg, MID_MESSAGE);
  mh = (struct olsr_message_header *) msg;

  memcpy (top, addr_list, addr_size);
  top += addr_size;
  mh->size = htons (top - msg);

  return (msg + (top - msg));
}


struct olsr_duplicate_tuple *
olsr_message_dup_lookup (struct olsr_message_header *mh)
{
  struct listnode *dn;
  struct olsr_duplicate_tuple *dt;

  for (dn = listhead (olsr.duplicate_set); dn; nextnode (dn))
    {
      dt = (struct olsr_duplicate_tuple *) dn->data;

      if (dt->D_seq_num == ntohs(mh->seq) &&
	  ! memcmp (&dt->D_addr, &mh->originator, sizeof (struct in6_addr)))
	return dt;
    }

  return NULL;
}

void
olsr_duplicate_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;
}

struct olsr_duplicate_tuple *
olsr_duplicate_set_add (struct list *set, struct olsr_duplicate_tuple *new)
{
  struct olsr_duplicate_tuple *dt;

  dt = (struct olsr_duplicate_tuple *)
    malloc (sizeof (struct olsr_duplicate_tuple));
  if (dt == NULL)
    {
      perror ("duplicate_set_add: malloc():");
      return NULL;
    }

  memcpy (dt, new, sizeof (struct olsr_duplicate_tuple));
  listnode_add (set, dt);

  return dt;
}

void
olsr_duplicate_set_add_recv_interface (struct olsr_duplicate_tuple *dt,
				       struct in6_addr recv)
{
  if (dt->D_iface_num >= MAXIFACENUM)
    return;

  memcpy (&dt->D_iface_list[++(dt->D_iface_num)], &recv,
          sizeof (struct in6_addr));

  zlog_info ("duplicate tuple: new recv addr %s (originator: %s, seq: %d)",
             ip6_sprintf (&dt->D_addr), ip6_sprintf (&recv), dt->D_seq_num);
}

void
olsr_duplicate_set_delete (struct list *set,
			   struct olsr_duplicate_tuple *node)
{
  listnode_delete (set, node);
  free (node);
}

void
olsr_duplicate_set_expire_check ()
{
  time_t now;
  struct listnode *node, *next;
  struct olsr_duplicate_tuple *dt;

  now = time (NULL);
  node = listhead (olsr.duplicate_set);

  while (node)
    {
      dt = (struct olsr_duplicate_tuple *) node->data;

      if (dt->D_time < now)
	{
	  next = node->next;
	  olsr_duplicate_set_delete (olsr.duplicate_set, dt);
	  node = next;
	  continue;
	}

      nextnode (node);
    }

  return;
}

int
olsr_message_is_dup_received (struct olsr_duplicate_tuple *ds,
                              struct in6_addr recv)
{
  int i;

  for (i = 0; i < ds->D_iface_num; i++)
    {
      if (! memcmp (&ds->D_iface_list[i], &recv, sizeof (struct in6_addr)))
	return 1;
    }
  return 0;
}


void
olsr_sendmsg (struct olsr_interface_tuple *it, char *msg,
	      struct in6_addr dst, int size)
{
  int retval;
  char *top;
  char packet[MAXPACKETSIZE];
  struct iovec iovec[2];
  struct msghdr smsghdr;
  struct cmsghdr *scmsgp;
  u_char cmsgbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
  struct in6_pktinfo *pktinfo;
  struct olsr_packet_header *ph;
  struct olsr_message_header *mh;
  struct sockaddr_in6 dst_sin6;

  scmsgp = (struct cmsghdr *) cmsgbuf;
  pktinfo = (struct in6_pktinfo *) (CMSG_DATA (scmsgp));
  memcpy (&pktinfo->ipi6_addr, &it->link_local_addr, sizeof (struct in6_addr));
  pktinfo->ipi6_ifindex = it->ifindex;

  memset (packet, 0, MAXPACKETSIZE);
  ph = (struct olsr_packet_header *) packet;
  ph->length = htons (size + sizeof (struct olsr_packet_header));
  ph->seq = htons (pseq++);

  mh = (struct olsr_message_header *) (ph + 1);

  top = packet + sizeof (struct olsr_packet_header);
  memcpy (top, msg, size);
  iovec[0].iov_base = packet;
  iovec[0].iov_len = size + sizeof (struct olsr_packet_header);
  iovec[1].iov_base = NULL;
  iovec[1].iov_len = 0;

  memset (&dst_sin6, 0, sizeof (dst_sin6));
  dst_sin6.sin6_family = AF_INET6;
  dst_sin6.sin6_addr = dst;
  dst_sin6.sin6_port = htons (OLSR_PORT_NUMBER);
#ifdef SIN6_LEN
  dst_sin6.sin6_len = sizeof (struct sockaddr_in6);
#endif /*SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
  dst_sin6.sin6_scope_id = it->ifindex;
#endif

  scmsgp->cmsg_level = IPPROTO_IPV6;
  scmsgp->cmsg_type = IPV6_PKTINFO;
  scmsgp->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

  smsghdr.msg_iov = iovec;
  smsghdr.msg_iovlen = 1;
  smsghdr.msg_name = (caddr_t) & dst_sin6;
  smsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  smsghdr.msg_control = (caddr_t) cmsgbuf;
  smsghdr.msg_controllen = sizeof (cmsgbuf);

  retval = sendmsg (olsr_sock, &smsghdr, 0);
  if (retval != ntohs (ph->length))
    zlog_err ("sendmsg: retval: %d length: %d", retval, ntohs (ph->length));

  return;
}

void
olsr_message_default_forwarding (char *top, struct olsr_duplicate_tuple *ds,
				 struct in6_addr sender, struct in6_addr recv)
{
  int size;
  time_t now;
  char ifname[IFNAMSIZ];

  struct in6_addr dst;
  struct in6_addr main_addr;
  struct listnode *node;
  struct olsr_message_header *mh;
  struct olsr_duplicate_tuple new;
  struct olsr_link_tuple *ls;
  struct olsr_mpr_selector_tuple *mss;
  struct olsr_interface_tuple *it = NULL;
  u_int16_t ttl, hopcount;

  now = time (NULL);
  mh = (struct olsr_message_header *) top;

  ls = olsr_link_set_lookup (olsr.link_set, recv, sender);
  if (ls  && ! olsr_link_is_SYM (ls))
    {
      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        zlog_info ("link_set not found or link is SYM, no forwarding");
      return;
    }

  if (ds && ds->D_retransmitted != DUPLICATE_STATUS_FALSE)
    {
      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        zlog_info ("valid duplicate set, no forwarding");
      return;
    }

  main_addr = *olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set, &sender);
  mss = olsr_mpr_selector_set_lookup (olsr.mpr_selector_set, main_addr);

  if ( ! mss)
    {
      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        zlog_info ("message is not from MPR selector of ours, no forwarding");
      return;
    }

  if (mh->ttl <= 1)
    {
      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        zlog_info ("message has TTL <= 1, no forwarding");
      return;
    }

  if (! ds)
    {
      memset(&new, 0, sizeof(new));
      new.D_addr = mh->originator;
      new.D_seq_num = ntohs (mh->seq);
      ds = olsr_duplicate_set_add (olsr.duplicate_set, &new);

      if (! ds)
        {
          zlog_info ("message: olsr_dupliate_set_add failed, no forwarding");
          return;
        }

      zlog_info ("new duplicate tuple: originator %s seq %d",
                 ip6_sprintf(&ds->D_addr), ds->D_seq_num);
    }

  ds->D_time = now + DUP_HOLD_TIME;
  olsr_duplicate_set_add_recv_interface (ds, recv);

  ttl = ntohs (mh->ttl);
  mh->ttl = htons (--ttl);

  hopcount = ntohs (mh->hopcount);
  mh->hopcount = htons (++hopcount);

  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &dst);
  size = ntohs (mh->size);
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;
      if (! (it->status & ACTIVE))
        continue;

      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        {
          if_indextoname(it->ifindex, ifname);
          zlog_info ("forward type-%d message to %s: originator: %s",
                     mh->type, ifname, ip6_sprintf (&mh->originator));
        }

      olsr_sendmsg (it, top, dst, size);
    }

  return;
}

void
olsr_message_forwarding (char *top, struct olsr_duplicate_tuple *ds,
			 struct in6_addr sender, struct in6_addr recv)
{
  struct olsr_message_header *mh;

  mh = (struct olsr_message_header *) top;
  switch (mh->type)
    {
    case HELLO_MESSAGE: /* HELLO message is NEVER forwarded */
      break;

    case TC_MESSAGE:
    case MID_MESSAGE:
    case HNA_MESSAGE:
    case RA_MESSAGE:
      olsr_message_default_forwarding(top, ds, sender, recv); 
      break;

#if 0
      olsr_message_hna_forwarding(top, ds, sender, recv); 
      break;
#endif

    default:
      break;
    }

  return;
}


void
olsr_process_packet (char *msg, int size, struct in6_addr *sender,
		     struct in6_addr *recv)
{
  int mh_size;
  char *top;
  char *limit;

  struct olsr_duplicate_tuple *ds;
  struct olsr_packet_header *ph;
  struct olsr_message_header *mh;

  ph = (struct olsr_packet_header *) msg;

  if (IS_OLSR_DEBUG_PACKET)
    {
      zlog_info ("process packet: size %d", size);
      zlog_info ("packet: src: %s dst: %s",
                 ip6_sprintf (sender), ip6_sprintf (recv));
      zlog_info ("packet: length %d seqnum %04hx", 
  	          ntohs (ph->length), ntohs (ph->seq));
    }

  /* if packet contains no message */
  if (size <= sizeof (struct olsr_packet_header))
    {
      zlog_info ("packet: contains no data, ignore");
      return;
    }

  top = (char *) (ph + 1);
  limit = msg + ntohs (ph->length);

  while (top < limit)
    {
      mh = (struct olsr_message_header *) top;
      mh_size = ntohs (mh->size);

      /* message logging */
      if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        {
          zlog_info ("message: type: %d vtime: %d size: %d",
                     mh->type, mh->vtime, ntohs (mh->size));
          zlog_info ("message: originator: %s", ip6_sprintf (&mh->originator));
          zlog_info ("message: ttl: %d hopcount: %d seq: %04hx",
     	             mh->ttl, mh->hopcount, ntohs (mh->seq));
        }

      if (mh->ttl == 0)
	{
          if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
	    zlog_info ("message: 0 ttl, ignore");
	  top += mh_size;
	  continue;
	}

      if (! memcmp (&mh->originator, &olsr.main_addr,
                    sizeof (struct in6_addr)))
	{
          if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
	    zlog_info ("message: self-originated, ignore");
	  top += mh_size;
	  continue;
	}

      if ((ds = olsr_message_dup_lookup (mh)) == NULL)
	{
	  if (process_message[mh->type] != NULL)
	    process_message[mh->type] (top, recv, sender);
	}
      else
        {
          if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
            zlog_info ("message: duplicated, not processed");
	  top += mh_size;
	  continue;
        }

      if (! ds || ! olsr_message_is_dup_received (ds, *recv))
	olsr_message_forwarding (top, ds, *sender, *recv);
      else if (IS_OLSR_DEBUG_MESSAGE_TYPE (mh->type))
        zlog_info ("message: no dup or already received, ignore");

      top += mh_size;
    }
}

int
olsr_recvmsg (int sock, struct in6_addr *src, struct in6_addr *dst,
	      u_int * ifindex, struct iovec *msg)
{
  int retval;
  struct msghdr rmsghdr;
  struct cmsghdr *rcmsgp;
  u_char cmsgbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
  struct in6_pktinfo *pktinfo;
  struct sockaddr_in6 src_sin6;

  rcmsgp = (struct cmsghdr *) cmsgbuf;
  pktinfo = (struct in6_pktinfo *) (CMSG_DATA (rcmsgp));
  memset (&src_sin6, 0, sizeof (struct sockaddr_in6));

  rcmsgp->cmsg_level = IPPROTO_IPV6;
  rcmsgp->cmsg_type = IPV6_PKTINFO;
  rcmsgp->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

  rmsghdr.msg_iov = msg;
  rmsghdr.msg_iovlen = 1;
  rmsghdr.msg_name = (caddr_t) & src_sin6;
  rmsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  rmsghdr.msg_control = (caddr_t) cmsgbuf;
  rmsghdr.msg_controllen = sizeof (cmsgbuf);

  retval = recvmsg (sock, &rmsghdr, 0);
  if (retval < 0)
    perror ("olsr_recvmsg: recvmsg()");

  *src = src_sin6.sin6_addr;
  *dst = pktinfo->ipi6_addr;
  *ifindex = pktinfo->ipi6_ifindex;

  return retval;
}

int
olsr_receive (struct thread *thread)
{
  int sock;
  int len;
  u_int ifindex;
  char recvbuf[MAXPACKETSIZE];
  struct iovec iovector[2];
  struct in6_addr src, dst;
  struct olsr_interface_tuple *it;

  sock = THREAD_FD (thread);
  thread_add_read (master, olsr_receive, NULL, sock);

  memset (recvbuf, 0, MAXPACKETSIZE);
  iovector[0].iov_base = recvbuf;
  iovector[0].iov_len = MAXPACKETSIZE;
  iovector[1].iov_base = NULL;
  iovector[1].iov_len = 0;

  len = olsr_recvmsg (sock, &src, &dst, &ifindex, iovector);
  if (!(it = olsr_interface_lookup_by_ifindex (olsr.interface_set, ifindex)))
    return 0;

  /* discard self originate packet */
  if (! memcmp (&it->local_iface_addr, &src, sizeof (struct in6_addr)))
    { 
      if (IS_OLSR_DEBUG_PACKET)
        zlog_warn ("message: self-originated packet, ignore recv=%s, self=%s",
	ip6_sprintf(&it->local_iface_addr), ip6_sprintf(&src));
      return len;
    }

  olsr_process_packet (recvbuf, len, &src, &it->local_iface_addr);
  return len;
}

#define OLSR_STR "Optimized Link State Routing Information\n"
#define PACKET_STR "OLSR Packet Information\n"
#define MESSAGE_STR "OLSR Message Information\n"

DEFUN (debug_olsr_packet,
       debug_olsr_packet_cmd,
       "debug olsr packet",
       DEBUG_STR
       OLSR_STR
       PACKET_STR)
{
  OLSR_DEBUG_PACKET_ON;
  return CMD_SUCCESS;
}

DEFUN (no_debug_olsr_packet,
       no_debug_olsr_packet_cmd,
       "no debug olsr packet",
       NO_STR
       DEBUG_STR
       OLSR_STR
       PACKET_STR)
{
  OLSR_DEBUG_PACKET_OFF;
  return CMD_SUCCESS;
}

DEFUN (debug_olsr_message,
       debug_olsr_message_cmd,
       "debug olsr message (hello|tc|mid|hna)",
       DEBUG_STR
       OLSR_STR
       MESSAGE_STR
       "Hello message\n"
       "Topology Control message\n"
       "Multiple Interface Descriminator\n"
       "Host Network Association\n")
{
  if (! strncmp (argv[0], "he", 2))
    OLSR_DEBUG_MESSAGE_ON (HELLO);
  if (! strncmp (argv[0], "tc", 2))
    OLSR_DEBUG_MESSAGE_ON (TC);
  if (! strncmp (argv[0], "mi", 2))
    OLSR_DEBUG_MESSAGE_ON (MID);
  if (! strncmp (argv[0], "hn", 2))
    OLSR_DEBUG_MESSAGE_ON (HNA);
  return CMD_SUCCESS;
}

DEFUN (no_debug_olsr_message,
       no_debug_olsr_message_cmd,
       "no debug olsr message (hello|tc|mid|hna)",
       NO_STR
       DEBUG_STR
       OLSR_STR
       MESSAGE_STR
       "Hello message\n"
       "Topology Control message\n"
       "Multiple Interface Descriminator\n"
       "Host Network Association\n")
{
  if (! strncmp (argv[0], "hello", 5))
    OLSR_DEBUG_MESSAGE_OFF (HELLO);
  if (! strncmp (argv[0], "tc", 2))
    OLSR_DEBUG_MESSAGE_OFF (TC);
  if (! strncmp (argv[0], "mi", 2))
    OLSR_DEBUG_MESSAGE_OFF (MID);
  if (! strncmp (argv[0], "hn", 2))
    OLSR_DEBUG_MESSAGE_OFF (HNA);
  return CMD_SUCCESS;
}

struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",
  1 /* VTYSH */
};

int
config_write_debug (struct vty *vty)
{
  if (IS_OLSR_DEBUG_PACKET)
    vty_out (vty, "debug olsr packet%s", VNL);
  if (IS_OLSR_DEBUG_MESSAGE (HELLO))
    vty_out (vty, "debug olsr message hello%s", VNL);
  if (IS_OLSR_DEBUG_MESSAGE (TC))
    vty_out (vty, "debug olsr message tc%s", VNL);
  if (IS_OLSR_DEBUG_MESSAGE (MID))
    vty_out (vty, "debug olsr message mid%s", VNL);
  if (IS_OLSR_DEBUG_MESSAGE (HNA))
    vty_out (vty, "debug olsr message hna%s", VNL);
  vty_out (vty, "!%s", VNL);
  return 0;
}

void
olsr_packet_init ()
{
  install_node (&debug_node, config_write_debug);
  install_element (CONFIG_NODE, &debug_olsr_packet_cmd);
  install_element (CONFIG_NODE, &no_debug_olsr_packet_cmd);
  install_element (CONFIG_NODE, &debug_olsr_message_cmd);
  install_element (CONFIG_NODE, &no_debug_olsr_message_cmd);
}



