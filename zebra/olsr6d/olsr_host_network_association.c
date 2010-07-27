/*
 * OLSR_Host_Network_Association.c
 */

#include <zebra.h>

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"


struct olsr_nwassoc_tuple *
olsr_nwassoc_set_lookup (struct list *set, struct in6_addr gw_addr,
                   struct in6_addr nw_addr, int plen)
{
  struct listnode *node;
  struct olsr_nwassoc_tuple *nat;

  for (node = listhead (set); node; nextnode (node))
    {
      nat = (struct olsr_nwassoc_tuple *) node->data;

      if (IN6_IS_ADDR_SAME (nat->A_gateway_addr, gw_addr) &&
          IN6_IS_ADDR_SAME (nat->A_network_addr, nw_addr) &&
          (nat->A_plen == plen) )
        return nat;
    }

  return NULL;
}

DEFUN (show_ipv6_olsr6_network_association,
       show_ipv6_olsr6_network_association_cmd,
       "show ipv6 olsr6 network association",
       SHOW_STR
       IP6_STR
       OLSR6_STR
       "Network Association list\n")
{
  char nw_addr[40];
  char gw_addr[40];
  struct listnode *node;
  struct olsr_nwassoc_tuple *nat;

  vty_out (vty, "%-30s %15s%10s%s", "Network Addr", "Gateway Addr", "PLEN", VNL);

  for (node = listhead (olsr.nw_assoc_set); node; nextnode (node))
    {
      nat = (struct olsr_nwassoc_tuple *) node->data;
      inet_ntop (AF_INET6, &nat->A_network_addr, nw_addr, sizeof (nw_addr));
      inet_ntop (AF_INET6, &nat->A_gateway_addr, gw_addr, sizeof (gw_addr));
      vty_out (vty, "%-30s %15s%10d%s", nw_addr, gw_addr, nat->A_plen, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_nwassoc_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_network_association_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_network_association_cmd);
}

void
olsr_message_hna_forwarding (char *top, struct olsr_duplicate_tuple *ds,
				 struct in6_addr sender, struct in6_addr recv)
{
  int size;
  time_t now;
  char ifname[IFNAMSIZ];

  struct in6_addr dst;
  struct in6_addr null_addr;
  struct in6_addr main_addr;
  struct listnode *node;
  struct olsr_message_header *mh;
  struct olsr_duplicate_tuple new;
  struct olsr_link_tuple *ls;
  struct olsr_mpr_selector_tuple *mss;
  struct hna_message *hm;
  struct olsr_interface_tuple *it = NULL;
  u_int16_t ttl, hopcount;

  now = time (NULL);
  mh = (struct olsr_message_header *) top;
  hm = (struct hna_message *) (mh + 1);

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

  memset (&null_addr, 0, sizeof (null_addr));
  if (IN6_IS_ADDR_SAME (hm->nw_addr, null_addr) && (hm->plen == 0))
       mh->originator = olsr.main_addr;
 
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;
      if (it->status & ACTIVE)
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
olsr_nwassoc_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;
}

struct olsr_nwassoc_tuple *
olsr_nwassoc_set_add (struct list *set, struct olsr_nwassoc_tuple tuple)
{
  struct olsr_nwassoc_tuple *new;

  if ((new =
       (struct olsr_nwassoc_tuple *)
       malloc (sizeof (struct olsr_nwassoc_tuple))) == NULL)
    {
      perror ("olsr_nwassoc_set_add: malloc()");
      return NULL;
    }

  *new = tuple;
  listnode_add (set, new);

  return new;
}

void
olsr_nwassoc_set_delete (struct list *set, struct olsr_nwassoc_tuple *tuple)
{
  listnode_delete (set, tuple);
  free (tuple);

  return;
}

void
olsr_nwassoc_set_destroy (struct list **set)
{
  list_delete_all_node (*set);
  *set = NULL;

  return;
}

char *
olsr_generate_hna_message (char *msg)
{
  int cnt = 0;
  char *top;

  struct in6_addr addr_list[MAX_ADDR_LIST];
  struct listnode *node;
  struct olsr_message_header *mh;
  struct hna_message *hm;
  struct olsr_nwassoc_tuple *nat;


  memset (addr_list, 0, sizeof (addr_list));
  mh = (struct olsr_message_header *)msg;
  top = (char *)(mh + 1);

  for (node = listhead (olsr.nw_assoc_set); node; nextnode (node))
    {
      nat = (struct olsr_nwassoc_tuple *) node->data;

      if (!IN6_IS_ADDR_SAME (olsr.main_addr, nat->A_gateway_addr))
        continue;

      memset(top, 0, sizeof(struct hna_message));
      hm = (struct hna_message *)top;

      hm->nw_addr = nat->A_network_addr;
      hm->plen = nat->A_plen;

      top = (char *) (hm + 1);
      cnt++;
    }

  if (cnt == 0)
    return msg;

  mh->type = HNA_MESSAGE;
  mh->ttl = OLSR_DEFAULT_TTL;
  mh->hopcount = 0;
  mh->seq = htons (mseq++);
  mh->size = htons (top - msg);
  memcpy(&mh->originator, &olsr.main_addr, sizeof (struct in6_addr));
  mh->vtime = olsr_message_encode_time (olsr.hna_validity == -1 ?
                                        olsr.hna_interval*3 : olsr.hna_validity);

  return top;
}


int
olsr_hna_send_thread ()
{
  int size;
  char *head, *end;
  char msg[MAXPACKETSIZE];
  struct listnode *node;
  struct in6_addr dst;
  struct olsr_interface_tuple *it;
  struct olsr_message_header *mh;
  char ifname[IFNAMSIZ];

  thread_add_timer (master, olsr_hna_send_thread, NULL, olsr.hna_interval);

  if (!mainaddr_set)
    return  0;

  memset (msg, 0, MAXPACKETSIZE);
  head = msg;
  end = olsr_generate_hna_message (msg);
  if (end == head)
    return 0;

  size = end - head;
  mh = (struct olsr_message_header *) head;

  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &dst);
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (! (it->status & ACTIVE) || (!it->optset))
	continue;

      if (IS_OLSR_DEBUG_MESSAGE (MID))
        zlog_info ("MID message send on %s",
                   if_indextoname (it->ifindex, ifname));
      olsr_sendmsg (it, msg, dst, size);
    }

  return 0;
}

char *
olsr_process_hna_message(char *msg, struct in6_addr *recv_addr,
                         struct in6_addr *send_addr)
{
  char *top;
  char *limit;
  time_t now;
  time_t valid_time;

  struct olsr_message_header *mh;
  struct hna_message *hm;
  struct olsr_link_tuple *lt;
  struct olsr_nwassoc_tuple *nwassoc, new;

  now = time(NULL);
  mh = (struct olsr_message_header *) msg;
  valid_time = olsr_message_decode_time (mh->vtime);

  limit = msg + ntohs (mh->size);
  if ((! (lt = olsr_link_set_lookup (olsr.link_set, *recv_addr, *send_addr)))
    || (! olsr_link_is_SYM(lt))) /* link to the neighbor is not SYM link  */
    {
      return limit;
    }

  top = msg + sizeof (struct olsr_message_header);
  hm = (struct hna_message *) top;

  while ((char *) hm < limit)
    {
      if (! (nwassoc = olsr_nwassoc_set_lookup
                 (olsr.nw_assoc_set, mh->originator, hm->nw_addr, hm->plen)))
        {
		struct olsr_routing_entry new_re;
           memset(&new, 0, sizeof(new));
           new.A_gateway_addr = mh->originator;
           new.A_network_addr = hm->nw_addr;
           new.A_plen = hm->plen;

           nwassoc = olsr_nwassoc_set_add (olsr.nw_assoc_set, new);

	   memset (&new_re, 0, sizeof (new_re));
//	   memcpy(&new_re.R_dest_addr, &new.A_network_addr, sizeof(struct in6_addr));
	   new_re.R_dest_addr = new.A_network_addr;
	   memcpy(&new_re.R_next_addr, &lt->L_neighbor_iface_addr, sizeof(struct in6_addr));
	   new_re.R_iface_addr = lt->L_local_iface_addr;
	   new_re.R_plen = new.A_plen;
	   new_re.R_dist = 1;
	   olsr_zebra_route_update(OLSR_ROUTE_ADD, &new_re);
        }

      nwassoc->A_time = now + valid_time;
      hm++;
    }

  return limit;
}

void
olsr_network_association_set_expire_check()
{
  time_t now;
  struct listnode *nanode, *next;
  struct olsr_nwassoc_tuple *nat;

  now = time(NULL);

  nanode = listhead(olsr.nw_assoc_set);
  while (nanode)
    {
      nat = (struct olsr_nwassoc_tuple *)nanode->data;

      next = nanode->next;
      if (nat->A_time < now)
        {
           olsr_nwassoc_set_delete (olsr.nw_assoc_set, nat);
        }
      nanode = next;
    }

  return;
}
