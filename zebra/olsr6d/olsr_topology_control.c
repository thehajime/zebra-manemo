/* 
 * OLSR_Topology_Control.c
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "log.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

u_short ansn;
time_t null_tc_time;

DEFUN (show_ipv6_olsr6_topology,
       show_ipv6_olsr6_topology_cmd,
       "show ipv6 olsr6 topology",
       SHOW_STR
       IP6_STR
       OLSR6_STR
       "Topology information list\n")
{
  char destaddr[BUFSIZ];
  char lastaddr[BUFSIZ];
  struct listnode *node;
  struct olsr_topology_tuple *tt;

  vty_out (vty, "%-30s %-25s %4s%s",
	   "Dest Main Addr", "Last Addr", "Seq", VNL);

  for (node = listhead (olsr.topology_set); node; nextnode (node))
    {
      tt = (struct olsr_topology_tuple *) node->data;

      memset(destaddr, 0, sizeof(destaddr));
      memset(lastaddr, 0, sizeof(lastaddr));

      inet_ntop (AF_INET6, &tt->T_dest_addr, destaddr, sizeof (destaddr));
      inet_ntop (AF_INET6, &tt->T_last_addr, lastaddr, sizeof (lastaddr));
      vty_out (vty, "%-30s %-25s %04x%s", destaddr, lastaddr, tt->T_seq, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_topology_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_topology_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_topology_cmd);
}

void
olsr_topology_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

struct olsr_topology_tuple *
olsr_topology_set_add (struct list *set, struct olsr_topology_tuple *new)
{
  struct olsr_topology_tuple *tt;

  tt = (struct olsr_topology_tuple *) 
	malloc (sizeof (struct olsr_topology_tuple));
  if (tt == NULL)
    {
      perror ("olsr_topology_set_add");
      return NULL;
    }
  memset(tt, 0, sizeof(struct olsr_topology_tuple));

  memcpy (tt, new, sizeof (struct olsr_topology_tuple));
  listnode_add (set, tt);

  olsr_routing_set_update ();

  return tt;
}

void
olsr_topology_set_delete (struct list *set, struct olsr_topology_tuple *del)
{
  listnode_delete (set, del);
  free (del);
  olsr_routing_set_update ();

  return;
}

char *
olsr_generate_tc_message (char *msg)
{
  char *top;
  int cnt = 0;

  struct listnode *mss;
  struct tc_header *th;
  struct in6_addr *addr_list;
  struct olsr_message_header *mh;
  struct olsr_mpr_selector_tuple *mpr_selector_tuple;


#ifdef TC_EXTENDED
  {
    time_t now;

    now = time (NULL);
    /* null_tc_time has to be reset when the table creation is occured */
    if (olsr.mpr_selector_set->count == 0)
      {
	if (null_tc_time == 0)
	  {
	    null_tc_time = now;
	  }
	else if (now > (olsr.valid_time + null_tc_time))
	  {
	    return msg;
	  }
      }
  }
#endif /* TC_EXTENDED */

  mh = (struct olsr_message_header *) msg;
  top = olsr_message_create (msg, TC_MESSAGE);
  th = (struct tc_header *) top;
  top += sizeof (struct tc_header);
  memset (th, 0, sizeof (struct tc_header));
  th->ANSN = htons (ansn);

  addr_list = (struct in6_addr *) (th + 1);

  if (olsr.tc_redundant_mode != TC_REDUNDANCY_FULL) 
    {
      for (mss = listhead (olsr.mpr_selector_set); mss; nextnode (mss))
        {
          mpr_selector_tuple = (struct olsr_mpr_selector_tuple *) mss->data;
          addr_list[cnt] = mpr_selector_tuple->MS_main_addr;
          cnt++;
        }

      if (olsr.tc_redundant_mode == TC_REDUNDANCY_EXTENDED)
        {
          struct listnode *is;
          struct listnode *ms;
          struct olsr_interface_tuple *it;
          struct olsr_mpr_tuple *mt;

          for (is = listhead (olsr.interface_set); is; nextnode (is)) 
            {
              it = (struct olsr_interface_tuple *) is->data;
              for (ms = listhead (it->mpr_set); ms; nextnode (ms))
                {
                  mt = (struct olsr_mpr_tuple *) ms->data;
                  addr_list[cnt] = mt->M_main_addr;
                  cnt++;
                }
            }
        }
    }
  else if (olsr.tc_redundant_mode == TC_REDUNDANCY_FULL)
    {
      struct listnode *ns;
      struct olsr_neighbor_tuple *nt;

      for (ns = listhead (olsr.neighbor_set); ns; nextnode (ns))
        {
          nt = (struct olsr_neighbor_tuple *) ns->data;
          addr_list[cnt] = nt->N_neighbor_main_addr;
          cnt++;
        }
    }
  else /* Invalid TC REDUNDANCY type */
    return msg;


  if (cnt == 0)
    {
      return msg;
    }

  top += sizeof (struct in6_addr) * cnt;
  mh->size = htons (top - msg);

  return top;
}

int
olsr_topology_validate_message (struct in6_addr originator, u_short ANSN)
{
  u_short dummy;
  struct listnode *ts;
  struct olsr_topology_tuple *topology_tuple;

  for (ts = listhead (olsr.topology_set); ts; nextnode (ts))
    {
      topology_tuple = (struct olsr_topology_tuple *) ts->data;

      if (memcmp (&originator, &topology_tuple->T_last_addr,
		  sizeof (struct in6_addr)) == 0)
	{
	  if (topology_tuple->T_seq <= ANSN)
	    continue;

	  dummy = ANSN + INVALID_SEQ_INTERVAL;
	  if (dummy < topology_tuple->T_seq)
	    return 0;
	}
    }

  return 1;
}

void
olsr_topology_remove_old_entry (struct in6_addr originator, u_short ANSN)
{
  struct listnode *ts, *next;
  struct olsr_topology_tuple *topology_tuple;


  ts = listhead (olsr.topology_set);
  while (ts)
    {
      topology_tuple = (struct olsr_topology_tuple *) ts->data;
      next = ts->next;

      if (memcmp
	  (&originator, &topology_tuple->T_last_addr,
	   sizeof (struct in6_addr)) == 0)
	{
	  if (topology_tuple->T_seq == ANSN)
	    {
	      ts = next;
	      continue;
	    }

	  olsr_topology_set_delete (olsr.topology_set, topology_tuple);
	}
      ts = next;
    }

  return;
}

struct olsr_topology_tuple *
olsr_topology_set_lookup (struct list *set, struct in6_addr last,
			  struct in6_addr dest)
{
  struct listnode *node;
  struct olsr_topology_tuple *tt;

  for (node = listhead (set); node; nextnode (node))
    {
      tt = (struct olsr_topology_tuple *) node->data;

      if (IN6_IS_ADDR_SAME (tt->T_dest_addr, dest)
	  && IN6_IS_ADDR_SAME (tt->T_last_addr, last))
	return tt;
    }

  return NULL;
}

char *
olsr_process_tc_message (char *msg, struct in6_addr *recv_addr,
			 struct in6_addr *sender)
{
  char *end;
  time_t now;
  time_t valid_time;

  struct listnode *ls;
  struct olsr_message_header *mh;
  struct tc_header *th;
  struct olsr_link_tuple *link_tuple;
  struct olsr_topology_tuple *ts, new;
  struct in6_addr *addr_list;

  mh = (struct olsr_message_header *) msg;

  end = msg + ntohs (mh->size);
  now = time (NULL);

  for (ls = listhead (olsr.link_set); ls; nextnode (ls))
    {
      link_tuple = (struct olsr_link_tuple *) ls->data;

      if (memcmp (sender, &link_tuple->L_neighbor_iface_addr,
		  sizeof (struct in6_addr)) != 0)
	continue;

      if (olsr_link_is_SYM (link_tuple) == 0)
	{
	  return end;
	}
      break;
    }
  if (ls == NULL)
    return end;

  th = (struct tc_header *) (mh + 1);
  valid_time = olsr_message_decode_time (mh->vtime);

  if (olsr_topology_validate_message (mh->originator, ntohs (th->ANSN)) == 0)
    {
      return end;		/* This message is not "Fresh" */
    }

  olsr_topology_remove_old_entry (mh->originator, ntohs (th->ANSN));


  for (addr_list = (struct in6_addr *) (th + 1);
       addr_list < (struct in6_addr *) end; addr_list++)
    {

      ts =
	olsr_topology_set_lookup (olsr.topology_set, mh->originator,
				  *addr_list);
      if (ts == NULL)
	{
	  memset (&new, 0, sizeof (new));
	  new.T_dest_addr = *addr_list;
	  new.T_last_addr = mh->originator;
	  new.T_seq = ntohs (th->ANSN);
	  ts = olsr_topology_set_add (olsr.topology_set, &new);
	}

      ts->T_time = now + valid_time;
    }

  return end;
}


void
olsr_topology_set_expire_check ()
{
  time_t now;
  struct listnode *node, *next;
  struct olsr_topology_tuple *tt;

  now = time (NULL);
  node = listhead (olsr.topology_set);
  while (node)
    {
      tt = (struct olsr_topology_tuple *) node->data;

      if (tt->T_time < now)
	{
	  next = node->next;
	  olsr_topology_set_delete (olsr.topology_set, tt);
	  node = next;
	  continue;
	}

      nextnode (node);
    }

  return;
}

int
olsr_tc_send_thread ()
{
  int size;
  char *top;
  char msg[MAXPACKETSIZE];
  struct listnode *node;
  struct in6_addr dst;
  struct olsr_interface_tuple *it;
  struct olsr_message_header *mh;
  char ifname[IFNAMSIZ];

  thread_add_timer (master, olsr_tc_send_thread, NULL, olsr.tc_interval);

  if (!mainaddr_set)
    return  0;

  memset (msg, 0, MAXPACKETSIZE);
  top = olsr_generate_tc_message (msg);
  if (top == NULL)
    return 0;
  if (top == msg)
    return 0;

  size = top - msg;
  mh = (struct olsr_message_header *) msg;

  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &dst);
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if ( !(it->status & ACTIVE) || (!it->optset))
	continue;

      if (IS_OLSR_DEBUG_MESSAGE (TC))
        zlog_info ("TC message send on %s",
                   if_indextoname (it->ifindex, ifname));

      olsr_sendmsg (it, msg, dst, size);
    }

  return 0;
}
