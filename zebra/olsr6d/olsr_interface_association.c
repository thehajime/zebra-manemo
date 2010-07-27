/*
 * OLSR_Interface_Association.c
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

struct olsr_ifassoc_tuple *
olsr_assoc_lookup (struct list *set, struct in6_addr main_addr,
		   struct in6_addr ifaddr)
{
  struct listnode *node;
  struct olsr_ifassoc_tuple *iat;

  for (node = listhead (set); node; nextnode (node))
    {
      iat = (struct olsr_ifassoc_tuple *) node->data;

      if (IN6_IS_ADDR_SAME (iat->I_main_addr, main_addr) &&
	  IN6_IS_ADDR_SAME (iat->I_iface_addr, ifaddr))
	return iat;
    }

  return NULL;
}

DEFUN (show_ipv6_olsr6_interface_association,
       show_ipv6_olsr6_interface_association_cmd,
       "show ipv6 olsr6 interface association",
       SHOW_STR
       IP6_STR
       OLSR6_STR
       "Interface Association list\n")
{
  char mainaddr[40];
  char ifaddr[40];
  struct listnode *node;
  struct olsr_ifassoc_tuple *iat;

  vty_out (vty, "%-30s %s%s", "Main Addr", "IF Addr", VNL);

  for (node = listhead (olsr.iface_assoc_set); node; nextnode (node))
    {
      iat = (struct olsr_ifassoc_tuple *) node->data;
      inet_ntop (AF_INET6, &iat->I_main_addr, mainaddr, sizeof (mainaddr));
      inet_ntop (AF_INET6, &iat->I_iface_addr, ifaddr, sizeof (mainaddr));
      vty_out (vty, "%-30s %s%s", mainaddr, ifaddr, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_assoc_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_interface_association_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_interface_association_cmd);
}

void
olsr_assoc_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;
}

struct olsr_ifassoc_tuple *
olsr_assoc_set_add (struct list *set, struct olsr_ifassoc_tuple tuple)
{
  struct olsr_ifassoc_tuple *new;

  if ((new =
       (struct olsr_ifassoc_tuple *)
       malloc (sizeof (struct olsr_ifassoc_tuple))) == NULL)
    {
      perror ("olsr_ifassoc_set_add: malloc()");
      return NULL;
    }

  *new = tuple;
  listnode_add (set, new);

  return new;
}

void
olsr_assoc_set_delete (struct list *set, struct olsr_ifassoc_tuple *tuple)
{
  listnode_delete (set, tuple);
  free (tuple);

  return;
}

void
olsr_assoc_set_destroy (struct list **set)
{
  list_delete_all_node (*set);
  *set = NULL;

  return;
}

struct in6_addr *
olsr_assoc_ifaddr2mainaddr (struct list *iface_set,
			    struct in6_addr *iface_addr)
{
  struct listnode *is;
  struct olsr_ifassoc_tuple *assoc_tuple;

  for (is = listhead (iface_set); is; nextnode (is))
    {
      assoc_tuple = (struct olsr_ifassoc_tuple *) is->data;

      if (memcmp (&assoc_tuple->I_iface_addr,
		  iface_addr, sizeof (struct in6_addr)) == 0)
	{
	  return &assoc_tuple->I_main_addr;
	}
    }

  return iface_addr;
}

void
olsr_assoc_set_create_local_entry (struct list *iface_set,
				   struct list *assoc_set)
{
  struct listnode *node;
  struct olsr_interface_tuple *it;
  struct olsr_ifassoc_tuple new;

  for (node = listhead (iface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (! (it->status & ACTIVE))
	continue;

      if (IN6_IS_ADDR_SAME (it->local_iface_addr, olsr.main_addr))
	continue;

      memset (&new, 0, sizeof (new));
      new.I_iface_addr = it->local_iface_addr;
      new.I_main_addr = olsr.main_addr;
      new.I_time = HOLD_TIME_FOREVER;
    }

  return;
}

int
olsr_mid_send_thread ()
{
  int size;
  char *head, *end;
  char msg[MAXPACKETSIZE];
  struct listnode *node;
  struct in6_addr dst;
  struct olsr_interface_tuple *it;
  struct olsr_message_header *mh;
  char ifname[IFNAMSIZ];

  thread_add_timer (master, olsr_mid_send_thread, NULL, olsr.mid_interval);

  if (!mainaddr_set)
    return  0;

  memset (msg, 0, MAXPACKETSIZE);
  head = msg;
  end = olsr_generate_mid_message (msg);
  if (end == head)
    return 0;

  size = end - head;
  mh = (struct olsr_message_header *) head;

  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &dst);
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if ( !(it->status & ACTIVE) || (!it->optset))
	continue;

      if (IS_OLSR_DEBUG_MESSAGE (MID))
        zlog_info ("MID message send on %s",
                   if_indextoname (it->ifindex, ifname));
      olsr_sendmsg (it, msg, dst, size);
    }

  return 0;
}

void
olsr_interface_association_set_expire_check()
{
  time_t now;
  struct listnode *ianode, *next;
  struct olsr_ifassoc_tuple *iat;

  now = time(NULL);

  ianode = listhead(olsr.iface_assoc_set);
  while (ianode)
    {
      iat = (struct olsr_ifassoc_tuple *)ianode->data;

      next = ianode->next;
      if (iat->I_time < now)
        {
          olsr_assoc_set_delete(olsr.iface_assoc_set, iat);
        }
      ianode = next;
    }

  return;
}
