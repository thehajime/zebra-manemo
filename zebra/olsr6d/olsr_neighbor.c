/*
 * OLSR_Neighbor.c
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


void neighbor_2hop_set_delete (struct list *,
			       struct olsr_2hop_neighbor_tuple *);
static int neighbor_is_MPR (struct olsr_interface_tuple *, struct in6_addr *);
static struct olsr_2hop_neighbor_tuple *neighbor_2hop_set_add (struct list *,
							       struct
							       olsr_2hop_neighbor_tuple
							       *);

time_t hello_interval;


int (*evaluate_link_type[]) (struct olsr_link_tuple *) =
{
NULL, olsr_link_is_ASYM, olsr_link_is_SYM, olsr_link_is_LOST};

DEFUN (show_ipv6_olsr6_neighbor,
       show_ipv6_olsr6_neighbor_cmd,
       "show ipv6 olsr6 neighbor",
       SHOW_STR IP6_STR OLSR6_STR "Neighbor list\n")
{
  char *status;
  char straddr[40];
  struct listnode *nnode;
  struct olsr_neighbor_tuple *nt;

  vty_out (vty, "%-30s %3s\t%s%s",
	   "Neighbor Main Addr", "Wil", "State", VNL);

  for (nnode = listhead (olsr.neighbor_set); nnode; nextnode (nnode))
    {
      nt = (struct olsr_neighbor_tuple *) nnode->data;

      if (nt->N_status == NOT_SYM)
	status = "NOT_SYM";
      else
	status = "SYM";

      inet_ntop (AF_INET6, &nt->N_neighbor_main_addr, straddr,
		 sizeof (straddr));
      vty_out (vty, "%-30s %3d\t%s%s", straddr, nt->N_willingness, status,
	       VNL);

    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_olsr6_2hop_neighbor,
       show_ipv6_olsr6_2hop_neighbor_cmd,
       "show ipv6 olsr6 2hop_neighbor",
       SHOW_STR IP6_STR OLSR6_STR "2hop neighbor list\n")
{
  char onehopaddr[40];
  char twohopaddr[40];
  struct listnode *node;
  struct olsr_2hop_neighbor_tuple *tnt;

  vty_out (vty, "%-30s %s%s", "2hop Neighbor Main Addr", "Nexthop", VNL);

  for (node = listhead (olsr.two_neighbor_set); node; nextnode (node))
    {
      tnt = (struct olsr_2hop_neighbor_tuple *) node->data;

      inet_ntop (AF_INET6, &tnt->N_2hop_addr, onehopaddr,
		 sizeof (onehopaddr));
      inet_ntop (AF_INET6, &tnt->N_neighbor_main_addr, twohopaddr,
		 sizeof (twohopaddr));
      vty_out (vty, "%-30s %s%s", onehopaddr, twohopaddr, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_neighbor_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_olsr6_2hop_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_2hop_neighbor_cmd);
}

static int
neighbor_is_MPR (is, addr)
     struct olsr_interface_tuple *is;
     struct in6_addr *addr;
{
  struct listnode *ms;
  struct in6_addr neighbor_main_addr;
  struct olsr_mpr_tuple *mpr_tuple;

  neighbor_main_addr =
    *olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set, addr);

  for (ms = listhead (is->mpr_set); ms; nextnode (ms))
    {
      mpr_tuple = (struct olsr_mpr_tuple *) ms->data;

      if (IN6_IS_ADDR_SAME (neighbor_main_addr, mpr_tuple->M_main_addr))
	return 1;
    }

  return 0;
}


void
neighbor_set_create (struct list **neighbor)
{
  *neighbor = list_new ();
  (*neighbor)->del = free;

  return;
}

struct olsr_neighbor_tuple *
neighbor_set_add (neighbor_set, node)
     struct list *neighbor_set;
     struct olsr_neighbor_tuple *node;
{
  struct olsr_neighbor_tuple *new;

  if ((new =
       (struct olsr_neighbor_tuple *)
       malloc (sizeof (struct olsr_neighbor_tuple))) == NULL)
    {
      perror ("neighbor_set_add: malloc()");
      return NULL;
    }

  *new = *node;
  listnode_add (neighbor_set, new);

  return new;
}

void
neighbor_set_delete (neighbor_set, del)
     struct list *neighbor_set;
     struct olsr_neighbor_tuple *del;
{
  struct listnode *node, *next;
  struct olsr_2hop_neighbor_tuple *tnt;

  node = listhead (olsr.two_neighbor_set);
  while (node)
    {
      tnt = (struct olsr_2hop_neighbor_tuple *) node->data;

      next = node->next;
      if (IN6_IS_ADDR_SAME
	  (tnt->N_neighbor_main_addr, del->N_neighbor_main_addr))
	{
	  neighbor_2hop_set_delete (olsr.two_neighbor_set, tnt);
	}

      node = next;
    }

  listnode_delete (neighbor_set, del);
  free (del);

  return;
}

void
neighbor_set_destroy (struct list *neighbor_set)
{
  list_delete_all_node (neighbor_set);
  neighbor_set = NULL;

  return;
}

int
neighbor_countup (struct list *neighbor_set)
{
  return neighbor_set->count;
}

void
neighbor_2hop_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

static struct olsr_2hop_neighbor_tuple *
neighbor_2hop_set_add (set, tuple)
     struct list *set;
     struct olsr_2hop_neighbor_tuple *tuple;
{
  struct olsr_2hop_neighbor_tuple *new;


  new =
    (struct olsr_2hop_neighbor_tuple *)
    malloc (sizeof (struct olsr_2hop_neighbor_tuple));
  if (new == NULL)
    {
      perror ("neighbor_set_add: malloc()");
      return NULL;
    }

  *new = *tuple;
  listnode_add (set, new);

  return new;
}

void
neighbor_2hop_set_delete (struct list *set,
			  struct olsr_2hop_neighbor_tuple *tuple)
{
  free (tuple);
  listnode_delete (set, tuple);

  return;
}

void
neighbor_2hop_set_destroy (struct list *set)
{
  list_delete_all_node (set);
  set = NULL;

  return;
}

char *
neighbor_message_create (msg, linkcode, cnt, neigh)
     char *msg;
     u_char linkcode;
     int cnt;
     struct in6_addr *neigh;
{
  int addr_size;
  struct in6_addr *addrlist;
  struct hello_body *hb;


  if (cnt == 0)
    return msg;

  addr_size = sizeof (struct in6_addr) * cnt;

  hb = (struct hello_body *) msg;
  addrlist = (struct in6_addr *) (hb + 1);

  memset (hb, 0, sizeof (struct hello_body));
  hb->linkcode = linkcode;
  hb->link_message_size = htons (sizeof (struct hello_body) + addr_size);
  memcpy (addrlist, neigh, addr_size);

  return (msg + sizeof (struct hello_body) + addr_size);
}

u_char
neighbor_get_status (struct olsr_link_tuple *lt)
{
  time_t now;

  now = time (NULL);
  if (lt->L_SYM_time >= now)
    return SYM;
  else
    return NOT_SYM;
}

char *
neighbor_message_create_link_type (msg, is, linktype)
     char *msg;
     struct olsr_interface_tuple *is;
     u_char linktype;
{
  char *top;
  u_char link_code;
  u_char neighbor_status;
  int mpr_cnt = 0;
  int sym_cnt = 0;
  int not_cnt = 0;

  struct olsr_link_tuple *ls;
  struct listnode *link_tuple;

  struct in6_addr main_addr;
  struct in6_addr mpr_neigh[MAX_ADDR_LIST];
  struct in6_addr sym_neigh[MAX_ADDR_LIST];
  struct in6_addr not_neigh[MAX_ADDR_LIST];


  if ((linktype <= UNSPEC_LINK) || (linktype > LOST_LINK))
    {
      fprintf (errout, "%s%s%d\n",
	       "neighbor_message_create_link_type(): ",
	       "Invalid link type", linktype);
      return msg;
    }

  for (link_tuple = listhead (olsr.link_set); link_tuple;
       nextnode (link_tuple))
    {
      ls = (struct olsr_link_tuple *) link_tuple->data;

      if (evaluate_link_type[linktype] (ls) == 0)
	continue;

      main_addr =
	*olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set,
				     &ls->L_neighbor_iface_addr);

/*      if (neighbor_is_MPR (is, &ls->L_neighbor_iface_addr)) */
      if (neighbor_is_MPR (is, &main_addr))
        {
#if 0
	  {
	    char buf[BUFSIZ];
	    printf ("create_link_type MPR %s\n",
		    inet_ntop (AF_INET6, &main_addr, buf,
			       BUFSIZ));
	  }
#endif

	  mpr_neigh[mpr_cnt++] = main_addr;
        }

      neighbor_status = neighbor_get_status (ls);

      if (neighbor_status == SYM)
	{
#ifdef DEBUG
	  {
	    char buf[BUFSIZ];
	    printf ("create_link_type SYM %s\n",
		    inet_ntop (AF_INET6, &ls->L_neighbor_iface_addr, buf,
			       BUFSIZ));
	  }
#endif
	  sym_neigh[sym_cnt++] = main_addr;
	}
      else if (neighbor_status == NOT_SYM)
	{
#ifdef DEBUG
	  {
	    char buf[BUFSIZ];
	    printf ("create_link_type NOT_SYM %s\n",
		    inet_ntop (AF_INET6, &ls->L_neighbor_iface_addr, buf,
			       BUFSIZ));
	  }
#endif
	  not_neigh[not_cnt++] = main_addr;
	}
    }

  top = msg;

  /*zlog_info ("neighbor: %s MPR %d SYM %d Not %d", __FUNCTION__, mpr_cnt, sym_cnt, not_cnt);*/

  link_code = (MPR_NEIGH << 2) | linktype;
  top = neighbor_message_create (top, link_code, mpr_cnt, mpr_neigh);

  link_code = (SYM_NEIGH << 2) | linktype;
  top = neighbor_message_create (top, link_code, sym_cnt, sym_neigh);

  link_code = (NOT_NEIGH << 2) | linktype;
  top = neighbor_message_create (top, link_code, not_cnt, not_neigh);

  return top;
}

struct olsr_neighbor_tuple *
olsr_neighbor_tuple_lookup_from_main_addr (neighbor_set, main_addr)
     struct list *neighbor_set;
     struct in6_addr main_addr;
{
  struct listnode *ns;
  struct olsr_neighbor_tuple *neighbor_tuple;

  for (ns = listhead (neighbor_set); ns; nextnode (ns))
    {
      neighbor_tuple = (struct olsr_neighbor_tuple *) ns->data;

#ifdef DEBUG
      {
	char buf1[BUFSIZ];
	char buf2[BUFSIZ];
	printf ("nlookup(): target %s entry %s\n",
		inet_ntop (AF_INET6, &main_addr, buf1, sizeof (buf1)),
		inet_ntop (AF_INET6, &neighbor_tuple->N_neighbor_main_addr,
			   buf2, sizeof (buf2)));
      }
#endif
      if (!memcmp
	  (&neighbor_tuple->N_neighbor_main_addr, &main_addr,
	   sizeof (struct in6_addr)))
	{
	  return neighbor_tuple;
	}
    }

  return NULL;
}

void
neighbor_status_update (void)
{
  time_t now;
  u_char type;

  struct listnode *ls;
  struct in6_addr main_addr;
  struct olsr_link_tuple *link_tuple;
  struct olsr_neighbor_tuple *neighbor_tuple;


  now = time (NULL);
  for (ls = listhead (olsr.link_set); ls; nextnode (ls))
    {
      link_tuple = (struct olsr_link_tuple *) ls->data;

      if (link_tuple->L_SYM_time > now)
	type = SYM;
      else
	type = NOT_SYM;

      main_addr = *olsr_assoc_ifaddr2mainaddr
	(olsr.iface_assoc_set, &link_tuple->L_neighbor_iface_addr);
      neighbor_tuple = olsr_neighbor_tuple_lookup_from_main_addr
	(olsr.neighbor_set, main_addr);
      if (neighbor_tuple == NULL)
	continue;

      neighbor_tuple->N_status = type;
    }

  return;
}

int
olsr_neighbor_is_SYM (main_addr)
     struct in6_addr *main_addr;
{
  struct listnode *ns;
  struct olsr_neighbor_tuple *neighbor_tuple;

  for (ns = listhead (olsr.neighbor_set); ns; nextnode (ns))
    {
      neighbor_tuple = (struct olsr_neighbor_tuple *) ns->data;

      if (!memcmp (&neighbor_tuple->N_neighbor_main_addr, main_addr,
		   sizeof (struct in6_addr)))
	{
	  if (neighbor_tuple->N_status == SYM)
	    {
	      return SYM;
	    }
	  break;
	}
    }

  return NOT_SYM;
}


char *
neighbor_generate_hello_message (msg, is)
     char *msg;
     struct olsr_interface_tuple *is;
{
  char *top;

  struct hello_header *hh;
  struct olsr_message_header *mh;


  top = olsr_message_create (msg, HELLO_MESSAGE);
  mh = (struct olsr_message_header *) msg;
  hh = (struct hello_header *) top;

  memset (hh, 0, sizeof (struct hello_header));
  hh->htime = olsr_message_encode_time (olsr.hello_interval);
  hh->willingness = olsr.willingness;
  top = (char *) (hh + 1);

  if ((top = neighbor_message_create_link_type (top, is, SYM_LINK)) == NULL)
    {
      /* some error message to errout */
      return NULL;
    }

  if ((top = neighbor_message_create_link_type (top, is, ASYM_LINK)) == NULL)
    {
      /* some error message to errout */
      return NULL;
    }

  if ((top = neighbor_message_create_link_type (top, is, LOST_LINK)) == NULL)
    {
      /* some error message to errout */
      return NULL;
    }

  mh->size = htons (top - msg);

  return top;
}

int
neighbor_hello_message_find_addr (msg, recv_addr)
     char *msg;
     struct in6_addr *recv_addr;
{
  char *limit;
  struct in6_addr *addr;
  struct hello_body *hb;

  hb = (struct hello_body *) msg;
  limit = msg + ntohs (hb->link_message_size);

  for (addr = (struct in6_addr *) (hb + 1); (char *) addr < limit; addr++)
    {
#if 0
printf ("addr search in neighbor list: %s\n", ip6_sprintf (addr));
#endif
      if (memcmp (addr, recv_addr, sizeof (struct in6_addr)) == 0)
	return 1;
    }

  return 0;
}

struct olsr_link_tuple *
neighbor_process_hello_link_set (msg, valid_time, originator, recv_addr,
				 src_addr, willingness)
     char *msg;
     time_t valid_time;
     struct in6_addr originator;
     struct in6_addr recv_addr;
     struct in6_addr src_addr;
     int willingness;
{
  u_char link_type;
  time_t now;

  struct hello_body *hb;
  struct listnode *node;
  struct olsr_link_tuple new;
  struct olsr_link_tuple *ls;
  struct in6_addr main_addr;
  struct olsr_neighbor_tuple new_nei;
  struct olsr_neighbor_tuple *nt = NULL;
  struct olsr_interface_tuple *it;

  now = time (NULL);
  hb = (struct hello_body *) msg;

  main_addr = originator;
  ls = olsr_link_set_lookup (olsr.link_set, recv_addr, src_addr);
  if (ls == NULL)
    {
      nt =
	olsr_neighbor_tuple_lookup_from_main_addr (olsr.neighbor_set,
						   main_addr);
      if (!nt)
	{
	  memset (&new_nei, 0, sizeof (new_nei));
	  new_nei.N_neighbor_main_addr = main_addr;
          new_nei.N_willingness = willingness;
	  nt = neighbor_set_add (olsr.neighbor_set, &new_nei);
	}

      memset (&new, 0, sizeof (new));
      new.L_local_iface_addr = recv_addr;
      new.L_neighbor_iface_addr = src_addr;
      new.L_SYM_time = now - 1;	/* set as expired */
      new.L_time = now + valid_time;

      if (!(ls = olsr_link_set_add (olsr.link_set, new)))
	{
	  fprintf (errout, "%s%s\n",
		   "neighbor_process_hello_link_tuple:",
		   "error occured in add_table -> ignored");
	  return NULL;
	}
    }

  if (nt == NULL)
    {
      if (!(nt = olsr_neighbor_tuple_lookup_from_main_addr
	    (olsr.neighbor_set, main_addr)))
	{
	  memset (&new_nei, 0, sizeof (new_nei));
	  new_nei.N_neighbor_main_addr = main_addr;
          new_nei.N_willingness = willingness;
	  nt = neighbor_set_add (olsr.neighbor_set, &new_nei);
	}
    }

  ls->L_ASYM_time = now + valid_time;
  link_type = hb->linkcode & LINKTYPEMASK;


  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (neighbor_hello_message_find_addr (msg, &it->local_iface_addr) ==
	  FOUND)
	{
	  if (link_type == LOST_LINK)
	    {
	      ls->L_SYM_time = now - 1;
	      nt->N_status = NOT_SYM;
	    }
	  else if ((link_type == SYM_LINK) || (link_type == ASYM_LINK))
	    {
              int hello_valid = (olsr.hello_validity == -1) ? 
                olsr.hello_interval * 3 : olsr.hello_validity;
	      ls->L_SYM_time = now + valid_time;
	      ls->L_time = ls->L_SYM_time + hello_valid;
	      nt->N_status = SYM;
	    }
	  break;
	}
    }

  ls->L_time = (ls->L_time > ls->L_ASYM_time) ? ls->L_time : ls->L_ASYM_time;

  return ls;
}

void
process_hello_mpr_neighbor (struct in6_addr originator, time_t valid_time)
{
  time_t now;
  struct olsr_mpr_selector_tuple *mss, new;


  if (!
      (mss =
       olsr_mpr_selector_set_lookup (olsr.mpr_selector_set, originator)))
    {
      memset (&new, 0, sizeof (new));
      new.MS_main_addr = originator;

      if (!(mss = olsr_mpr_selector_set_add (olsr.mpr_selector_set, new)))
	{
	  return;
	}
    }
  now = time (NULL);
  mss->MS_time = now + valid_time;

  return;
}

struct olsr_neighbor_tuple *
neighbor_process_hello_neighbor_set (char *msg, struct in6_addr originator,
				     struct in6_addr recv, int willingness,
				     time_t valid_time)
{
  char *limit;
  u_char nodetype;

  struct in6_addr *addr_list;
  struct hello_body *hb;
  struct olsr_neighbor_tuple *ns;


  ns =
    olsr_neighbor_tuple_lookup_from_main_addr (olsr.neighbor_set, originator);
  if (ns == NULL)
    {
      return NULL;
    }
  ns->N_willingness = willingness;

  hb = (struct hello_body *) msg;

  limit = msg + ntohs (hb->link_message_size);


  for (addr_list = (struct in6_addr *) (hb + 1);
       addr_list < (struct in6_addr *) limit; addr_list++)
    {

#if 0
      if (!memcmp (addr_list, &olsr.main_addr, sizeof (struct in6_addr)))
	break;
#endif

      if (olsr_interface_lookup_by_addr (olsr.interface_set, *addr_list))
	{
	  break;		/* skip node itself */
	}
    }
  if (addr_list >= (struct in6_addr *) limit)
    {
      return ns;
    }

  nodetype = hb->linkcode >> 2;
  if (nodetype == MPR_NEIGH)
    {
#ifdef DEBUG
      printf ("process_hello: neighbor selects this node as mpr\n");
#endif
      process_hello_mpr_neighbor (originator, valid_time);
#ifdef DEBUG
      printf ("process_hello: mpr selector updated %d \n",
	      listcount (olsr.mpr_selector_set));
#endif
    }

  return ns;
}

struct olsr_2hop_neighbor_tuple *
neighbor_2hop_lookup (struct list *twohop_neighbor_set, struct in6_addr orig,
		      struct in6_addr nei)
{
  struct listnode *nts;
  struct olsr_2hop_neighbor_tuple *twohop_neighbor_tuple;

  for (nts = listhead (twohop_neighbor_set); nts; nextnode (nts))
    {
      twohop_neighbor_tuple = (struct olsr_2hop_neighbor_tuple *) nts->data;

      if (!IN6_IS_ADDR_SAME
	  (twohop_neighbor_tuple->N_neighbor_main_addr, orig))
	continue;

      if (!IN6_IS_ADDR_SAME (twohop_neighbor_tuple->N_2hop_addr, nei))
	continue;

      return twohop_neighbor_tuple;
    }

  return NULL;
}

struct olsr_2hop_neighbor_tuple *
neighbor_process_hello_2hop_neighbor_set (char *msg,
					  struct in6_addr originator,
					  time_t valid_time,
                                          int willingness)
{
  time_t now;
  char *limit;
  u_char neighbor_type;

  struct hello_body *hb;
  struct in6_addr main_addr;
  struct in6_addr *addrlist;
  struct olsr_2hop_neighbor_tuple new, *nts;


  hb = (struct hello_body *) msg;

  now = time (NULL);
  neighbor_type = hb->linkcode >> 2;

#ifdef DEBUG
  if (neighbor_type == NOT_NEIGH)
    printf ("process_2nei: neighbor lost\n");
#endif

  if (olsr_neighbor_is_SYM (&originator) == 0)
    {
#ifdef DEBUG
      fprintf (errout, "%s %s %s\n",
	       "neighbor_process_hello_2hop_neighbor_tuple:",
	       "not symmetric neighbor",
               ip6_sprintf (&originator));
#endif
      return NULL;
    }


#ifdef DEBUG
printf ("process_2nei: originator %s\n", ip6_sprintf (&originator));
#endif
  limit = msg + ntohs (hb->link_message_size);
  for (addrlist = (struct in6_addr *) (hb + 1);
       addrlist < (struct in6_addr *) limit; addrlist++)
    {
#ifdef DEBUG
      {
	char buf[BUFSIZ];
	printf ("process_2nei: process addr %s\n",
		inet_ntop (AF_INET6, addrlist, buf, sizeof (buf)));
      }
#endif

      if (olsr_interface_lookup_by_addr (olsr.interface_set, *addrlist))
	{
#ifdef DEBUG
	  printf ("process_2nei: addr is myself continue\n");
#endif
	  continue;		/* skip node itself */
	}

      main_addr =
	*olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set, addrlist);
      nts =
	neighbor_2hop_lookup (olsr.two_neighbor_set, originator, *addrlist);
      if (nts && !IN6_IS_ADDR_SAME (main_addr, *addrlist) )
	{ 
          /* for making sure there is no "not mainaddr entry"
             in 2hop neighbor list */
#ifdef DEBUG
printf("process_2nei: delete redundant node %s %s\n", 
ip6_sprintf (&main_addr), ip6_sprintf (addrlist));
#endif /* DEBUG */
          neighbor_2hop_set_delete (olsr.two_neighbor_set, nts);
          nts = NULL;
	}
      nts =
	neighbor_2hop_lookup (olsr.two_neighbor_set, originator, main_addr);
      if ((nts == NULL) && (neighbor_type != NOT_NEIGH))
	{
	  memset (&new, 0, sizeof (new));
	  new.N_neighbor_main_addr = originator;
	  new.N_2hop_addr = main_addr;
          new.N_willingness = willingness;
	  nts = neighbor_2hop_set_add (olsr.two_neighbor_set, &new);
	  olsr_routing_set_update ();
#ifdef DEBUG
	  {
	    char buf[BUFSIZ];
	    printf ("process_2nei: address %s is now added %d\n",
		    inet_ntop (AF_INET6, addrlist, buf, sizeof (buf)),
		    listcount (olsr.two_neighbor_set));
	  }
#endif
	}

      if (nts)
	nts->N_time = now + valid_time;

      if (neighbor_type == NOT_NEIGH)
	{
#ifdef DEBUG
	  printf ("process_2nei: delete process\n");
#endif
	  if (nts)
	    {
	      neighbor_2hop_set_delete (olsr.two_neighbor_set, nts);
	      olsr_routing_set_update ();
	    }
	}
    }

  return NULL;
}



char *
neighbor_process_each_hello_message (struct olsr_message_header *mh,
				     struct hello_header *hh, char *msg,
				     struct in6_addr recv_addr,
				     struct in6_addr send_addr)
{
  char *top;
  time_t now;
  int valid_time;

  struct hello_body *hb;
  struct olsr_link_tuple *ls;
  struct olsr_ifassoc_tuple new_assoc, *iat;
  struct olsr_neighbor_tuple *ns;


  top = msg;
  hb = (struct hello_body *) msg;
  now = time (NULL);
  valid_time = olsr_message_decode_time (mh->vtime);

  ls =
    neighbor_process_hello_link_set (top, valid_time, mh->originator,
				     recv_addr, send_addr, hh->willingness);

#if 0
  iat = NULL;
  if (!IN6_IS_ADDR_SAME (mh->originator, send_addr)
      && ! (iat = olsr_assoc_lookup 
               (olsr.iface_assoc_set, mh->originator, send_addr)))
    {
      memset (&new_assoc, 0, sizeof (new_assoc));
      new_assoc.I_main_addr = mh->originator;
      new_assoc.I_iface_addr = send_addr;
      iat = olsr_assoc_set_add (olsr.iface_assoc_set, new_assoc);
    }
  if (iat)
    iat->I_time = now + valid_time;
#endif

  if (ls == NULL)
    {
      fprintf (errout, "%s%s\n",
	       "neighbor_process_hello_message:",
	       "neighbor_process_hello_link_tuple got some failure");
    }

  ns =
    neighbor_process_hello_neighbor_set (top, mh->originator, recv_addr,
					 hh->willingness, valid_time);
  if (ns == NULL)
    {
      fprintf (errout, "%s%s\n",
	       "neighbor_process_hello_message:",
	       "neighbor_process_hello_neighbor_tuple got some failure");
    }

  neighbor_process_hello_2hop_neighbor_set (top, mh->originator, valid_time, hh->willingness);

  return (top + ntohs (hb->link_message_size));
}

char *
neighbor_process_hello_message (char *msg, struct in6_addr *recv_addr,
				struct in6_addr *send_addr)
{
  char *top;
  char *limit;
  time_t now;
  time_t valid_time;

  struct hello_header *hh;
  struct olsr_message_header *mh;
  struct olsr_neighbor_tuple new_nei;
  struct olsr_link_tuple new_link;
  struct olsr_link_tuple *lt;
  struct olsr_ifassoc_tuple new_assoc, *iat;

  mh = (struct olsr_message_header *) msg;
  hh = (struct hello_header *) (mh + 1);

  now = time (NULL);
  valid_time = olsr_message_decode_time (mh->vtime);

#if 0
  {
    char buf[BUFSIZ];
    printf ("process_hello() originator %s \n",
	    inet_ntop (AF_INET6, &mh->originator, buf, BUFSIZ));
  }
#endif

  if (!olsr_neighbor_tuple_lookup_from_main_addr
      (olsr.neighbor_set, mh->originator))
    {
      memset (&new_nei, 0, sizeof (new_nei));
      new_nei.N_neighbor_main_addr = mh->originator;
      new_nei.N_status = NOT_SYM;
      new_nei.N_willingness = hh->willingness;
      neighbor_set_add (olsr.neighbor_set, &new_nei);

      lt = olsr_link_set_lookup (olsr.link_set, *recv_addr, *send_addr);
      if (!lt)
	{
	  memset (&new_link, 0, sizeof (new_link));
	  new_link.L_local_iface_addr = *recv_addr;
	  new_link.L_neighbor_iface_addr = *send_addr;
	  new_link.L_SYM_time = now - 1;	/* set as expired */
	  new_link.L_time = now + valid_time;
	  new_link.L_ASYM_time = now + valid_time;
	  olsr_link_set_add (olsr.link_set, new_link);
	}
    }

  top = (char *) (hh + 1);
  limit = msg + ntohs (mh->size);

  iat = NULL;
  if (!IN6_IS_ADDR_SAME (mh->originator, send_addr)
      && ! (iat = olsr_assoc_lookup 
               (olsr.iface_assoc_set, mh->originator, *send_addr)))
    {
      memset (&new_assoc, 0, sizeof (new_assoc));
      new_assoc.I_main_addr = mh->originator;
      new_assoc.I_iface_addr = *send_addr;
      iat = olsr_assoc_set_add (olsr.iface_assoc_set, new_assoc);
    }
  if (iat)
    iat->I_time = now + valid_time;


  while (top < limit)
    top =
      neighbor_process_each_hello_message (mh, hh, top, *recv_addr, *send_addr);

  olsr_mpr_selection ();

  return top;
}


/*******
	the function described in RFC section 8.5 should be add
 *******/

void
neighbor_2hop_expire_check ()
{
  time_t now;
  struct listnode *node, *next;
  struct olsr_2hop_neighbor_tuple *tnt;

  now = time (NULL);
  node = listhead (olsr.two_neighbor_set);
  while (node)
    {
      tnt = (struct olsr_2hop_neighbor_tuple *) node->data;

      if (tnt->N_time < now)
	{
	  next = node->next;
	  neighbor_2hop_set_delete (olsr.two_neighbor_set, tnt);
	  node = next;
	  continue;
	}

      nextnode (node);
    }

  return;
}

int
olsr_hello_send_thread ()
{
  int size;
  char *top;
  char msg[MAXPACKETSIZE];
  struct listnode *node;
  struct in6_addr dst;
  struct olsr_interface_tuple *it;
  struct olsr_message_header *mh;
  char ifname[IFNAMSIZ];

  thread_add_timer (master, olsr_hello_send_thread, NULL,
		    olsr.hello_interval);

  if (!mainaddr_set)
    return 0;

  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &dst);
  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if ( ! (it->status & ACTIVE) || (!it->optset))
	continue;
      memset (msg, 0, MAXPACKETSIZE);
      top = neighbor_generate_hello_message (msg, it);
      if (top == NULL)
	continue;
      size = top - msg;
      mh = (struct olsr_message_header *) msg;

      if (IS_OLSR_DEBUG_MESSAGE (HELLO))
        zlog_info ("Hello message send on %s",
                   if_indextoname (it->ifindex, ifname));

      olsr_sendmsg (it, msg, dst, size);
    }

  return 0;
}

