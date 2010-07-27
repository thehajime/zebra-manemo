#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "prefix.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

int olsr_socket ();

const char *
ip6_sprintf (const struct in6_addr *addr)
{
  static int ip6round = 0;
  static char ip6buf[8][NI_MAXHOST];
  struct sockaddr_in6 sin6;
  int flags = NI_NUMERICHOST;

  memset (&sin6, 0, sizeof (sin6));
#ifdef SIN6_LEN
  sin6.sin6_len = sizeof (sin6);
#endif /*SIN6_LEN*/
  sin6.sin6_family = AF_INET6;
  sin6.sin6_addr = *addr;

#if 0
  /* XXX: This is a special workaround for KAME kernels.
     sin6_scope_id field of SA should be set in the future. */
  if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
      IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr) ||
      IN6_IS_ADDR_MC_NODELOCAL(&sin6.sin6_addr))
    {
      /* XXX: override is ok? */
      sin6.sin6_scope_id = (u_int32_t)
        ntohs (*(u_short *) &sin6.sin6_addr.s6_addr[2]);
      *(u_short *) &sin6.sin6_addr.s6_addr[2] = 0;
    }
#endif

  ip6round = (ip6round + 1) & 7;

  if (getnameinfo ((struct sockaddr *)&sin6, sizeof(sin6),
                   ip6buf[ip6round], NI_MAXHOST, NULL, 0, flags) != 0)
    return ("???");

  return (ip6buf[ip6round]);
}


DEFUN (show_version_olsr6,
       show_version_olsr6_cmd,
       "show version olsr6",
       SHOW_STR
       "Displays the olsr6d version\n")
{
  vty_out (vty, "Zebra OLSR6D Version: %s%s", OLSR6D_VERSION, VNL);
  return CMD_SUCCESS;
}

DEFUN (router_olsr6,
       router_olsr6_cmd,
       "router olsr6",
       ROUTER_STR
       OLSR6_STR)
{
  vty->node = OLSR6_NODE;
  vty->index = &olsr;
  return CMD_SUCCESS;
}

#if 0
DEFUN (interface,
       interface_cmd,
       "interface",
       INTERFACE_STR
       OLSR6_STR)
{
  vty->node = OLSR6_NODE;
  vty->index = &olsr;
  return CMD_SUCCESS;
}
#endif

DEFUN (hello_interval,
       hello_interval_cmd,
       "hello-interval <0-3600>",
       "Hello interval\n"
       "Hello interval in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->hello_interval = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (hello_validity,
       hello_validity_cmd,
       "hello-validity <0-3600>",
       "Hello validity\n"
       "Hello validity in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->hello_validity = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (tc_interval,
       tc_interval_cmd,
       "tc-interval <0-3600>",
       "Topology Control interval\n"
       "Topology Control interval in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->tc_interval = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (tc_validity,
       tc_validity_cmd,
       "tc-validity <0-3600>",
       "Topology Control validity\n"
       "Topology Control validity in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->tc_validity = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (mid_interval,
       mid_interval_cmd,
       "mid-interval <0-3600>",
       "Multiple Interface Descriminate interval\n"
       "Multiple Interface Descriminate interval in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->mid_interval = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (hna_interval,
       hna_interval_cmd,
       "hna-interval <0-3600>",
       "Host and Network Association interval\n"
       "Host and Network Association interval in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->hna_interval = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (hna_validity,
       hna_validity_cmd,
       "hna-validity <0-3600>",
       "Host and Network Association validity\n"
       "Host and Network Association validity in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->hna_validity = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (willingness,
       willingness_cmd,
       "willingness <0-1000>",
       "Willingness\n"
       "Willingness\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->willingness = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (tc_redundancy_mode_basic,
       tc_redundancy_mode_basic_cmd,
       "tc_redundancy_mode basic",
       "Advertise Only MPR Selector\n"
       "Advertise Only MPR Selector\n")
{
  struct olsr *o = (struct olsr *) vty->index;

  o->tc_redundant_mode = TC_REDUNDANCY_BASIC;
  return CMD_SUCCESS;
}

DEFUN (tc_redundancy_mode_extended,
       tc_redundancy_mode_extended_cmd,
       "tc_redundancy_mode extended",
       "Advertise MPR and MPR Selector\n"
       "Advertise MPR and MPR Selector\n")
{
  struct olsr *o = (struct olsr *) vty->index;

  o->tc_redundant_mode = TC_REDUNDANCY_EXTENDED;
  return CMD_SUCCESS;
}

DEFUN (tc_redundancy_mode_full,
       tc_redundancy_mode_full_cmd,
       "tc_redundancy_mode full",
       "Advertise All Neighbors\n"
       "Advertise All Neighbors\n")
{
  struct olsr *o = (struct olsr *) vty->index;

  o->tc_redundant_mode = TC_REDUNDANCY_FULL;
  return CMD_SUCCESS;
}

DEFUN (valid_time,
       valid_time_cmd,
       "valid-time <0-3600>",
       "Valid Time\n"
       "Valid Time in seconds\n")
{
  struct olsr *o = (struct olsr *) vty->index;
  o->valid_time = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (olsr6_enable,
       olsr6_enable_cmd,
       "olsr6 enable",
       OLSR6_STR
       "Enable Interface\n")
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  it = olsr_interface_get_by_name (ifp->name);
  vty_out (vty, "enabling interace %s%s", ifp->name, VNL);
  it->status |= ACTIVE;

  if (!mainaddr_set && (it->status & LOCAL_ADDR_SET))
    {
      olsr.main_addr = it->local_iface_addr;
      mainaddr_set++;
    }

  return CMD_SUCCESS;
}

DEFUN (olsr6_disable,
       olsr6_disable_cmd,
       "olsr6 disable",
       OLSR6_STR
       "Disable Interface\n")
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  it = olsr_interface_get_by_name (ifp->name);
  if (it->status & ACTIVE)
    it->status ^= ACTIVE;
  return CMD_SUCCESS;
}

DEFUN (olsr6_prefix,
       olsr6_prefix_cmd,
       "olsr6 prefix PREFIX PLEN",
       OLSR6_STR
       "Network Prefix for HNA\n"
       "Prefix\n")
{
  struct olsr_nwassoc_tuple new;

  memset (&new, 0, sizeof(new));
  new.A_gateway_addr = olsr.main_addr;
  inet_pton (AF_INET6, argv[0], &new.A_network_addr);

  if (argc == 1)
       new.A_plen = 64;
  else
       new.A_plen = atoi (argv[1]);

  if (olsr_nwassoc_set_lookup(olsr.nw_assoc_set, olsr.main_addr, new.A_network_addr, new.A_plen))
    return CMD_SUCCESS;
  new.A_time = HOLD_TIME_FOREVER;

  olsr_nwassoc_set_add (olsr.nw_assoc_set, new);

  return CMD_SUCCESS;
}

DEFUN (no_olsr6_prefix,
       no_olsr6_prefix_cmd,
       "no olsr6 prefix PREFIX PLEN",
       NO_STR
       OLSR6_STR
       "Network Prefix for HNA\n"
       "Prefix\n")
{
  int plen;
  struct in6_addr nw_addr;
  struct olsr_nwassoc_tuple *nat;

  memset(&nw_addr, 0, sizeof (nw_addr));
  inet_pton (AF_INET6, argv[0], &nw_addr);
  if (argc == 1)
    plen = 64;
  else
    plen = atoi(argv[1]);

  if ((nat = olsr_nwassoc_set_lookup
               (olsr.nw_assoc_set, olsr.main_addr, nw_addr, plen)) != NULL)
    {
      olsr_nwassoc_set_delete (olsr.nw_assoc_set, nat);
    }

  return CMD_SUCCESS;
}

DEFUN (olsr6_prefix_ifp,
       olsr6_prefix_ifp_cmd,
       "olsr6 prefix",
       OLSR6_STR
       "Network Prefix for HNA\n")
{
  struct interface *ifp;
  struct listnode *node;
  struct prefix *hna = NULL;
  struct olsr_interface_tuple *it;
  struct olsr_nwassoc_tuple new;

  ifp = (struct interface *) vty->index;

  it = (struct olsr_interface_tuple *) ifp->info;
  if(!it)
	  it = olsr_interface_create(ifp);
  it->ifindex = ifp->ifindex;
  it->hna_flag = 1;

  for (node = listhead(ifp->connected); node; nextnode(node)) {
	  struct connected *c;
	  c = (struct connected *) getdata(node);
  zlog_warn("HNA add %s/%d", ip6_sprintf(&c->address->u.prefix6), c->address->prefixlen);
	  if (c->address->family != AF_INET6)
		  continue;

	  if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
		  continue;

	  hna = c->address;
	  break;
  }

  if(!hna)
	  return CMD_WARNING;

  memset (&new, 0, sizeof(new));
  new.A_gateway_addr = olsr.main_addr;
  memcpy(&new.A_network_addr, &hna->u.prefix, sizeof(struct in6_addr));
  new.A_plen = hna->prefixlen;

  zlog_warn("HNA add %s/%d", ip6_sprintf(&new.A_network_addr), hna->prefixlen);

  if (olsr_nwassoc_set_lookup(olsr.nw_assoc_set, olsr.main_addr, new.A_network_addr, new.A_plen))
    return CMD_SUCCESS;
  new.A_time = HOLD_TIME_FOREVER;

  olsr_nwassoc_set_add (olsr.nw_assoc_set, new);

  return CMD_SUCCESS;
}

DEFUN(olsr6_global6_mode_gateway,
       olsr6_global6_mode_gateway_cmd,
       "olsr6 global6 mode gateway",
       OLSR6_STR
       "Global6 Mode Gateway Enable\n")
{
  if (olsr.igw_mode != IGW_MODE_GATEWAY)
    {
      olsr.igw_mode = IGW_MODE_GATEWAY;
      thread_add_timer(master, olsr_igwadv_send_thread, NULL, olsr.igwadv_interval);
    }

  return CMD_SUCCESS;
}

DEFUN(olsr6_global6_mode_client,
       olsr6_global6_mode_client_cmd,
       "olsr6 global6 mode client",
       OLSR6_STR
       "Global6 Mode Client\n")
{
  olsr.igw_mode = IGW_MODE_CLIENT;
  return CMD_SUCCESS;
}

#if 0
DEFUN (olsr6_global6_prefix,
       olsr6_global6_prefix_cmd,
       "olsr6 global6 prefix PREFIX PLEN",
       OLSR6_STR
       "Network Prefix for Internet Gateway Advertisement\n"
       "Prefix\n")
{
  int plen;
  struct in6_addr null_addr;
  struct olsr_internet_gateway_tuple new;

  memset (&new, 0, sizeof(new));
  memset (&null_addr, 0, sizeof (null_addr));

  if (IN6_ARE_ADDR_EQUAL (&olsr.gw_addr, &null_addr))
    new.gw_global_addr = olsr.main_addr;
  else
    new.gw_global_addr = olsr.gw_addr;

  inet_pton (AF_INET6, argv[0], &new.gw_prefix_addr);

  plen = atoi (argv[1]);
  if ((plen < 0) || (plen > 64))
    {
      zlog_warn ("Invalid Prefix Length");
      return CMD_SUCCESS;
    }

  if (argc == 1)
    new.gw_plen = 64;
  else
    new.gw_plen = atoi (argv[1]);

  new.gw_prefix_lifetime = HOLD_TIME_FOREVER;
  new.gw_lifetime = HOLD_TIME_FOREVER;

  olsr_internet_gateway_set_add (olsr.igw_list, &new);

  return CMD_SUCCESS;
}
#endif

DEFUN (global6_advertisement_enable,
       global6_advertisement_enable_cmd,
       "global6 advertisement enable",
       OLSR6_STR
       "Enable Global6 Gateway function on the Interface\n")
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = (struct interface *) vty->index;
  it = (struct olsr_interface_tuple *) ifp->info;

  it->status |= INTERNET_GATEWAY_IF;
  return CMD_SUCCESS;
}

DEFUN (global6_advertisement_disable,
       global6_advertisement_disable_cmd,
       "global6 advertisement disable",
       OLSR6_STR
       "Disable Global6 Gateway function on the Interface\n")
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = (struct interface *) vty->index;
  it = (struct olsr_interface_tuple *) ifp->info;

  if (it->status & INTERNET_GATEWAY_IF)
    it->status ^= INTERNET_GATEWAY_IF;
  return CMD_SUCCESS;
}

int
config_write_olsr6 (struct vty *vty)
{
  char addr[BUFSIZ];
  struct listnode *node;
  struct olsr *o = &olsr;
  struct olsr_nwassoc_tuple *nat;

  vty_out (vty, "router olsr6%s", VNL);
  if (o->hello_interval != OLSR_DEFAULT_HELLO_INTERVAL)
    vty_out (vty, " hello-interval %d%s", o->hello_interval, VNL);
  if (o->tc_interval != OLSR_DEFAULT_TC_INTERVAL)
    vty_out (vty, " tc-interval %d%s", o->tc_interval, VNL);
  if (o->mid_interval != OLSR_DEFAULT_MID_INTERVAL)
    vty_out (vty, " mid-interval %d%s", o->mid_interval, VNL);
  if (o->hna_interval != OLSR_DEFAULT_HNA_INTERVAL)
    vty_out (vty, " hna-interval %d%s", o->hna_interval, VNL);
  if (o->hello_validity != -1)
    vty_out (vty, " hello-validity %d%s", o->hello_validity, VNL);
  if (o->tc_validity != -1)
    vty_out (vty, " tc-validity %d%s", o->tc_validity, VNL);
  if (o->hna_validity != -1)
    vty_out (vty, " hna-validity %d%s", o->hna_validity, VNL);
  if (o->willingness != WILL_DEFAULT)
    vty_out (vty, " willingness %d%s", o->willingness, VNL);
  if (o->valid_time != OLSR_DEFAULT_VALIDTIME)
    vty_out (vty, " valid-time %d%s", o->valid_time, VNL);
  if (o->tc_redundant_mode == TC_REDUNDANCY_EXTENDED)
    vty_out (vty, " tc_redundancy_mode extended%s", VNL);
  else if (o->tc_redundant_mode == TC_REDUNDANCY_FULL)
    vty_out (vty, " tc_redundancy_mode full%s", VNL);
  if (o->igw_mode == IGW_MODE_GATEWAY)
    vty_out (vty, " olsr6 global6 mode gateway%s", VNL);

  for (node = listhead (o->nw_assoc_set); node; nextnode (node))
    {
      nat = (struct olsr_nwassoc_tuple *) node->data;

      if (IN6_IS_ADDR_SAME(o->main_addr, nat->A_gateway_addr))
        {
          memset (addr, 0, sizeof (addr));
          inet_ntop(AF_INET6, &nat->A_network_addr, addr, sizeof (addr));
          vty_out (vty, " olsr6 prefix %s %d%s", addr, nat->A_plen, VNL);
        }
    }
  vty_out (vty, "!%s", VNL);
  return 0;
}

int
config_write_olsr6_interface (struct vty *vty)
{
  struct listnode *node;
  struct olsr *o = &olsr;
  struct olsr_interface_tuple *it;
#if 1
  for (node = listhead (o->interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;
#else /*1*/
  for (node = listhead (iflist); node; nextnode (node))
    {
      struct interface *ifp = getdata (node);
      it = ifp->info;
      if (! it)
        continue;
#endif /*1*/
      vty_out (vty, "interface %s%s", it->ifp->name, VNL);

      if (it->status & ACTIVE)
        vty_out (vty, " olsr6 enable%s", VNL);
      if (it->status & INTERNET_GATEWAY_IF)
        vty_out (vty, " global6 advertisement enable%s", VNL);
      vty_out (vty, "!%s", VNL);
    }
  vty_out (vty, "!%s", VNL);

  return 0;
}

struct cmd_node olsr6_node =
{
  OLSR6_NODE,
  "%s(config-olsr6)# ",
  1 /* VTYSH */
};

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  1 /* VTYSH */
};

void
olsr_vty_cmd_init ()
{
  install_element (VIEW_NODE, &show_version_olsr6_cmd);
  install_element (ENABLE_NODE, &show_version_olsr6_cmd);

  olsr_neighbor_install_element ();
  olsr_mpr_install_element ();
  olsr_topology_install_element ();
  olsr_route_install_element ();
  olsr_assoc_install_element ();
  olsr_nwassoc_install_element ();
  olsr_link_install_element ();

  install_node (&olsr6_node, config_write_olsr6);
  install_node (&interface_node, config_write_olsr6_interface);
  install_element (CONFIG_NODE, &router_olsr6_cmd);
  install_element (CONFIG_NODE, &interface_cmd);

  install_default (OLSR6_NODE);
  install_default (INTERFACE_NODE);
  install_element (OLSR6_NODE, &hello_interval_cmd);
  install_element (OLSR6_NODE, &tc_interval_cmd);
  install_element (OLSR6_NODE, &mid_interval_cmd);
  install_element (OLSR6_NODE, &hna_interval_cmd);
  install_element (OLSR6_NODE, &hello_validity_cmd);
  install_element (OLSR6_NODE, &tc_validity_cmd);
  install_element (OLSR6_NODE, &hna_validity_cmd);
  install_element (OLSR6_NODE, &willingness_cmd);
  install_element (OLSR6_NODE, &tc_redundancy_mode_basic_cmd);
  install_element (OLSR6_NODE, &tc_redundancy_mode_extended_cmd);
  install_element (OLSR6_NODE, &tc_redundancy_mode_full_cmd);
  install_element (OLSR6_NODE, &valid_time_cmd);
  install_element (OLSR6_NODE, &olsr6_prefix_cmd);
  install_element (OLSR6_NODE, &no_olsr6_prefix_cmd);
  install_element (OLSR6_NODE, &olsr6_global6_mode_gateway_cmd);
  install_element (OLSR6_NODE, &olsr6_global6_mode_client_cmd);
  install_element (INTERFACE_NODE, &olsr6_enable_cmd);
  install_element (INTERFACE_NODE, &olsr6_disable_cmd);
  install_element (INTERFACE_NODE, &olsr6_prefix_ifp_cmd);
  install_element (INTERFACE_NODE, &global6_advertisement_enable_cmd);
  install_element (INTERFACE_NODE, &global6_advertisement_disable_cmd);
}


void
olsr_init_list (struct olsr *set)
{
  olsr_assoc_set_create (&set->iface_assoc_set);
  olsr_nwassoc_set_create (&set->nw_assoc_set);
  olsr_interface_set_create (&set->interface_set);
  olsr_link_set_create (&set->link_set);
  olsr_mpr_selector_set_create (&set->mpr_selector_set);
  olsr_topology_set_create (&set->topology_set);
  olsr_duplicate_set_create (&set->duplicate_set);
  olsr_routing_set_create (&set->routing_table);
  olsr_internet_gateway_set_create (&set->igw_list);
  neighbor_set_create (&set->neighbor_set);
  neighbor_2hop_set_create (&set->two_neighbor_set);
}

void
olsr6_init ()
{
  memset (&olsr, 0, sizeof (olsr));
  olsr.hello_interval = OLSR_DEFAULT_HELLO_INTERVAL;
  olsr.tc_interval = OLSR_DEFAULT_TC_INTERVAL;
  olsr.mid_interval = OLSR_DEFAULT_MID_INTERVAL;
  olsr.hna_interval = OLSR_DEFAULT_HNA_INTERVAL;
  olsr.hello_validity = -1;
  olsr.tc_validity = -1;
  olsr.hna_validity = -1;
  olsr.igwadv_interval = OLSR_DEFAULT_IGADV_INTERVAL;
  olsr.willingness = WILL_DEFAULT;
  olsr.valid_time = OLSR_DEFAULT_VALIDTIME;
  olsr.igw_prefix_lifetime = OLSR_DEFAULT_VALIDTIME;

  olsr_sock = olsr_socket ();
  thread_add_read (master, olsr_receive, NULL, olsr_sock);

  olsr_init_list (&olsr);
  olsr_zebra_init ();
  olsr_vty_cmd_init ();
  olsr_packet_init ();
}


