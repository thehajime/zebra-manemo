#ifndef _OLSR_NODE_H_
#define _OLSR_NODE_H_

#define OLSR6D_VERSION "0.1"

/*
 * Link types
 */

#define UNSPEC_LINK	0
#define ASYM_LINK	1
#define SYM_LINK	2
#define LOST_LINK	3

#define LINKTYPEMASK	3


/*
 *  Neighbor types
 */

#define NOT_SYM		0
#define SYM		1

/*
 * Willingness
 */

#define WILL_NEVER	0
#define WILL_LOW	1
#define WILL_DEFAULT	3
#define WILL_HIGH	6
#define WILL_ALWAYS	7




struct olsr_ifassoc_tuple
{
  struct in6_addr I_iface_addr;	/* node's actual inteface address */
  struct in6_addr I_main_addr;	/* node's main address */
  time_t I_time;
};

struct olsr_link_tuple
{
  struct in6_addr L_local_iface_addr;	/* my local I/F addr */
  struct in6_addr L_neighbor_iface_addr;	/* foreign neighbor I/F addr */
  time_t L_SYM_time;
  time_t L_ASYM_time;
  time_t L_time;
};

struct olsr_neighbor_tuple
{
  struct in6_addr N_neighbor_main_addr;
  u_char N_status;
  int N_degree;
  int N_reachability;
  int N_routecount;
  int N_willingness;
};

struct olsr_2hop_neighbor_tuple
{
  struct in6_addr N_neighbor_main_addr;
  struct in6_addr N_2hop_addr;
  time_t N_time;
  int N_willingness;
};

struct olsr_mpr_tuple
{
  struct in6_addr M_main_addr;
};

struct olsr_mpr_selector_tuple
{
  struct in6_addr MS_main_addr;
  time_t MS_time;
};

struct olsr_topology_tuple
{
  struct in6_addr T_dest_addr;
  struct in6_addr T_last_addr;
  u_int16_t T_seq;
  time_t T_time;
};

struct olsr_routing_entry
{
  struct in6_addr R_dest_addr;
  struct in6_addr R_next_addr;
  int R_dist;
  int R_plen;
  struct in6_addr R_iface_addr;
};

#define MAXIFACENUM	16

struct olsr_duplicate_tuple
{
  struct in6_addr D_addr;
  u_int16_t D_seq_num;
  u_char D_retransmitted;
  time_t D_time;
  int D_iface_num;
  struct in6_addr D_iface_list[MAXIFACENUM];
};

struct olsr_nwassoc_tuple
{
  struct in6_addr A_gateway_addr;
  struct in6_addr A_network_addr;
  time_t A_time;
  u_char A_plen;
};

#define IGW_MODE_CLIENT		0
#define IGW_MODE_GATEWAY	1

struct olsr
{
  struct list *iface_assoc_set;
  struct list *interface_set;
  struct list *link_set;
  struct list *neighbor_set;
  struct list *two_neighbor_set;
  struct list *mpr_selector_set;
  struct list *nw_assoc_set;
  struct list *topology_set;
  struct list *duplicate_set;
  struct list *routing_table;
  struct list *igw_list;

  struct in6_addr main_addr;
  struct in6_addr gw_addr;
  int willingness;
  int hello_interval;
  int tc_interval;
  int mid_interval;
  int hna_interval;
  int hello_validity;
  int tc_validity;
  int hna_validity;
  int igwadv_interval;
  int valid_time;

  u_char igw_mode;
  u_char igw_prefix_lifetime;

  u_char tc_redundant_mode;
};


#if 0
#define NOT_ACTIVE	0
#endif 

/*
 * Interface Status Flags
 */

#define ACTIVE			1
#define LOCAL_ADDR_SET		2
#define GLOBAL_ADDR_SET		4
#define INTERNET_GATEWAY_IF	8

struct olsr_interface_tuple
{
  int ifindex;
  u_char status;
  u_char hna_flag;
  int optset;
  struct in6_addr link_local_addr;	/* interface link-local addr */
  struct in6_addr local_iface_addr;	/* interface Manet local main addr */
  struct in6_addr global_iface_addr;	/* interface Manet global main addr */
  struct list *mpr_set;
  struct list *prefix_list;
  struct interface *ifp;
};

/*********
  The structure below is for the Global connectivity for IPv6 Manets.
  See draft-wakikawa-manet-globalv6-05.txt for the detail.
 *********/

struct olsr_internet_gateway_tuple {
  struct in6_addr gw_global_addr;
  struct in6_addr gw_prefix_addr;
  u_char gw_plen;
  time_t gw_prefix_lifetime;
  time_t gw_lifetime;
  struct in6_addr gw_manet_addr;
};


#define HOLD_TIME_FOREVER	0x7fffffff

#define OLSR_DEFAULT_HELLO_INTERVAL	2
#define OLSR_DEFAULT_TC_INTERVAL	5
#define OLSR_DEFAULT_MID_INTERVAL	5
#define OLSR_DEFAULT_HNA_INTERVAL	5
#define OLSR_DEFAULT_IGADV_INTERVAL	5
#define OLSR_DEFAULT_REFRESH_INTERVAL	2

#define NEIGHB_HOLD_TIME		(3 * OLSR_DEFAULT_REFRESH_INTERVAL)
#define TOP_HOLD_TIME			(3 * OLSR_DEFAULT_TC_INTERVAL)
#define DUP_HOLD_TIME			30
#define MID_HOLD_TIME			(3 * OLSR_DEFAULT_MID_INTERVAL)
#define HNA_HOLD_TIME			(3 * OLSR_DEFAULT_HNA_INTERVAL)
#define OLSR_DEFAULT_VALIDTIME		15

#define MAX_ADDR_LIST		255
#define INVALID_SEQ_INTERVAL	3

#define NOTFOUND	0
#define FOUND		1

#define OLSR_ROUTE_ADD		0
#define OLSR_ROUTE_DELETE	1

#define HOSTROUTE_PREFIXLEN	128

#define IN6_IS_ADDR_SAME(a, b)\
	(!memcmp(&(a), &(b), sizeof(struct in6_addr)))

extern u_int ifindex;
extern int mainaddr_set;
extern struct olsr olsr;
extern struct zclient *zclient;
extern struct thread_master *master;


void neighbor_set_create (struct list **);
void olsr_internet_gateway_set_create (struct list **);
void neighbor_set_delete (struct list *, struct olsr_neighbor_tuple *);

int olsr_neighbor_is_SYM (struct in6_addr *);

struct olsr_neighbor_tuple *neighbor_set_add (struct list *,
					      struct olsr_neighbor_tuple *);
struct olsr_neighbor_tuple *olsr_neighbor_tuple_lookup_from_main_addr (struct
								       list *,
								       struct
								       in6_addr);
struct olsr_neighbor_tuple *olsr_neighbor_tuple_lookup_from_main_addr (struct
								       list *,
								       struct
								       in6_addr);


void neighbor_2hop_set_create (struct list **neighbor);

void olsr_link_set_create (struct list **);
struct olsr_link_tuple *olsr_link_set_add (struct list *,
					   struct olsr_link_tuple);
struct olsr_link_tuple *olsr_link_set_lookup (struct list *, struct in6_addr,
					      struct in6_addr);

void olsr_assoc_set_create (struct list **);
void olsr_assoc_set_destroy (struct list **);
void olsr_assoc_set_delete (struct list *, struct olsr_ifassoc_tuple *);
void olsr_assoc_set_create_local_entry (struct list *, struct list *);
struct olsr_ifassoc_tuple *olsr_assoc_set_add (struct list *,
					       struct olsr_ifassoc_tuple);
struct olsr_ifassoc_tuple *olsr_assoc_lookup (struct list *, struct in6_addr,
					      struct in6_addr);
struct in6_addr *olsr_assoc_ifaddr2mainaddr (struct list *,
					     struct in6_addr *);

void olsr_nwassoc_set_create (struct list **);
struct olsr_nwassoc_tuple *olsr_nwassoc_set_add (struct list *, struct olsr_nwassoc_tuple);
void olsr_nwassoc_set_delete (struct list *, struct olsr_nwassoc_tuple *);
struct olsr_nwassoc_tuple *olsr_nwassoc_set_lookup (struct list *,
                                        struct in6_addr, struct in6_addr, int);

void olsr_mpr_set_create (struct list **);
struct olsr_mpr_tuple *olsr_mpr_set_lookup (struct list *, struct in6_addr);


void olsr_mpr_selector_set_create (struct list **);
struct olsr_mpr_selector_tuple *olsr_mpr_selector_set_lookup (struct list *,
							      struct
							      in6_addr);
struct olsr_mpr_selector_tuple *olsr_mpr_selector_set_add (struct list *,
							   struct
							   olsr_mpr_selector_tuple);



void olsr_topology_set_create (struct list **);

void olsr_duplicate_set_create (struct list **);
struct olsr_duplicate_tuple *olsr_duplicate_set_add (struct list *, struct olsr_duplicate_tuple *);
void olsr_duplicate_set_add_recv_interface (struct olsr_duplicate_tuple *, struct in6_addr);

void olsr_routing_set_create (struct list **);
void olsr_routing_set_clear (struct list *);

int olsr_link_is_SYM (struct olsr_link_tuple *);
int olsr_link_is_ASYM (struct olsr_link_tuple *);
int olsr_link_is_LOST (struct olsr_link_tuple *);

void olsr_interface_setsockopt (int, int);
void olsr_interface_set_create (struct list **);
struct olsr_interface_tuple *olsr_interface_create (struct interface *);
struct olsr_interface_tuple *olsr_interface_get_by_name (char *ifname);

struct olsr_interface_tuple *olsr_interface_lookup_by_ifindex (struct list *,
							       int);
struct olsr_interface_tuple *olsr_interface_lookup_by_addr (struct list *,
							    struct in6_addr);

struct olsr_internet_gateway_tuple * olsr_internet_gateway_set_add
        (struct list *set, struct olsr_internet_gateway_tuple *new);

const char *ip6_sprintf(const struct in6_addr *);

void olsr_mpr_selection ();
void olsr_routing_set_update ();
void olsr_zebra_init ();
void olsr_zebra_route_update (int, struct olsr_routing_entry *);

void neighbor_link_expire_check ();
void olsr_mpr_selector_expire_check ();
void neighbor_2hop_expire_check ();
void olsr_duplicate_set_expire_check ();
void olsr_topology_set_expire_check ();
void olsr_interface_association_set_expire_check ();
void olsr_network_association_set_expire_check ();
void olsr_global_prefix_expire_check ();

void olsr_vty_cmd_init ();
void olsr_neighbor_install_element ();
void olsr_mpr_install_element ();
void olsr_topology_install_element ();
void olsr_route_install_element ();
void olsr_assoc_install_element ();
void olsr_nwassoc_install_element ();
void olsr_link_install_element ();

struct olsr_link_tuple *olsr_link_set_lookup_by_foreign_ifaddr (struct list *, struct in6_addr); 

int olsr_ifaddr_add (struct interface *, struct in6_addr *);

#endif /* _OLSR_NODE_H_ */
