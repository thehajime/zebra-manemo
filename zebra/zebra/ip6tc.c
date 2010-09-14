#include <zebra.h>

#include <libiptc/libip6tc.h>
#include <xtables.h>
#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6t_mh.h>

int nat_enable = 0;

union nf_conntrack_man_proto {
	/* Add other protocols here. */
	__be16 all;

	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;	/* GRE key is 32bit, PPtP only uses 16bit */
	} gre;
};

struct nf_nat6_range
{
	/* Set to OR of flags above. */
	unsigned int flags;

	/* Inclusive: network order. */
	struct in6_addr min_ip6, max_ip6;

	/* Inclusive: network order */
	union nf_conntrack_man_proto min, max;
};

/* For backwards compat: don't use in modern code. */
struct nf_nat6_multi_range_compat
{
	unsigned int rangesize; /* Must be 1. */

	/* hangs off end. */
	struct nf_nat6_range range[1];
};

static int
zebra_mod_chain_entry (int cmd, const char *chain, const char *target, 
                       struct ip6tc_handle *handle, 
                       struct in6_addr *src, struct in6_addr *dst, struct in6_addr *trans)
{
  if (!nat_enable)
    return 0;

  struct in6_addr tmp;
  struct ip6t_entry *chain_entry = calloc (1, sizeof (struct ip6t_entry));
  long match_size = 0;
  int ret;

  /* SNAT */
  if (src)
    {
      memcpy (&chain_entry->ipv6.src, src, sizeof (*src));
      inet_pton (AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &tmp);
      memcpy (&chain_entry->ipv6.smsk, &tmp, sizeof (tmp));
    }
  else
    {
      inet_pton (AF_INET6, "::0", &tmp);
      memcpy (&chain_entry->ipv6.src, &tmp, sizeof (tmp));
      inet_pton (AF_INET6, "::0", &tmp);
      memcpy (&chain_entry->ipv6.smsk, &tmp, sizeof (tmp));
    }

  if (dst)
    {
      memcpy (&chain_entry->ipv6.dst, dst, sizeof (*dst));
      inet_pton (AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &tmp);
      memcpy (&chain_entry->ipv6.dmsk, &tmp, sizeof (tmp));
    }
  else
    {
      inet_pton (AF_INET6, "::0", &tmp);
      memcpy (&chain_entry->ipv6.dst, &tmp, sizeof (tmp));
      inet_pton (AF_INET6, "::0", &tmp);
      memcpy (&chain_entry->ipv6.dmsk, &tmp, sizeof (tmp));
    }


  //  strncpy (chain_entry->ipv6.outiface, "sim0", 4);
  //  memset (chain_entry->ipv6.outiface_mask, 0xFF, 4);


  /* Target */
  struct ip6t_entry_target *entry_target = NULL;
  struct nf_nat6_multi_range_compat *range;
  size_t size;
  size = IP6T_ALIGN(sizeof(struct ip6t_entry_target)) + IP6T_ALIGN(sizeof(struct nf_nat6_multi_range_compat));
  entry_target = calloc(1, size);

  range = (struct nf_nat6_multi_range_compat *)entry_target->data;
  range->rangesize = 1;
  memcpy (&range->range[0].min_ip6, trans, sizeof (*trans));

  entry_target->u.user.target_size = size;
  strncpy(entry_target->u.user.name, target, IP6T_FUNCTION_MAXNAMELEN);

  /* Match */
  struct ip6t_entry_match *entry_match = NULL;

#if 0
  chain_entry->ipv6.proto = IPPROTO_MH;
  chain_entry->ipv6.flags |= IP6T_F_PROTO;
  struct ip6t_mh *mhinfo;
  size = IP6T_ALIGN(sizeof(*entry_match)) + IP6T_ALIGN (sizeof(mhinfo));
  entry_match = calloc(1, size);
  strncpy(entry_match->u.user.name, "mh", IP6T_FUNCTION_MAXNAMELEN);

  mhinfo = (struct ip6t_mh *)entry_match->data;
  mhinfo->types[0] = 0;
  mhinfo->types[1] = 200;
  mhinfo->invflags = 0;
#endif

  if (entry_match)
    {
      entry_match->u.match_size = size;
      match_size = entry_match->u.match_size;
    }

  /* Combine to Chain */
  chain_entry = realloc(chain_entry, sizeof(*chain_entry) + match_size + entry_target->u.target_size);
  memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
  chain_entry->target_offset = sizeof(*chain_entry) + match_size;
  chain_entry->next_offset = sizeof(*chain_entry) + match_size + entry_target->u.target_size;

  if (entry_match)
    memcpy(chain_entry->elems, entry_match, match_size);

  {
    char abuf1[INET6_ADDRSTRLEN], abuf2[INET6_ADDRSTRLEN], abuf3[INET6_ADDRSTRLEN];
    zlog_info ("NAT cmd=%d src: %s dst: %s trans: %s",
               cmd,
               inet_ntop (AF_INET6, &chain_entry->ipv6.src, abuf1, sizeof (abuf1)),
               inet_ntop (AF_INET6, &chain_entry->ipv6.dst, abuf2, sizeof (abuf2)),
               inet_ntop (AF_INET6, trans, abuf3, sizeof (abuf3))
               );
  }


  if (cmd == 0)
    ret = ip6tc_append_entry(chain, chain_entry, handle);
  else if (cmd == 1)
    ret = ip6tc_delete_entry(chain, chain_entry, "", handle);
  else
    {
      zlog_err ("ABORT");
      //      assert (0);
    }
    

  free (entry_target);
  free (chain_entry);

  return ret;
}

#define CMD_ADD 0
#define CMD_DEL 1

int
zebra_iptc_add (struct in6_addr *ocoa, struct in6_addr *pcoa)
{
  struct ip6tc_handle *handle = NULL;
  char *table = "nat";
  int ret;
  struct in6_addr src, dst, trans;

  handle = ip6tc_init(table);
  if (!handle)
    {
      zlog_err ("can't initialize iptables table `%s': %s",
                table, iptc_strerror(errno));
      return -1;
    }

  dump_entries6 (handle);

  trans = *ocoa;
  memcpy (&trans, pcoa, sizeof(struct in6_addr)/2); /* copy higher 64 bit */
  ret = zebra_mod_chain_entry (CMD_ADD, "POSTROUTING", "SNAT", handle, ocoa, NULL, &trans);
  ret = zebra_mod_chain_entry (CMD_ADD, "PREROUTING", "DNAT", handle, NULL, &trans, ocoa);

  if (!ret) {
    zlog_err ("ABORT");
    //    assert (0);
  }
  ret = ip6tc_commit(handle);
  ip6tc_free(handle);
}

int
zebra_iptc_del (struct in6_addr *ocoa, struct in6_addr *pcoa)
{
  struct ip6tc_handle *handle = NULL;
  char *table = "nat";
  int ret;
  struct in6_addr src, dst, trans;

  handle = ip6tc_init(table);
  if (!handle)
    {
      zlog_err ("can't initialize iptables table `%s': %s",
                table, iptc_strerror(errno));
      return -1;
    }

  dump_entries6 (handle);

  trans = *ocoa;
  memcpy (&trans, pcoa, sizeof(struct in6_addr)/2); /* copy higher 64 bit */
  ret = zebra_mod_chain_entry (CMD_DEL, "POSTROUTING", "SNAT", handle, ocoa, NULL, &trans);
  ret = zebra_mod_chain_entry (CMD_DEL, "PREROUTING", "DNAT", handle, NULL, &trans, ocoa);

  if (!ret) {
    zlog_err ("ABORT");
    //    assert (0);
  }
  ret = ip6tc_commit(handle);
  ip6tc_free(handle);
}
