/* Zebra connect library for OSPFd.
   Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada.

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GNU Zebra is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
Boston, MA 02110-1301, USA.  */

#ifndef _ZEBRA_OSPF_ZEBRA_H
#define _ZEBRA_OSPF_ZEBRA_H

#define EXTERNAL_METRIC_TYPE_1      0
#define EXTERNAL_METRIC_TYPE_2      1

#define DEFAULT_ROUTE		    ZEBRA_ROUTE_MAX
#define DEFAULT_ROUTE_TYPE(T) ((T) == DEFAULT_ROUTE)

/* OSPF distance. */
struct ospf_distance
{
  /* Distance value for the IP source prefix. */
  u_char distance;

  /* Name of the access-list to be matched. */
  char *access_list;
};

/* Prototypes */
void ospf_zclient_start ();

void ospf_zebra_add (struct prefix_ipv4 *, struct ospf_route *);
void ospf_zebra_delete (struct prefix_ipv4 *, struct ospf_route *);

void ospf_zebra_add_discard (struct prefix_ipv4 *);
void ospf_zebra_delete_discard (struct prefix_ipv4 *);

int ospf_default_originate_timer (struct thread *);

int ospf_redistribute_check (struct ospf *, struct external_info *, int *);
int ospf_distribute_check_connected (struct ospf *, struct external_info *);
void ospf_distribute_list_update (struct ospf *, int);

int ospf_is_type_redistributed (int);
void ospf_distance_reset (struct ospf *);
u_char ospf_distance_apply (struct prefix_ipv4 *, struct ospf_route *);

struct vty;

int ospf_redistribute_set (struct ospf *, int, int, int);
int ospf_redistribute_unset (struct ospf *, int);
int ospf_redistribute_default_set (struct ospf *, int, int, int);
int ospf_redistribute_default_unset (struct ospf *);
int ospf_distribute_list_out_set (struct ospf *, int, char *);
int ospf_distribute_list_out_unset (struct ospf *, int, char *);
void ospf_routemap_set (struct ospf *, int, char *);
void ospf_routemap_unset (struct ospf *, int);
int ospf_distance_set (struct vty *, struct ospf *, char *, char *, char *);
int ospf_distance_unset (struct vty *, struct ospf *, char *, char *, char *);
#ifdef HAVE_KBFD
int ospf_bfd_peer_add (struct ospf_neighbor *);
int ospf_bfd_peer_delete (struct ospf_neighbor *);
#endif /*HAVE_KBFD*/
void ospf_zebra_init ();

#endif /* _ZEBRA_OSPF_ZEBRA_H */

