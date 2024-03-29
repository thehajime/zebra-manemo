/* OSPFv3 to zebra interface.
   Copyright (C) 2003 Yasuhiro Ohara.

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

#ifndef OSPF6_ZEBRA_H
#define OSPF6_ZEBRA_H

#include "zclient.h"

/* Debug option */
extern unsigned char conf_debug_ospf6_zebra;
#define OSPF6_DEBUG_ZEBRA_SEND 0x01
#define OSPF6_DEBUG_ZEBRA_RECV 0x02
#define OSPF6_DEBUG_ZEBRA_ON(level) \
  (conf_debug_ospf6_zebra |= level)
#define OSPF6_DEBUG_ZEBRA_OFF(level) \
  (conf_debug_ospf6_zebra &= ~(level))
#define IS_OSPF6_DEBUG_ZEBRA(e) \
  (conf_debug_ospf6_zebra & OSPF6_DEBUG_ZEBRA_ ## e)

extern struct zclient *zclient;

void ospf6_zebra_route_update_add (struct ospf6_route *request);
void ospf6_zebra_route_update_remove (struct ospf6_route *request);

void ospf6_zebra_redistribute (int);
void ospf6_zebra_no_redistribute (int);
#define ospf6_zebra_is_redistribute(type) \
  (zclient->redist[type])
void ospf6_zebra_init ();

int config_write_ospf6_debug_zebra (struct vty *vty);
void install_element_ospf6_debug_zebra ();

#ifdef HAVE_KBFD
struct ospf6_neighbor;
int ospf6_bfd_peer_add (struct ospf6_neighbor *);
int ospf6_bfd_peer_delete (struct ospf6_neighbor *);
#endif /*HAVE_KBFD*/

#endif /*OSPF6_ZEBRA_H*/

