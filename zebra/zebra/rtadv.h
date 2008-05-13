/* Router advertisement.
   Copyright (C) 1999 Kunihiro Ishiguro.

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

#ifndef _ZEBRA_RTADV_H
#define _ZEBRA_RTADV_H

enum rtadv_event {RTADV_START, RTADV_STOP, RTADV_TIMER, RTADV_READ};

/* Structure which hold status of router advertisement. */
struct rtadv
{
  int sock;

  int adv_if_count;

  struct thread *ra_read;
  struct thread *ra_timer;
};

/* Router advertisement prefix. */
struct rtadv_prefix
{
  /* Prefix to be advertised. */
  struct prefix prefix;
  
  /* The value to be placed in the Valid Lifetime in the Prefix */
  u_int32_t AdvValidLifetime;
#define RTADV_VALID_LIFETIME 2592000

  /* The value to be placed in the on-link flag */
  int AdvOnLinkFlag;

  /* The value to be placed in the Preferred Lifetime in the Prefix
     Information option, in seconds.*/
  u_int32_t AdvPreferredLifetime;
#define RTADV_PREFERRED_LIFETIME 604800

  /* The value to be placed in the Autonomous Flag. */
  int AdvAutonomousFlag;
};

void rtadv_config_write (struct vty *, struct interface *);

void rtadv_event (enum rtadv_event, int);
void rtadv_send_packet (int, struct interface *, 
                        const struct in6_addr *, int);

#endif /* _ZEBRA_RTADV_H */
