/* AS path related definitions.
   Copyright (C) 1997, 98, 99 Kunihiro Ishiguro.

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

/* AS path segment type.  */
#define AS_SET                       1
#define AS_SEQUENCE                  2
#define AS_CONFED_SEQUENCE           3
#define AS_CONFED_SET                4

/* Private AS range defined in RFC2270.  */
#define BGP_PRIVATE_AS_MIN       64512
#define BGP_PRIVATE_AS_MAX       65535

/* AS number for two octet to four octet transition.  */
#define BGP_AS_TRANS             23456
#define BGP_AS2_MAX              65535

/* AS path may be include some AsSegments.  */
struct aspath 
{
  /* Reference count to this aspath.  */
  unsigned long refcnt;

  /* Rawdata length.  */
  int length;

  /* AS count.  */
  int count;

  /* Rawdata.  */
  caddr_t data;

  /* String expression of AS path.  This string is used by vty output
     and AS path regular expression match.  */
  char *str;
};

#define ASPATH_STR_DEFAULT_LEN 32

/* Prototypes. */
void aspath_init ();
struct aspath *aspath_parse ();
struct aspath *aspath_dup (struct aspath *);
struct aspath *aspath_aggregate (struct aspath *, struct aspath *);
struct aspath *aspath_prepend (struct aspath *, struct aspath *);
struct aspath *aspath_add_seq (struct aspath *, as_t);
struct aspath *aspath_add_confed_seq (struct aspath *, as_t);
int aspath_cmp_left (struct aspath *, struct aspath *);
int aspath_cmp_left_confed (struct aspath *, struct aspath *);
struct aspath *aspath_delete_confed_seq (struct aspath *);
struct aspath *aspath_empty ();
struct aspath *aspath_empty_get ();
struct aspath *aspath_str2aspath (const char *);
void aspath_free (struct aspath *);
struct aspath *aspath_intern (struct aspath *);
void aspath_unintern (struct aspath *);
const char *aspath_print (struct aspath *);
void aspath_print_vty (struct vty *, struct aspath *);
void aspath_print_all_vty (struct vty *);
unsigned int aspath_key_make (struct aspath *);
int aspath_loop_check (struct aspath *, as_t);
int aspath_private_as_check (struct aspath *);
int aspath_firstas_check (struct aspath *, as_t);
unsigned long aspath_count ();

/* Include four octet AS path.  */
#include "bgp_aspath4.h"
