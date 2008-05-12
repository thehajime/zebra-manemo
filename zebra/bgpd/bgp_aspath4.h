/* BGP four octet AS path support.
   Copyright (C) 2007 Kunihiro Ishiguro.

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

#ifndef _BGP_ASPATH4_H_
#define _BGP_ASPATH4_H_

/* Four octet AS to two octet separation macro.  */
#define BGP_AS4_HIGH(AS4)  (((AS4) >> 16) & 0xffff)
#define BGP_AS4_LOW(AS4)   ((AS4) & 0xffff)

/* Prototypes.  */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _BGP_ASPATH4_H_ */
