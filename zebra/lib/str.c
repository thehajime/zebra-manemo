/* String functions.
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

#include <zebra.h>

#include "str.h"

#ifndef HAVE_SNPRINTF
/*
 * snprint() is a real basic wrapper around the standard sprintf()
 * without any bounds checking
 */
int
snprintf(char *str, size_t size, const char *format, ...)
{
  va_list args;

  va_start (args, format);

  return vsprintf (str, format, args);
}
#endif

#ifndef HAVE_STRLCPY
/*
 * strlcpy is a safer version of strncpy(), checking the total
 * size of the buffer
 */
size_t
strlcpy(char *dst, const char *src, size_t size)
{
  strncpy(dst, src, size);

  return (strlen(dst));
}
#endif

#ifndef HAVE_STRLCAT
/*
 * strlcat is a safer version of strncat(), checking the total
 * size of the buffer
 */
size_t
strlcat(char *dst, const char *src, size_t size)
{
  /* strncpy(dst, src, size - strlen(dst)); */

  /* I've just added below code only for workable under Linux.  So
     need rewrite -- Kunihiro. */
  if (strlen (dst) + strlen (src) >= size)
    return -1;

  strcat (dst, src);

  return (strlen(dst));
}
#endif
