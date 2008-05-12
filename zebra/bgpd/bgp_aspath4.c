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

#include <zebra.h>

#include <bgpd/bgpd.h>
#include <bgpd/bgp_aspath4.h>

/* Four octet AS string parser token type enumeration.  */
enum bgp_as4_token_type
  {
    bgp_as4_token_val,
    bgp_as4_token_dot,
    bgp_as4_token_error,
    bgp_as4_token_eof
  };

/* Tokenizer struct.  */
struct bgp_as4_token
{
  /* Last character which caused parse error.  */
  char *str;

  /* BGP AS4 token type.  */
  enum bgp_as4_token_type type;

  /* AS value.  This can be AS2 or AS4 value.  */
  u_int32_t val;
};

/* Four octet AS string tokenizer.  The format can be AS2:AS2 or
   AS4.  */
char *
bgp_as4_gettoken (char *str, struct bgp_as4_token *token)
{
  char *p = str;
  int digit = 0;
  u_int32_t digit_val = 0;

  /* Skip white space.  */
  while (isspace ((int) *p))
    p++;

  /* Check the end of the line.  */
  if (*p == '\0')
    {
      token->type = bgp_as4_token_eof;
      token->str = p;
      return NULL;
    }

  /* Process dot.  */
  if (*p == '.')
    {
      p++;
      token->type = bgp_as4_token_dot;
      token->str = p;
      return p;
    }

  /* Digit processing.  */
  while (isdigit ((int) *p))
    {
      if (! digit)
	digit = 1;

      digit_val *= 10;
      digit_val += (*p - '0');

      p++;
    }

  /* In case of digit.  The maximum value is */
  if (digit)
    {
      token->type = bgp_as4_token_val;
      token->val = digit_val;
      token->str = p;
      return p;
    }

  token->type = bgp_as4_token_error;
  token->str = p;
  return NULL;
}

/* Parse four octet AS value.  */
int
bgp_aspath4_str2as (char *str, as4_t *as, int *as_type)
{
  struct bgp_as4_token token;
  int dotnum;
  as4_t val;

  /* Clear values.  */
  memset (&token, 0, sizeof (struct bgp_as4_token));
  dotnum = 0;
  val = 0;

  /* When '.' is included in the value or the AS value is larger than
     two octet AS value, it is AS4.  */
  while ((str = bgp_as4_gettoken (str, &token)) != NULL)
    {
      switch (token.type)
	{
	case bgp_as4_token_val:
	  if (dotnum == 0)
	    /* First value, just set it.  */
	    val = token.val;
	  else if (dotnum == 1)
	    /* Second value, add to existing value.  */
	    val += token.val;
	  break;

	case bgp_as4_token_dot:
	  if (dotnum == 0)
	    /* In case of first dot.  */
	    val <<= 16;
	  else if (dotnum >= 1)
	    /* Dot should only appear once.  */
	    return -1;
	  dotnum++;
	  break;
	  
	default:
	  break;
	}
    }

  /* Value must be set.  */
  if (val == 0)
    return -1;

  /* Set value.  */
  *as = val;
  *as_type = (dotnum ? 1 : val > 65535 ? 1 : 0);

  return 0;
}

/**/
int
bgp_aspath4_test()
{
  int ret;
  as4_t as;
  int as_type;

  ret = bgp_aspath4_str2as ("65535.65530", &as, &as_type);

  printf ("ret %d\n", ret);
  printf ("as_type %d\n", as_type);

  if (as_type)
    {

      printf ("as %u.%u\n", BGP_AS4_HIGH(as), BGP_AS4_LOW(as));
      printf ("as %u\n", as);
    }
  else
    printf ("as %d\n", as);

  return ret;
}
