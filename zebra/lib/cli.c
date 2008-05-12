/* Command line interface implementation.
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

#include "zebra.h"
#include "vector.h"
#include "cli.h"

/* CLI macros.  */
#define WHITE_SPACE(C)     ((C) == ' ' || (C) == '\t' || (C) == '\n')
#define DELIMITER(C)       (WHITE_SPACE(C) || (C) == '\0')
#define COMMENT_CHAR(C)    ((C) == '!' || (C) == '#')

#if 0
/* Generic CLI Installation. */
int
cli_install_gen (struct cli_tree *ctree, int mode,
                 u_char privilege, u_int16_t flags, struct cli_element *cel)
{
  struct cli_builder cb;
  struct cli_node *node;
  vector parent;
  int index, max;

  /* Set flags. */
  if (flags)
    SET_FLAG (cel->flags, flags);

  /* Check help string is there.  */
  cli_check_help (cel, &index, &max);

  if (mode > MAX_MODE)
    return -1;

  /* Lookup root node.  */
  node = vector_lookup_index (ctree->modes, mode);

  /* Install a new root node.  */
  if (! node)
    {
      node = cli_node_new ();
      vector_set_index (ctree->modes, mode, node);
    }

  /* Update IFNAME token and help string.  */
  if (ifname_expand_token)
    cli_ifname_reflect (cel, index, max);

  /* Set initial value before calling cli_build().  */
  parent = vector_init (VECTOR_MIN_SIZE);
  vector_set (parent, node);
  cb.str = cel->str;
  cb.index = 0;

  cli_build (parent, NULL, NULL, &cb, cel, privilege, 0);

  vector_free (parent);

  return 0;
}

/* Compatible function for non-VR-supported protocols. */
int
cli_install (struct cli_tree *ctree, int mode,
             struct cli_element *cel)
{
  u_char privilege = PRIVILEGE_NORMAL;

  if (mode == EXEC_PRIV_MODE)
    {
      mode = EXEC_MODE;
      privilege = PRIVILEGE_MAX;
    }

  return cli_install_gen (ctree, mode, privilege, 0, cel);
}
#endif
