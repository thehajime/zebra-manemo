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

/* Perl script is used for extracting CLI and ALI macro from source
   code.  In that case EXTRACT_CLI should be defined to prevent macro
   expansion.  */

#ifndef EXTRACT_CLI

/* CLI macro.  Macro defines a CLI structure and a CLI function.  C99
   C preprocessor variadic macros is used to define arbitrary number
   of help string definition.  */

#define CLI(func_name, cli_name, cmd_str, ...)                          \
                                                                        \
/* Function prototype.  */                                              \
int func_name (struct cli *, int, char**);                              \
                                                                        \
/* Help string array.  */                                               \
char *cli_name ## _help[] = {__VA_ARGS__, NULL};                        \
                                                                        \
/* Define CLI structure.  */                                            \
struct cli_element cli_name =                                           \
{                                                                       \
  /* Command line string.  */                                           \
  cmd_str,                                                              \
                                                                        \
   /* Function pointer.  */                                             \
  func_name,                                                            \
                                                                        \
  /* Help string is defined as an array.  Last must be NULL.  */        \
  cli_name ## _help                                                     \
};                                                                      \
                                                                        \
/* Start function body at here.  */                                     \
int func_name (struct cli *cli, int argc, char** argv)

/* ALIAS to CLI macro.  Define CLI structure only.  There is no
   function body.  */

#define ALI(func_name, cli_name, cmd_str, ...)                          \
                                                                        \
/* Help string array.  */                                               \
char *cli_name ## _help[] = {__VA_ARGS__, NULL};                        \
                                                                        \
struct cli_element cli_name =                                           \
{                                                                       \
  cmd_str,                                                              \
  func_name,                                                            \
  cli_name ## _help                                                     \
}

#endif /* EXTRACT_CLI */

/* CLI output function.  We can switch over CLI output function
   with defining cli->out_func pointer.  */

typedef int (*CLI_OUT_FUNC) (void *, char *, ...);

/* CLI output function macro.  Instead of defining a function, user
   can specify CLI output function dynamically.  */

#define cli_out(cli, ...)                                                     \
        (*(cli)->out_func)((cli)->out_val, __VA_ARGS__)

/* CLI parsing tree.  This structure has all of CLI commands and run
   time variables such as mode and privilege.  Mode and privilege
   level will be passed to cli_parse() function then set to this
   structure.  */

struct cli_tree
{
  /* Current mode.  */
  int mode;

  /* Privilege level.  */
  u_char privilege;

  /* Vector of modes.  */
  vector modes;

  /* Vector of configuration output function.  */
  vector config_write;

  /* Node to be executed.  */
  struct cli_node *exec_node;

  /* Possibly matched cel.  Function internal use only.  */
  vector v;

  /* Traverse nodes. */
  vector t;

  /* Expand is needed.  Used by describe function.  */
  int expand_node;

  /* Show node match result.  */
  int show_node;

  /* Parsed argc and argv.  */
  int argc;
#define CLI_ARGC_MAX               128
#define CLI_ARGV_MAX_LEN           256
  char *argv[CLI_ARGC_MAX];

  /* For Output Modifier.  */
  struct cli_node *modifier_node;
  int argc_modifier;
  char *argv_modifier[CLI_ARGC_MAX];
  char *rem;

  /* Parse failed character pointer to show invalid input.  */
  char *invalid;

  /* To show pipe pointer.  */
  char *pipe;

  /* Advanced mode.  */
  int advanced;
};

/* Argument to cli functions.  */
struct cli
{
  /* CLI element.  */
  struct cli_element *cel;

  /* User input string.  */
  char *str;

  /* Output function to be used by cli_out().  */
  CLI_OUT_FUNC out_func;

  /* Output function's first argument.  */
  void *out_val;

  /* Arbitrary information for line.  */
  void *line;

  /* Auth required.  */
  int auth;

  /* Input source.  */
  int source;
#define CLI_SOURCE_USER                 0
#define CLI_SOURCE_FILE                 1

  /* For "line". */
  int line_type;
  int min;
  int max;

  /* Real CLI.  */
  void *index;
  void *index_sub;
  int mode;

  /* Current CLI status.  */
  enum
    {
      CLI_NORMAL,
      CLI_CLOSE,
      CLI_MORE,
      CLI_CONTINUE,
      CLI_MORE_CONTINUE,
      CLI_WAIT
    } status;

  /* Flags. */
#if 0
  u_char flags;
#define CLI_FROM_PVR    (1 << 0)
#endif

  void *self;
  u_char privilege;
  struct cli_tree *ctree;

  /* Global variable.  */
  //struct lib_globals *zg;
  //struct ipi_vr *vr;

  /* Terminal length.  */
  int lines;

  /* Call back function.  */
  int (*callback) (struct cli *);
  int (*cleanup) (struct cli *);
  int (*show_func) (struct cli *);
  int type;
  u_int32_t count;
  void *current;
  void *arg;
  //afi_t afi;
  //safi_t safi;
};

/* Configuration output function.  */
typedef int (*CLI_CONFIG_FUNC) (struct cli *cli);

/* CLI element.  */
struct cli_element
{
  /* Command line string.  */
  char *str;

  /* Function to execute this command.  */
  int (*func) (struct cli *, int, char **);

  /* Help strings array. */
  char **help;

  /* Unique key. */
  int key;

  /* Flags of the commands.  */
  u_int16_t flags;

  /* When CLI_FLAG_HIDDEN is defined, the command isn't used for
     completion.  */
#define CLI_FLAG_HIDDEN            (1 << 0)

  /* When CLI_FLAG_MODIFIER is define, output modifier '|' can be used
     for the command.  Usually the flag is set to show commands.  */
#define CLI_FLAG_MODIFIER          (1 << 1)

  /* This is only used by struct cli_node.  When the node is "show" or
     "*s=show" this flag should be set.  */
#define CLI_FLAG_SHOW              (1 << 2)

  /* This is only used by struct cli_node.  When the node is in
     parenthesis this flag is set.  */
#define CLI_FLAG_PAREN             (1 << 3)

  /* This node is in brace.  */
#define CLI_FLAG_TRAVERSE          (1 << 4)

  /* This node is recursive.  */
#define CLI_FLAG_RECURSIVE         (1 << 5)

  /* Execute CLI function before send it to IMI.  */
#define CLI_FLAG_LOCAL_FIRST       (1 << 6)

  /* This enforce not apply the pager to the output.  */
#define CLI_FLAG_NO_PAGER          (1 << 7)

  /* This flag is used for interface name match.  */
#define CLI_FLAG_IFNAME            (1 << 8)
  
  /* Protocol module to which this command belongs. */
  u_int32_t module;
};

/* CLI tree node.  */
struct cli_node
{
  /* CLI token types.  */
  enum cli_token
    {
      cli_token_paren_open,
      cli_token_paren_close,
      cli_token_cbrace_open,
      cli_token_cbrace_close,
      cli_token_brace_open,
      cli_token_brace_close,
      cli_token_ifname_open,
      cli_token_ifname_close,
      cli_token_separator,
      cli_token_pipe,
      cli_token_redirect,
      cli_token_dot,
      cli_token_question,
      cli_token_range,
      cli_token_keyword,
      cli_token_alias,
      cli_token_line,
      cli_token_word,
      cli_token_ipv4,
      cli_token_ipv4_prefix,
      cli_token_ipv6,
      cli_token_ipv6_prefix,
      cli_token_time,
      cli_token_community,
      cli_token_mac_address,
      cli_token_ifname,
      cli_token_unknown
    } type;

  /* String to be matched.  */
  char *str;

  /* Help string.  */
  char *help;

  /* Max and min.  */
  u_int32_t max;
  u_int32_t min;

  /* Pointer to CLI element.  */
  struct cli_element *cel;

  /* Vector of next nodes.  */
  vector keywords;

  /* Privilege node.  */
  u_char privilege;

  /* Same as cli_element's flags.  */
  u_int16_t flags;

  /* Reference count.  */
  u_int32_t refcnt;
};
