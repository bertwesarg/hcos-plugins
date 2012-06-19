/* This program is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Entry/Exit Trace adds logging function calls at the entry point and
   all the exit points for certain user-specified functions.  The
   test/ directory includes a sample config file, which shows how the
   user can specify which funtions to instrument and which hook
   functions to call. */

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

/* For fgets_unlocked */
#define _GNU_SOURCE

#include <inttypes.h>
#include <locale.h>

#include "config.h"
#include "libiberty.h"
#include "filenames.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "toplev.h"
#include "tree.h"
#include "input.h"
#include "varray.h"
#include "hashtab.h"
#include "pointer-set.h"
#include "splay-tree.h"
#include "langhooks.h"
#include "cgraph.h"
#include "intl.h"
#include "function.h"
#include "diagnostic.h"
#include "timevar.h"
#include "tree-iterator.h"
#include "tree-flow.h"
#include "tree-pass.h"
#include "plugin.h"
#include "gimple.h"
#include "c-common.h"

/* GCC only allows plug-ins that include this symbol. */
int plugin_is_GPL_compatible;

static const char dir_separator_str[] = { DIR_SEPARATOR, 0 };

//#define DEBUG
//#define PAUSE_ON_START

/* Print some potentially useful info when verbose is true.  When
   DEBUG is off, use the verbose=true option in the plugin args to
   turn verbose mode on. */
#ifndef DEBUG
static int verbose = false;
#else
static int verbose = true;
#endif

static char *entry_hook_name = "__scorep_entry";
static char *exit_hook_name = "__scorep_exit";
static char *token_var_name = "__scorep_token";
static char attribute_name[32] = "scorep_noinstrument";
static int token_size = 64;
static int token_unsigned = 1;

static GTY(()) tree token_type;
static GTY(()) tree entry_hook_decl;
static GTY(()) tree exit_hook_decl;

static tree build_string_ptr(const char* string)
{
  size_t	string_len;
  tree		string_tree;

  tree		string_ref;
  tree		ret;

  string_len = strlen(string) + 1;

  string_tree = build_string(string_len, string);
  TREE_TYPE(string_tree) = build_array_type(char_type_node, build_index_type(size_int(string_len)));

  string_ref = build4(ARRAY_REF,
                      char_type_node,
                      string_tree,
                      build_int_cst(TYPE_DOMAIN(TREE_TYPE(string_tree)), 0),
                      NULL,
                      NULL);

  ret = build1(ADDR_EXPR,
               build_pointer_type(TREE_TYPE(string_ref)),
               string_ref);

  return ret;
}

static void insert_entryexit_hooks(const char *function_name)
{
/*
  char *tmp_full_path;
  if (!IS_ABSOLUTE_PATH(input_filename))
    tmp_full_path = concat(getpwd(), dir_separator_str, input_filename, NULL);
  else
    tmp_full_path = xstrdup(input_filename);
  char *full_path = lrealpath(tmp_full_path);
  free(tmp_full_path);
*/
  char *full_path = "<foo.c>";

  if (!cfun)
    {
      fprintf(stderr, "Entry/Exit Trace: No cfun\n");
      return;
    }

  if (verbose)
    fprintf(stderr, "Entry/Exit Trace: Adding entry and exit hooks to %s\n", function_name);

  tree token_var = build_decl(UNKNOWN_LOCATION,
			      VAR_DECL,
			      get_identifier(token_var_name),
			      token_type);
  TREE_STATIC(token_var) = 1;
  TREE_PUBLIC(token_var) = 0;
  DECL_ARTIFICIAL(token_var) = 1;
  DECL_INITIAL(token_var) = build_int_cst(token_type, 0);
  DECL_IGNORED_P(token_var) = 1;
  DECL_CONTEXT(token_var) = current_function_decl;
  varpool_finalize_decl(token_var);
puts(__func__);

  /* Insert the entry hook. */
  edge in_edge = single_succ_edge(ENTRY_BLOCK_PTR_FOR_FUNCTION(cfun));

  int end_lno = 0;
  if (cfun && cfun->function_end_locus != UNKNOWN_LOCATION)
    end_lno = LOCATION_LINE(cfun->function_end_locus);

  gimple hook_call = gimple_build_call(entry_hook_decl, 5,
				       token_var,
				       build_string_ptr(function_name),
				       build_string_ptr(full_path),
				       build_int_cst(integer_type_node, input_line),
				       build_int_cst(integer_type_node, end_lno));
  gimple_call_set_lhs(hook_call, token_var);

  gsi_insert_on_edge_immediate(in_edge, hook_call);

  basic_block bb;
  FOR_EACH_BB(bb)
    {
      gimple_stmt_iterator gsi;
      for (gsi = gsi_start_bb(bb) ; !gsi_end_p(gsi) ; gsi_next(&gsi))
	{
	  gimple stmt = gsi_stmt(gsi);

	  if (gimple_code(stmt) == GIMPLE_RETURN)
	    {
	      int lno = 0;
	      if (gimple_has_location(stmt))
		lno = LOCATION_LINE(gimple_location(stmt));
	      hook_call = gimple_build_call(exit_hook_decl, 1, token_var);
	      gsi_insert_before(&gsi, hook_call, GSI_SAME_STMT);
	    }
	}
    }
  //free(full_path);
}

static unsigned int transform_gimple()
{
  const char *function_name;

  if (!token_type)
    {
      tree func_type;

      if (verbose)
        fprintf(stderr, "Entry/Exit Trace: Build types and function decls\n");

      /* Build the necessary types/decls. */
      token_type = lang_hooks.types.type_for_size(token_size, token_unsigned);

      func_type = build_function_type_list(token_type,
					   token_type,
					   /* Func name */
					   build_pointer_type(char_type_node),
					   /* File name */
					   build_pointer_type(char_type_node),
					   /* Begin line number */
					   integer_type_node,
					   /* End line number */
					   integer_type_node,
					   NULL_TREE);
      entry_hook_decl = build_fn_decl(entry_hook_name, func_type);
      TREE_PUBLIC(entry_hook_decl) = 1;

      func_type = build_function_type_list(void_type_node,
					   token_type,
					   NULL_TREE);
      exit_hook_decl = build_fn_decl(exit_hook_name, func_type);
      TREE_PUBLIC(exit_hook_decl) = 1;
    }

  function_name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

  if (lookup_attribute(attribute_name, DECL_ATTRIBUTES(cfun->decl)) != NULL)
    {
      if (verbose)
	fprintf(stderr, "Entry/Exit Trace: Skipping function %s marked as with '%s'.\n",
		function_name, attribute_name);
      return 0;
    }

  insert_entryexit_hooks(function_name);

  return 0;
}

/* Some attributes (mainly noinstrument) are shared by several
   plug-ins.  If all the plug-ins attempt to register the same
   attribute, GCC will get angry (and fail an assert check).  This
   functions registers an attribute only after checking to make sure
   it hasn't been registered by another plug-in. */
void register_attribute_once(const struct attribute_spec *attr)
{
  if (lookup_attribute_spec(get_identifier(attr->name)) == NULL)
    {
      /* Safe to register this attribute. */
      register_attribute(attr);
    }
  else
    {
      /* This attribute was already registered. */
      if (verbose)
	fprintf(stderr, "Entry/Exit Trace: Ignoring duplicate registration of attribute %s.\n",
		attr->name);
    }
}

static tree null_attrib_handler(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
  return NULL_TREE;
}

static struct attribute_spec noinstr_attr = {
  .name = attribute_name,
  .min_length = 0,
  .max_length = 0,
  .decl_required = false,
  .type_required = false,
  .function_type_required = false,
  .handler = null_attrib_handler,
};

static void register_plugin_attributes(void *event_data, void *data)
{
  register_attribute_once(&noinstr_attr);
}

/* This is the last plug-in function called before GCC exits.  Cleanup
   all the memory we allocated. */
static void cleanup(void *event_date, void *data)
{
}

static void
pre_genericize(void *fndecl_tree, void *data)
{
  tree fndecl = fndecl_tree;
  DECL_NO_INSTRUMENT_FUNCTION_ENTRY_EXIT(fndecl) = 1;
}

static void
pass_execution(void *opt_pass, void *user_data)
{
    struct opt_pass *pass = opt_pass;

    char *fname = "<unknown>";
    if (current_function_decl)
        fname = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

    if (pass)
        printf("%s on '%s'\n", pass->name, fname);
}

static struct opt_pass pass_instrument_field_refs = {
  .type = GIMPLE_PASS,
  .name = "scorep_instrument",
  .gate = NULL,
  .execute = transform_gimple,
  .sub = NULL,
  .next = NULL,
  .static_pass_number = 0,
  .tv_id = 0,
  .properties_required = PROP_cfg,
  .properties_provided = 0,
  .properties_destroyed = PROP_ssa | PROP_cfg,
  .todo_flags_start = TODO_dump_func,
  .todo_flags_finish = TODO_dump_func | TODO_update_ssa_any,
};

static struct register_pass_info pass_info = {
  .pass = &pass_instrument_field_refs,
  /* .reference_pass_name = "cfg", */
  .reference_pass_name = "*all_optimizations",
  .ref_pass_instance_number = 0,
  .pos_op = PASS_POS_INSERT_AFTER,
};

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
  const char *plugin_name = plugin_info->base_name;
  int argc = plugin_info->argc;
  struct plugin_argument *argv = plugin_info->argv;
  int i;

#ifdef DEBUG
  fprintf(stderr, "Initializing Entry/Exit Trace plugin.\n");
#endif

#ifdef PAUSE_ON_START
  fprintf(stderr, "cc has PID %d.  Attach debugger now.\n", getpid());
  fprintf(stderr, "[Enter to continue.]\n");
  scanf("%*c");
#endif

  /* Parse plugin arguments. */
  for (i = 0 ; i < argc ; i++)
    {
      if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	}
      else
	{
	  warning(0, "(Entry/Exit Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
		  argv[i].key);
	}
    }

  if (verbose)
    fprintf(stderr, "Entry/Exit Trace plugin running in verbose mode.\n");

  /* Set up a callback to register our attributes. */
  register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_plugin_attributes, NULL);

  /* Register the main GIMPLE pass, which performs the actual instrumentation. */
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  register_callback(plugin_name, PLUGIN_PASS_EXECUTION, pass_execution, NULL);

  /* Register the main GIMPLE pass, which performs the actual instrumentation. */
  register_callback(plugin_name, PLUGIN_PRE_GENERICIZE, pre_genericize, NULL);

  /* Register our cleanup function. */
  register_callback(plugin_name, PLUGIN_FINISH, cleanup, NULL);

  return 0;
}
