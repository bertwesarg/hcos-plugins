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

#include "config.h"
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

//#define DEBUG
//#define PAUSE_ON_START

#define NOINSTRUMENT_ATTR "hcos_noinstrument"

/* Print some potentially useful info when verbose is true.  When
   DEBUG is off, use the verbose=true option in the plugin args to
   turn verbose mode on. */
#ifndef DEBUG
static int verbose = false;
#else
static int verbose = true;
#endif

/* Default config file */
static const char *config_file_name = "entryexit-trace.config";

typedef const char *func_name;
DEF_VEC_P(func_name);
DEF_VEC_ALLOC_P(func_name, heap);
static VEC(func_name, heap) *func_name_vec;

const char *entry_hook_name = NULL;
const char *exit_hook_name = NULL;

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
  tree hook_type;
  tree entry_hook_decl;
  tree exit_hook_decl;

  basic_block bb;
  gimple_stmt_iterator gsi;
  gimple stmt;

  if (verbose)
    fprintf(stderr, "Entry/Exit Trace: Adding entry and exit hooks to %s\n", function_name);

  /* Build the necessary types/decls. */
  hook_type = build_function_type_list(void_type_node,
				       build_pointer_type(char_type_node), /* Func name */
				       build_pointer_type(char_type_node), /*File name*/
				       integer_type_node, /* Line number */
				       NULL_TREE);
  entry_hook_decl = build_fn_decl(entry_hook_name, hook_type);
  exit_hook_decl = build_fn_decl(exit_hook_name, hook_type);

  /* Insert the entry hook. */
  bb = ENTRY_BLOCK_PTR_FOR_FUNCTION(cfun)->next_bb;
  gsi = gsi_start_bb(bb);
  gimple hook_call = gimple_build_call(entry_hook_decl, 3,
				       build_string_ptr(function_name),
				       build_string_ptr(input_filename),
				       build_int_cst(integer_type_node, input_line));
  gsi_insert_before(&gsi, hook_call, GSI_SAME_STMT);

  FOR_EACH_BB(bb)
    {
      for (gsi = gsi_start_bb(bb) ; !gsi_end_p(gsi) ; gsi_next(&gsi)) 
	{
	  stmt = gsi_stmt(gsi);
	  if (gimple_has_location(stmt))
	    input_location = gimple_location(stmt);

	  if (gimple_code(stmt) == GIMPLE_RETURN)
	    {
	      gimple hook_call = gimple_build_call(exit_hook_decl, 3,
						   build_string_ptr(function_name),
						   build_string_ptr(input_filename),
						   build_int_cst(integer_type_node, input_line));
	      gsi_insert_before(&gsi, hook_call, GSI_SAME_STMT);
	    }
	}
    }
}

/* Return true if the given function name should get entry and exit
   hooks (based on the user's list). */
static bool check_func(const char *function_name)
{
  int i;
  const char *check_name;
  for (i = 0 ; VEC_iterate(func_name, func_name_vec, i, check_name) ; i++)
    if (strcmp(function_name, check_name) == 0)
      return true;

  return false;
}

static unsigned int transform_gimple()
{
  const char *function_name;
  function_name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

  if (lookup_attribute(NOINSTRUMENT_ATTR, DECL_ATTRIBUTES(cfun->decl)) != NULL)
    {
      if (verbose)
	fprintf(stderr, "(Entry/Exit Trace) Function %s marked as noinstrument.  Skipping.\n",
		function_name);
      return 0;
    }


  if (check_func(function_name))
    {
      insert_entryexit_hooks(function_name);
    }

  return 0;
}

static void handle_config_pair(const char *key, const char *value)
{
  if (strcmp(key, "func") == 0)
    {
      if (verbose)
	fprintf(stderr, "(Entry/Exit Trace) Found config entry for function: %s.\n", value);

      VEC_safe_push(func_name, heap, func_name_vec, xstrdup(value));
    }
  else if (strcmp(key, "entry-hook") == 0)
    {
      if (entry_hook_name != NULL)
	error("Entry/Exit Trace: Plug-in options specify more than one entry hook name");

      entry_hook_name = xstrdup(value);
    }
  else if (strcmp(key, "exit-hook") == 0)
    {
      if (exit_hook_name != NULL)
	error("Entry/Exit Trace: Plug-in options specify more than one exit hook name");

      exit_hook_name = xstrdup(value);
    }
  else if (strcmp(key, "verbose") == 0)
    {
      verbose = true;
      fprintf(stderr, "Entry/Exit Trace plug-in running in verbose mode.\n");
    }
  else
    {
      error("Invalid key '%s' in Entry/Exit Trace configuration", key);
    }
}

static void read_config_file(const char *filename)
{
  int config_lineno = 0;
  char line[1024];
  FILE *file = fopen(filename, "r");

  if (file == NULL)
    goto out_file_err;

  while (fgets(line, sizeof(line), file) != NULL)
    {
      char *key_start;
      char *val_start;
      char *newline_pos;

      config_lineno++;

      /* Chomp the newline. */
      newline_pos = strchr(line, '\r');
      if (newline_pos == NULL)
	newline_pos = strchr(line, '\n');
      if (newline_pos != NULL)
	*newline_pos = '\0';

      /* Start with the first non-whitespace character. */
      for (key_start = line ; ISSPACE(*key_start) ; key_start++)
	;

      /* Ignore # lines (comments) and blank lines. */
      if (*key_start == '#' || *key_start == '\0')
	continue;

      val_start = strchr(key_start, '=');
      if (val_start == NULL)
	goto out_parse_err;

      *val_start = '\0';
      val_start++;

      handle_config_pair(key_start, val_start);
    }

  /* Did we exit because of EOF or because of an I/O error? */
  if (!feof(file))
    goto out_file_err;

  fclose(file);
  return;

 out_file_err:
  if (file != NULL)
    fclose(file);
  error("(Entry/Exit Trace) Failed to read config file %s: %s", filename, strerror(errno));
  return;

 out_parse_err:
  fclose(file);
  error("(Entry/Exit Trace) Parse error in config file %s:%d", filename, config_lineno);
  return;
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
	fprintf(stderr, "(Field Trace) Ignoring duplicate registration of attribute %s.\n",
		attr->name);
    }
}

static tree null_attrib_handler(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
  return NULL_TREE;
}

static struct attribute_spec noinstr_attr = {
  .name = NOINSTRUMENT_ATTR,
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

static struct opt_pass pass_instrument_field_refs = {
  .type = GIMPLE_PASS,
  .name = "instr_entryexit",
  .gate = NULL,
  .execute = transform_gimple,
  .sub = NULL,
  .next = NULL,
  .static_pass_number = 0,
  .tv_id = 0,
  .properties_required = 0,
  .properties_provided = 0,
  .properties_destroyed = 0,
  .todo_flags_start = 0,
  .todo_flags_finish = TODO_update_ssa,
};

static struct plugin_pass pass_info = {
  .pass = &pass_instrument_field_refs,
  .reference_pass_name = "*all_optimizations",
  .ref_pass_instance_number = 0,
  .pos_op = PASS_POS_INSERT_BEFORE,
};

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
  const char *plugin_name = plugin_info->base_name;
  int argc = plugin_info->argc;
  struct plugin_argument *argv = plugin_info->argv;
  int i;

  func_name_vec = VEC_alloc(func_name, heap, 10);

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
      if (strcmp(argv[i].key, "config") == 0)
	{
	  if (argv[i].value != NULL)
	    config_file_name = argv[i].value;
	  else
	    error("(Entry/Exit Trace) Must specify filename for -fplugin-arg-%s-config", plugin_name);
	}
      else if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	  fprintf(stderr, "Entry/Exit Trace plugin running in verbose mode.\n");
	}
      else
	{
	  warning(0, "(Entry/Exit Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
		  argv[i].key);
	}
    }

  read_config_file(config_file_name);
  if (entry_hook_name == NULL)
    error("Entry/Exit Trace: Configuration does not specify an entry hook name");
  if (exit_hook_name == NULL)
    error("Entry/Exit Trace: Configuration does not specify an exit hook name");

  /* Set up a callback to register our attributes. */
  register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_plugin_attributes, NULL);

  /* Register the main GIMPLE pass, which performs the actual instrumentation. */
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  /* Register our cleanup function. */
  register_callback(plugin_name, PLUGIN_FINISH, cleanup, NULL);

  return 0;
}
