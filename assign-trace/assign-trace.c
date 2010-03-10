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

/* Assign Trace adds a logging function to every statement that
   assigns a pointer to a tracked data structure to memory.  A config
   file specifies which data structures to track.  Take a look at the
   test/ directory for an example configuration. */

/* Whether we want them or not (we don't), Autoconf _insists_ on
   defining these.  Since GCC's config.h (which we must include) also
   defines them, we have to undef them here. */
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
#include "output.h"
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
#define MARKED_ATTR "hcos_marked"

/* Print some potentially useful info when verbose is true.  When
   DEBUG is off, use the verbose=true option in the plugin args to
   turn verbose mode on. */
#ifndef DEBUG
static int verbose = false;
#else
static int verbose = true;
#endif

/* Default config file */
static const char *config_file_name = "assign-trace.config";

typedef struct hook_directive
{
  char *struct_name;
  char *hook_func_name;
} hook_directive;

DEF_VEC_O(hook_directive);
DEF_VEC_ALLOC_O(hook_directive, heap);
static VEC(hook_directive, heap) *hook_directive_vec;

static tree assign_hook_type = NULL;

static tree get_assign_hook_type()
{
  if (assign_hook_type == NULL)
    {
      /* Construct the C type for the assign-trace hook functions.
	 Functions with this type have the prototype:
	 void __report_assignment(void *addr, const char *filename, int lineno); */
      assign_hook_type = build_function_type_list(void_type_node,
						  ptr_type_node,
						  build_pointer_type(char_type_node),
						  integer_type_node,
						  NULL_TREE);
    }

  return assign_hook_type;
}

static tree build_string_ptr(const char *string)
{
  size_t	string_len;
  tree		string_tree;

  tree		string_ref;
  tree		ret;

  tree		min_value;
  tree		size_in_align;

  string_len = strlen(string) + 1;

  string_tree = build_string(string_len, string);
  TREE_TYPE(string_tree) = build_array_type(char_type_node, build_index_type(size_int(string_len)));

  min_value = TYPE_MIN_VALUE(TYPE_DOMAIN(TREE_TYPE(string_tree)));
  size_in_align = build_int_cst(size_type_node, TREE_INT_CST_LOW(TYPE_SIZE(char_type_node)) / TYPE_ALIGN(char_type_node));

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

/* Given a type node, get that type node's identifier. */
static tree get_type_identifier(tree type)
{
  tree type_name;

  /* NB: On rare occasion, TYPE_NAME() mysteriously gives us a
     TYPE_DECL instead of the IDENTIFIER_NODE we really wanted for
     Christmas.  Documentation in tree.h promises that you can use
     DECL_ORIGINAL_TYPE to get through to the _actual_ type, which has
     the real IDENTIFIER_NODE.*/
  type_name = TYPE_NAME(type);
  while (type_name != NULL && TREE_CODE(type_name) == TYPE_DECL)
    if (DECL_ORIGINAL_TYPE(type_name) != NULL)
      type_name = TYPE_NAME(DECL_ORIGINAL_TYPE(type_name));
    else
      type_name = NULL;
  gcc_assert(type_name == NULL || TREE_CODE(type_name) == IDENTIFIER_NODE);
  return type_name;
}

/* Given a GIMPLE decl node, get its name.
   The result is a const char pointer. */
static const char *get_node_name(tree node)
{
  tree type_name = get_type_identifier(TREE_TYPE(node));
  if (type_name == NULL)
    {
      if (verbose)
	fprintf(stderr, "Anonymous type.\n");
      return "__anon";
    }

  return IDENTIFIER_POINTER(type_name);
}

/* Search through the assigment directives to find one whose type
   matches the given type node.  If one is found, return it.
   Otherwise return NULL.

   A directive for type struct foo matches a type node if that node
   is for type (struct foo *).  */
static struct hook_directive *match_directive_with_type(tree type)
{
  struct hook_directive *directive;
  unsigned int i;

  for (i = 0 ; VEC_iterate(hook_directive, hook_directive_vec, i, directive) ; i++)
    {
      tree ref_type;

      if (TREE_CODE(type) != POINTER_TYPE)
	continue;  /* Not a pointer type. */

      ref_type = TREE_TYPE(type);
      if (strcmp(get_node_name(type), directive->struct_name) == 0)
	return directive;  /* Found it! */
    }

  return NULL;  /* No matches. */
}

/* Create a GIMPLE statement assigning a reference to a temporary
   variable, add that statement at the iterator gsi, then return the
   temporary variable.

   If assign_out is not NULL, it is an out parameter that returns the
   gimple statement that assigns the temp. */
static tree assign_ref_to_tmp(gimple_stmt_iterator *gsi, tree ref, const char *tmp_prefix,
			      gimple *assign_out)
{
  tree tmp = create_tmp_var(TREE_TYPE(ref), tmp_prefix);

  /* Construct an assign statement: tmp = ref; */
  gimple assign_stmt = gimple_build_assign(tmp, ref);

  /* The left side of the assignment should be an SSA_NAME, but we
     can't create the SSA_NAME until after we build the assign
     statement. */
  gimple_assign_set_lhs(assign_stmt, make_ssa_name(tmp, assign_stmt));

  gsi_insert_before(gsi, assign_stmt, GSI_SAME_STMT);

  if (assign_out != NULL)
    *assign_out = assign_stmt;
  return gimple_assign_lhs(assign_stmt);
}

/* For any statement, see if it has a left-hand side (i.e., it is an
   assignment) and if that left-hand side has a type that we are
   tracking.  If so, add the relevant hook. */
static void instrument_assignment(gimple_stmt_iterator *gsi)
{
  gimple stmt;

  stmt = gsi_stmt(*gsi);

  if (gimple_has_lhs(stmt))
    {
      tree lhs = gimple_get_lhs(stmt);
      struct hook_directive *directive;

      if ((directive = match_directive_with_type(TREE_TYPE(lhs))) != NULL)
	{
	  tree lhs_pointer;
	  tree hook_decl;
	  tree func_name_tree;
	  tree line_num_tree;
	  gimple hook_call;

	  /* We found a compatible directive.  Add a call to its hook function. */
	  mark_addressable(lhs);
	  lhs_pointer = build1(ADDR_EXPR, build_pointer_type(TREE_TYPE(lhs)),
			       stabilize_reference(lhs));
	  if (!is_gimple_address(lhs_pointer))
	    return;  /* mark_addressable() failed: we're not assigning to something with an address. */
	  lhs_pointer = assign_ref_to_tmp(gsi, lhs_pointer, "assign_tmp_ptr", NULL);

	  func_name_tree = build_string_ptr(gimple_filename(stmt));
	  line_num_tree = build_int_cst(integer_type_node, gimple_lineno(stmt));

	  hook_decl = build_fn_decl(directive->hook_func_name, get_assign_hook_type());
	  hook_call = gimple_build_call(hook_decl, 3, lhs_pointer, func_name_tree, line_num_tree);

	  gsi_insert_after(gsi, hook_call, GSI_SAME_STMT);
	}
    }
}

static void insert_assign_hooks()
{
  basic_block my_basic_block;
  gimple_stmt_iterator gsi;

  FOR_EACH_BB(my_basic_block)
  {
    for (gsi = gsi_start_bb(my_basic_block);
         !gsi_end_p(gsi);
         gsi_next(&gsi)) 
      {
	gimple my_statement = gsi_stmt(gsi);
	if (gimple_has_location(my_statement))
	  input_location = gimple_location(my_statement);

	/* At this stage, there should be no GIMPLE statements with sub-statements. */
	gcc_assert(!gimple_has_substatements(my_statement));

	instrument_assignment(&gsi);
      }
  }
}

/* A hook directive instructs Assign Trace to add function calls
   (hooks) at certain assignments.  The directive should have the
   form:

   struct_name-func_name

   This function parses the directive. */
void parse_hook_directive(const char *directive_string)
{
  int str_size;
  const char *str_start;
  const char *str_end;

  struct hook_directive directive;;

  str_start = directive_string;
  str_end = strchr(str_start, '-');
  if (str_end == NULL)
    {
      error("Invalid hook directive for Assign Trace");
      return;
    }

  str_size = (int)(str_end - str_start);
  directive.struct_name = xmalloc(str_size + 1);
  memcpy(directive.struct_name, str_start, str_size);
  directive.struct_name[str_size] = '\0';

  str_start = str_end + 1;
  /* There should only be one dash. */
  if (strchr(str_start, '-') != NULL)
    {
      error("Invalid hook directive for Assign Trace");
      return;
    }
  directive.hook_func_name = xstrdup(str_start);

  VEC_safe_push(hook_directive, heap, hook_directive_vec, &directive);

  if (verbose)
    {
      fprintf(stderr, "Assign Trace recognized directive:\n");
      fprintf(stderr, "  Struct name: %s\n", directive.struct_name);
      fprintf(stderr, "  Call hook function: %s\n", directive.hook_func_name);
    }
}

static void handle_config_pair(const char *key, const char *value)
{
  if (strcmp(key, "hook") == 0)
    parse_hook_directive(value);
  else
    error("Invalid key '%s' in Field Trace configuration", key);
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
  error("(Assign Trace) Failed to read config file %s: %s", filename, strerror(errno));
  return;

 out_parse_err:
  fclose(file);
  error("(Assign Trace) Parse error in config file %s:%d", filename, config_lineno);
  return;
}

static unsigned int transform_gimple()
{
  const char *function_name;

  /* Since the last time we initialized assign_hook_type, the garbage
     collector may have destroyed it.  Set it to NULL and whoever
     needs it will initialize it on demand. */
  assign_hook_type = NULL;

  function_name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

  if (lookup_attribute(NOINSTRUMENT_ATTR, DECL_ATTRIBUTES(cfun->decl)) != NULL)
    {
      if (verbose)
	fprintf(stderr, "Function %s marked as noinstrument.  Skipping.\n", function_name);
      return 0;
    }

#ifdef DEBUG
  fprintf(stderr, "Function %s\n", function_name);
#endif

  insert_assign_hooks();

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
	fprintf(stderr, "(Assign Trace) Ignoring duplicate registration of attribute %s.\n",
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
  //TODO: Cleanup hook_directive_vec.
}

static struct opt_pass pass_instrument_assigns = {
  .type = GIMPLE_PASS,
  .name = "instr_assigns",
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

static struct register_pass_info pass_info = {
  .pass = &pass_instrument_assigns,
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

  hook_directive_vec = VEC_alloc(hook_directive, heap, 10);

#ifdef DEBUG
  fprintf(stderr, "Initializing Assign Trace plugin.\n");
#endif

#ifdef PAUSE_ON_START
  fprintf(stderr, "cc1 has PID %d.  Attach debugger now.\n", getpid());
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
	    error("(Assign Trace) Must specify filename for -fplugin-arg-%s-config", plugin_name);
	}
      else if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	  fprintf(stderr, "Assign Trace plugin running in verbose mode.\n");
	}
      else
	{
	  warning(0, "(Assign Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
		  argv[i].key);
	}
    }

  read_config_file(config_file_name);

  /* Set up a callback to register our attributes. */
  register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_plugin_attributes, NULL);

  /* Register the main GIMPLE pass, which performs the actual instrumentation. */
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  /* Register our cleanup function. */
  register_callback(plugin_name, PLUGIN_FINISH, cleanup, NULL);

  return 0;
}
