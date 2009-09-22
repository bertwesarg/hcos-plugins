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

/* Lock Trace adds a logging function call to every call to a locking
   function for specific locks.  A config file tells Lock Trace which
   functions are locking functions, which locks to instrument, and
   which logging functions to call for each of those locks.  Take a
   look at the test/ directory for an example configuration. */

/* For fgets_unlocked */
#define _GNU_SOURCE

#include <inttypes.h>

/* Whether we want them or not (we don't), Autoconf _insists_ on
   defining these.  Since GCC's config.h (which we must include) also
   defines them, we have to undef them here. */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

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
const char *config_file_name = "lock-trace.config";

/* A type node for lock hook functions. */
tree lock_hook_type = NULL;

enum locking_semantics {
  LS_NOT_LOCK,
  LS_ACQUIRE,
  LS_TRY,
  LS_RELEASE
};

/* We store a list of locking functions.  Each function can be a lock
   (LS_ACQUIRE), a try lock (LS_TRY), or an unlock (LS_RELEASE).  Each
   lock function has a hook that GCC is to insert before (for
   LS_RELEASE functions) or after (for LS_ACQUIRE and LS_TRY
   functions) instances of this function found in the source. */
typedef struct lock_func_desc {
  const char *name;
  enum locking_semantics semantics;

  const char *hook_func_name;
} lock_func_desc;

DEF_VEC_O(lock_func_desc);
DEF_VEC_ALLOC_O(lock_func_desc, heap);
static VEC(lock_func_desc, heap) *lock_func_vec;

/* We only want to instrument locking functions when the operate on
   locks belonging to certain structs.  This list is the list of lock
   owners whose lacks we wish to track. */
typedef const char *char_ptr;
DEF_VEC_P(char_ptr);
DEF_VEC_ALLOC_P(char_ptr, heap);
static VEC(char_ptr, heap) *lock_owner_vec;
static VEC(char_ptr, heap) *global_lock_vec;

/* Set up the lock_hook_type. */
static tree get_lock_hook_type()
{
  if (lock_hook_type == NULL)
    {
      lock_hook_type = build_function_type_list(void_type_node,
						build_pointer_type(char_type_node),
						build_pointer_type(char_type_node),
						integer_type_node,
						build_pointer_type(char_type_node),
						build_pointer_type(char_type_node),
						build_pointer_type(char_type_node), /* File name */
						integer_type_node,                  /* Line num */
						NULL_TREE);
    }

  return lock_hook_type;
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
                      min_value,
                      size_in_align);

  ret = build1(ADDR_EXPR,
               build_pointer_type(TREE_TYPE(string_ref)),
               string_ref);

  return ret;
}

/* Given a component ref, get the node for the left side of the ref.
   For example, in the case of a->b, get the node for a.  In almost
   all cases, that just means the left operand.  However, there is a
   trick case: if b is a member of a transparent union, the left
   operand of the expression is actually the hidden union reference.
   In this case, get_record keeps() traversing to the left to find the
   real record node. */
static tree get_record(tree node)
{
  tree record;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  record = TREE_OPERAND(node, 0);

  while (TYPE_NAME(TREE_TYPE(record)) == NULL &&
	 TREE_CODE(TREE_TYPE(record)) == UNION_TYPE &&
	 TREE_CODE(record) == COMPONENT_REF)
    {
      /* The record node is a field access to a union with no name: a
	 transparent union access.  Traverse down the left until we
	 find an honest-to-goodness named struct or union. */
      record = TREE_OPERAND(record, 0);
    }

  return record;
}

/* Given a GIMPLE COMPONENT_REF, find the name of the struct being
   accessed.
   The result is a string pointer obtained with ptr_from_string(). */
static tree get_record_name_ptr(tree node)
{
  tree record;
  tree field;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  record = get_record(node);
  return build_string_ptr(IDENTIFIER_POINTER(TYPE_NAME(TREE_TYPE(record))));
}

/* Given a GIMPLE COMPONENT_REF, find the name of the struct field
   being accessed.
   The result is a string pointer obtained with build_string_ptr(). */
static tree get_field_name_ptr(tree node)
{
  tree field;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  field = TREE_OPERAND(node, 1);
  return build_string_ptr(IDENTIFIER_POINTER(DECL_NAME(field)));
}

/* Given a GIMPLE decl node, get its name.
   The result is a const char pointer. */
static const char *get_node_name(tree node)
{
  if (TYPE_NAME(TREE_TYPE(node)) == NULL)
    {
      fprintf(stderr, "Anonymous type.\n");
      return "__anon";
    }

  if (TREE_CODE(TYPE_NAME(TREE_TYPE(node))) != IDENTIFIER_NODE)
    {
      fprintf(stderr, "Unknown record name.\n");
      return "__unknown_type";
    }

  return IDENTIFIER_POINTER(TYPE_NAME(TREE_TYPE(node)));
}

/* If there is a lock/unlock function with the given name, return its
   description.  Otherwise, return NULL. */
struct lock_func_desc *get_lock_func_desc(tree func)
{
  tree func_decl;
  const char *func_name;

  unsigned int i;
  struct lock_func_desc *lock_func;

  if (TREE_CODE(func) != ADDR_EXPR)
    {
      /* This is a call to a function pointer.  Don't worry about it. */
#ifdef DEBUG
      fprintf(stderr, "CALL_EXPR with non-ADDR_EXPR function.\n");
#endif
      return NULL;
    }

  /* Get the function's name. */
  func_decl = TREE_OPERAND(func, 0);
  func_name = IDENTIFIER_POINTER(DECL_NAME(func_decl));

  /* Look for its lock description. */
  for (i = 0 ; VEC_iterate(lock_func_desc, lock_func_vec, i, lock_func) ; i++)
    {
      if (strcmp(lock_func->name, func_name) == 0) {
	if (verbose)
	  fprintf(stderr, "Found lock function: %s\n", func_name);
	return lock_func;
      }
    }

  /* This function does not acquire or release a lock. */
  return NULL;
}

/* Does this lock belong to a struct object we are interested in? */
static int is_matching_lock_owner(tree owner)
{
  int i;
  const char *owner_name;
  const char *type_name_iter;

  owner_name = get_node_name(owner);

  for (i = 0 ; VEC_iterate(char_ptr, lock_owner_vec, i, type_name_iter) ; i++)
    {
      if (strcmp(owner_name, type_name_iter) == 0)
	return true;
    }

  /* This lock owner is not in the list of lock owners who should be traced. */
  return false;
}

/* Is this global lock one that we are interested in? */
static int is_matching_lock_name(const char *name)
{
  int i;
  const char *lock_name_iter;

  for (i = 0 ; VEC_iterate(char_ptr, global_lock_vec, i, lock_name_iter) ; i++)
    {
      if (strcmp(name, lock_name_iter) == 0)
	return true;
    }

  /* This global lock is not in the list of global locks who should be traced. */
  return false;
}

/* Given a function call, check if it should be instrumented (i.e., if
   it's a relevant locking function) and if so add the appropriate
   hook. */
static void instrument_function_call(gimple_stmt_iterator *gsi)
{
  struct lock_func_desc *lock_func;

  gimple stmt;
  gimple hook_call;

  tree func;
  tree lock;
  tree hook_decl;
  tree lock_owner;
  tree owner_name;
  tree lock_name;
  tree lock_success;
  tree owner_addr;
  tree lock_addr;
  tree func_name_tree;
  tree line_num_tree;

  stmt = gsi_stmt(*gsi);
  gcc_assert(gimple_code(stmt) == GIMPLE_CALL);

  /* Ignore functions that are not lock acquire/release functions. */
  func = gimple_call_fn(stmt);
  if ((lock_func = get_lock_func_desc(func)) == NULL)
    return;

  /* We are looking at a lock acquire or release function.  Figure out
     the lock and its owner. */
  if (gimple_call_num_args(stmt) < 1)
    error("(Lock Trace) Call to locking function with no arguments");
  lock = gimple_call_arg(stmt, 0);

  /* Sometimes an argument gets assigned to an SSA temporary variable
     before it gets passed as an argument.  We don't want that
     variable, we want the value assigned to it.  (Look for a better
     description in the ssa-test test case.)*/
  while (TREE_CODE(lock) == SSA_NAME)
    {
      /* the SSA_NAME_DEF_STMT for lock should be a GIMPLE_MODIFY_STMT
	 (because it assigns a value to lock).  However, when the lock
	 is assigned directly fom a function argument, the
	 SSA_NAME_DEF_STMT is just a NOP statement.  In that case, we
	 can't determine an owner for the lock. */
      if (gimple_code(SSA_NAME_DEF_STMT(lock)) == GIMPLE_NOP)
	return;

      gcc_assert(gimple_code(SSA_NAME_DEF_STMT(lock)) == GIMPLE_ASSIGN);
      lock = gimple_assign_rhs1(SSA_NAME_DEF_STMT(lock));
    }

  if (TREE_CODE(lock) == ADDR_EXPR)  /* Remove the address-of (&) operation. */
    lock = TREE_OPERAND(lock, 0);

  /* We can only determine a lock's owner if we have it in the form
     record.lock or record->lock. */
  if (TREE_CODE(lock) == COMPONENT_REF)
    {
      lock_owner = get_record(lock);

      /* This is a lock acquire/release, but do we care about the
	 lock's owner? */
      if (!is_matching_lock_owner(lock_owner))
	return;

      owner_name = get_record_name_ptr(lock);
      lock_name = get_field_name_ptr(lock);
    }
  else if (TREE_CODE(lock) == VAR_DECL)
    {
      /* This is a global lock, but is it a global lock we care
	 about? */
      const char *lock_name_str = IDENTIFIER_POINTER(DECL_NAME(lock));
      if (!is_matching_lock_name(lock_name_str))
	return;

      lock_owner = NULL;
      owner_name = build_int_cst(build_pointer_type(char_type_node), 0); /* NULL pointer */
      lock_name = build_string_ptr(lock_name_str);
    }
  else
    {
      if (verbose)
	fprintf(stderr, "(Lock Watch) Non-global lock without owner at line %d.\n", input_line);
      return;
    }

  /* If this is an LS_TRY lock function, we need a reference to the
     function's return value.*/
  if (lock_func->semantics == LS_TRY)
    {
      /* If this function isn't on the right side of an assignment,
	 somebody screwed up bad.  We have no way to pass the result
	 of the try to the hook function. */
      if (gimple_call_lhs(stmt) == NULL)
	{
	  error("(Lock Trace) Result of try lock function is not available.  Did you call a try "
		"lock function without storing its result?\n");
	  return;
	}

      lock_success = stabilize_reference(gimple_call_lhs(stmt));
    }
  else
    {
      /* LS_ACQUIRE and LS_RELEASE locks always succeed. */
      lock_success = build_int_cst(integer_type_node, 1 /* 1 for true */);
    }

  /* Add a hook. */
  hook_decl = build_fn_decl(lock_func->hook_func_name, get_lock_hook_type());
  if (lock_owner != NULL)
    owner_addr = build1(ADDR_EXPR, build_pointer_type(char_type_node), stabilize_reference(lock_owner));
  else
    owner_addr = build_int_cst(build_pointer_type(char_type_node), 0); /* NULL pointer */
  lock_addr = build1(ADDR_EXPR, build_pointer_type(char_type_node), stabilize_reference(lock));
  func_name_tree = build_string_ptr(gimple_filename(stmt));
  line_num_tree = build_int_cst(integer_type_node, gimple_lineno(stmt));

  hook_call = gimple_build_call(hook_decl, 7,
				owner_addr,
				lock_addr,
				lock_success,
				owner_name,
				lock_name,
				func_name_tree,
				line_num_tree);

  /* We want to call the hook function with the lock held, so add it
     just after acquiring or just before releasing. */
  if (lock_func->semantics == LS_ACQUIRE || lock_func->semantics == LS_TRY)
    gsi_insert_after(gsi, hook_call, GSI_SAME_STMT);
  else if (lock_func->semantics == LS_RELEASE)
    gsi_insert_before(gsi, hook_call, GSI_SAME_STMT);
  else
    gcc_assert(0);  /* This should not happen. */
}

/* This function does the actual instrumentation work for the current
   function. */
static void insert_locking_hooks()
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

	if (gimple_code(my_statement) == GIMPLE_CALL)
	  instrument_function_call(&gsi);
      }
  }
}

/* Lock function descriptions are specified in the plugin arguments
   (With "trace" keys).  Each description should have the form:

   func_name-[acquire|try|release]-hook_name

   This function parses the description and adds it to
   lock_desc_vec. */
static void parse_lock_func_desc(const char *desc_string)
{
  char *fields[3];  /* There are three fields, separated by - characters. */
  const char *str_start;
  const char *str_end;
  int str_size;
  int i;

  struct lock_func_desc desc;

  /* Perl, I know I said bad things about you in the past, but now
     that you aren't here, I really miss the way you used to parse
     regexes for me. */

  /* The first two fields in the directive are terminated with a -.
     Use strchr to parse them. */
  str_start = desc_string;
  for (i = 0 ; i < 2 ; i++)
    {
      str_end = strchr(str_start, '-');
      if (str_end == NULL)
	{
	  error("(Lock Trace) Invalid lock description");
	  return;
	}

      str_size = (int)(str_end - str_start);
      fields[i] = alloca(str_size + 1);
      memcpy(fields[i], str_start, str_size);
      fields[i][str_size] = '\0';

      str_start = str_end + 1;
    }

  /* The last field ends with the end of the string. */
  str_size = strlen(str_start);
  fields[2] = alloca(str_size + 1);
  memcpy(fields[2], str_start, str_size);
  fields[2][str_size] = '\0';

  /* There should not be more than two dashes. */
  if (strchr(str_start, '-') != NULL)
    {
      error("(Lock Trace) Invalid lock description");
      return;
    }

  /* Construct the description and push it on the list of
     lock_func_desc structs. */
  desc.name = xstrdup(fields[0]);
  if (strcmp(fields[1], "acquire") == 0)
    desc.semantics = LS_ACQUIRE;
  else if (strcmp(fields[1], "try") == 0)
    desc.semantics = LS_TRY;
  else if (strcmp(fields[1], "release") == 0)
    desc.semantics = LS_RELEASE;
  else
    {
      error("(Lock Trace) Invalid lock semantics: %s.  Specify acquire, try, or release.", fields[1]);
      return;
    }
  desc.hook_func_name = xstrdup(fields[2]);
  VEC_safe_push(lock_func_desc, heap, lock_func_vec, &desc);

  if (verbose)
    {
      fprintf(stderr, "Lock Trace recognized lock function description:\n");
      fprintf(stderr, "  Function name: %s\n", fields[0]);
      fprintf(stderr, "  Locking semantics: %s\n", fields[1]);
      fprintf(stderr, "  Hook function: %s\n", fields[2]);
    }
}

static void handle_config_pair(const char *key, const char *value)
{
  if (strcmp(key, "trace") == 0)
    {
      parse_lock_func_desc(value);
    }
  else if (strcmp(key, "lock_owner") == 0)
    {
      VEC_safe_push(char_ptr, heap, lock_owner_vec, xstrdup(value));
      if (verbose)
	fprintf(stderr, "(Lock Trace) Tracing locks belonging to: %s\n", value);
    }
  else if (strcmp(key, "global_lock") == 0)
    {
      VEC_safe_push(char_ptr, heap, global_lock_vec, xstrdup(value));
      if (verbose)
	fprintf(stderr, "(Lock Trace) Tracing global lock: %s\n", value);
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
  fclose(file);
  error("(Lock Trace) Failed to read config file %s: %s", filename, strerror(errno));
  return;

 out_parse_err:
  fclose(file);
  error("(Lock Trace) Parse error in config file %s:%d", filename, config_lineno);
  return;
}

static unsigned int transform_gimple()
{
  static bool init_completed = false;

  const char *function_name;

  /* Do initialization the first time transform_gimple gets called. */
  if (!init_completed)
    {
      read_config_file(config_file_name);
      init_completed = true;
    }

  /* Since the last time we initialized lock_hook_type, the garbage
     collector may have destroyed it.  Set it to NULL and whoever
     needs it will initialize it on demand. */
  lock_hook_type = NULL;

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

  insert_locking_hooks();

  return 0;
}

/* Some attributes (mainly noinstrument) are shared by several
   plug-ins.  If all the plug-ins attempt to register the same
   attribute, GCC will get angry (and fail an assert check).  This
   functions registers an attribute only after checking to make sure
   it hasn't been registered by another plug-in. */
void register_attribute_once(const struct attribute_spec *attr)
{
  tree name;

  if (lookup_attribute_spec(get_identifier(attr->name)) == NULL)
    {
      /* Safe to register this attribute. */
      register_attribute(attr);
    }
  else
    {
      /* This attribute was already registered. */
      if (verbose)
	fprintf(stderr, "(Lock Trace) Ignoring duplicate registration of attribute %s.\n",
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

static void destroy_lock_func_desc(struct lock_func_desc *lock_func)
{
  free(lock_func->name);
  lock_func->name = NULL;

  free(lock_func->hook_func_name);
  lock_func->hook_func_name = NULL;
}

/* This is the last plug-in function called before GCC exits.  Cleanup
   all the memory we allocated. */
static void cleanup(void *event_date, void *data)
{
  int i;
  struct lock_func_desc *lock_func_iter;
  const char *name_iter;

  /* Clear out lock_func_vec list. */
  for (i = 0 ; VEC_iterate(lock_func_desc, lock_func_vec, i, lock_func_iter) ; i++)
    destroy_lock_func_desc(lock_func_iter);
  VEC_free(lock_func_desc, heap, lock_func_vec);

  /* Clear out the lock_owner_vec list. */
  for (i = 0 ; VEC_iterate(char_ptr, lock_owner_vec, i, name_iter) ; i++)
    free(name_iter);
  VEC_free(char_ptr, heap, lock_owner_vec);

  /* Clear out the global_lock_vec list. */
  for (i = 0 ; VEC_iterate(char_ptr, global_lock_vec, i, name_iter) ; i++)
    free(name_iter);
  VEC_free(char_ptr, heap, global_lock_vec);
}

static struct opt_pass pass_instrument_lock_calls = {
  .type = GIMPLE_PASS,
  .name = "instr_locks",
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
  .pass = &pass_instrument_lock_calls,
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

  lock_func_vec = VEC_alloc(lock_func_desc, heap, 10);
  lock_owner_vec = VEC_alloc(char_ptr, heap, 10);
  global_lock_vec = VEC_alloc(char_ptr, heap, 10);

#ifdef DEBUG
  fprintf(stderr, "Initializing Lock Trace plugin.\n");
#endif

#ifdef PAUSE_ON_START
  fprintf(stderr, "cc109 has PID %d.  Attach debugger now.\n", getpid());
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
	    error("(Lock Trace) Must specify filename for -fplugin-arg-%s-config", plugin_name);
	}
      else if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	  fprintf(stderr, "Lock Trace plugin running in verbose mode.\n");
	}
      else
	{
	  warning(0, "(Lock Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
		  argv[i].key);
	}
    }

  /* Set up a callback to register our attributes. */
  register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_plugin_attributes, NULL);

  /* Register the main GIMPLE pass, which performs the actual instrumentation. */
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  /* Register our cleanup function. */
  register_callback(plugin_name, PLUGIN_FINISH, cleanup, NULL);

  return 0;
}
