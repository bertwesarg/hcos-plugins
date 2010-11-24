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

/* Malloc Trace adds a logging function call to every memory
   allocation function call that allocates a an object of a given
   type.  A config file tells Malloc Trace which functions are
   allocation functions, which allocation functions to instrument and
   which hooks to call.  Take a look at the test/ directory for an
   example configuration. */

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

/* Print some potentially useful info when verbose is true.  When
   DEBUG is off, use the verbose=true option in the plugin args to
   turn verbose mode on. */
#ifndef DEBUG
static int verbose = false;
#else
static int verbose = true;
#endif

/* Default config file */
static const char *config_file_name = "malloc-trace.config";

static tree mem_hook_type = NULL;

enum function_semantics {
  KMALLOC,
  KMEM,
  KMAP,
  KUNMAP,
};

typedef struct mem_func_desc {
  char *name;
  enum function_semantics semantics;

  char *hook_func_name;
} mem_func_desc;

DEF_VEC_O(mem_func_desc);
DEF_VEC_ALLOC_O(mem_func_desc, heap);
static VEC(mem_func_desc, heap) *mem_func_vec;

/* List of files we are willing to instrument. */
typedef const char *char_ptr;
DEF_VEC_P(char_ptr);
DEF_VEC_ALLOC_P(char_ptr, heap);
static VEC(char_ptr, heap) *file_vec;

/* Set up the mem_hook_type. */
static tree get_mem_hook_type()
{
  if (mem_hook_type == NULL)
    {
      mem_hook_type = build_function_type_list(void_type_node,
					       ptr_type_node,  /* Address */
					       integer_type_node,  /* Size */
					       build_pointer_type(char_type_node),  /* File */
					       integer_type_node,  /* Line number */
					       NULL_TREE);
    }

  return mem_hook_type;
}

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

/* If there is a memory function with the given name, return its
   description.  Otherwise, return NULL. */
struct mem_func_desc *get_mem_func_desc(tree func)
{
  tree func_decl;
  const char *func_name;

  unsigned int i;
  struct mem_func_desc *mem_func;

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
  
  //fprintf(stderr,"%s %s %d\n",func_name,input_filename,input_line); 
	//fprintf(stderr, " %s\n", func_name);
  /* Look for its memory description. */
  for (i = 0 ; VEC_iterate(mem_func_desc, mem_func_vec, i, mem_func) ; i++)
    {
      if (strcmp(mem_func->name, func_name) == 0) {
	//if (verbose)
	 // fprintf(stderr, "Found memory function: %s\n", func_name);
	return mem_func;
      }
    }

  return NULL;
}

/* Create a GIMPLE statement assigning a reference to a temporary
   variable, add that statement at the iterator gsi, then return the
   temporary variable.

   The assignment has a NOP cast. */
static tree assign_to_tmp_with_cast(gimple_stmt_iterator *gsi, tree ref, tree cast_type,
				    const char *tmp_prefix)
{
  tree tmp = create_tmp_var(cast_type, tmp_prefix);

  /* Construct an assign statement: tmp = ref; */
  gimple assign_stmt = gimple_build_assign(tmp, ref);
  gimple_assign_set_rhs_code(assign_stmt, NOP_EXPR);

  /* The left side of the assignment should be an SSA_NAME, but we
     can't create the SSA_NAME until after we build the assign
     statement. */
  gimple_assign_set_lhs(assign_stmt, make_ssa_name(tmp, assign_stmt));

  gsi_insert_before(gsi, assign_stmt, GSI_SAME_STMT);

  return gimple_assign_lhs(assign_stmt);
}

static void instrument_function_call(gimple_stmt_iterator *gsi)
{
  struct mem_func_desc *mem_func;

  gimple stmt;
  gimple hook_call;

  tree func;
  tree hook_decl;
  tree file_name_tree;
  tree line_num_tree;

  tree addr_arg;
  tree size_arg;

  stmt = gsi_stmt(*gsi);
  gcc_assert(gimple_code(stmt) == GIMPLE_CALL);

  /* Ignore functions that are not memory allocation functions. */
  func = gimple_call_fn(stmt);
  if ((mem_func = get_mem_func_desc(func)) == NULL)
    return;

  /* TODO: Make sure we are allocating an object that we care about. */

  /* What is the allocation address argument? */
  if (mem_func->semantics == KMALLOC || mem_func->semantics == KMAP || mem_func->semantics == KMEM)
    {
      /* If this function isn't on the right side of an assignment, we
	 need to _put it_ on the right hand side of an assignment so
	 we can grab its return value. */
      if (gimple_call_lhs(stmt) == NULL)
	{
	  tree new_lhs = create_tmp_var(gimple_call_return_type(stmt), "hcos_mem_result");
	  add_referenced_var(new_lhs);
	  new_lhs = make_ssa_name(new_lhs, stmt);
	  
	  gimple_call_set_lhs(stmt, new_lhs);
	  update_stmt(stmt);
	}
      addr_arg = stabilize_reference(gimple_call_lhs(stmt));
    }
  else if (mem_func->semantics == KUNMAP)
    {
      if (gimple_call_num_args(stmt) < 1)
	{
	  error("(Malloc Trace) Call to an MUNMAP-style function with no address argument.\n");
	  return;
	}

      addr_arg = stabilize_reference(gimple_call_arg(stmt, 0));
    }
  else
    {
      gcc_unreachable();
    }

  /* What is the allocation size argument? */
  if (mem_func->semantics == KMALLOC || mem_func->semantics == KMEM)
    {
      if (gimple_call_num_args(stmt) < 1)
	{
	  //Abhinav:Commented bec plugin is not recognizing kzalloc(SIZE,NOFS) here size is a macro
    //error("(Malloc Trace) Call to a MALLOC- or KMEM-style function with no size argument.\n");
	  return;
	}

      size_arg = stabilize_reference(gimple_call_arg(stmt, 0));
      if (mem_func->semantics == KMALLOC)  /* (int) cast */
	size_arg = assign_to_tmp_with_cast(gsi, size_arg, integer_type_node, "size_arg");
      else if (mem_func->semantics == KMEM)  /* (void *) cast */
	size_arg = assign_to_tmp_with_cast(gsi, size_arg, ptr_type_node, "size_arg");
      else
	gcc_unreachable();
    }
  else
    {
      /* Constant 0 size arg. */
      size_arg = build_int_cst(integer_type_node, 0);
    }

  hook_decl = build_fn_decl(mem_func->hook_func_name, get_mem_hook_type());

  /* File name and line number for this hook. */
  file_name_tree = build_string_ptr(input_filename);
  line_num_tree = build_int_cst(integer_type_node, input_line);
  if(input_filename == NULL)
    fprintf(stderr,"Malloc trace:Filename is null\n ",input_filename);
  hook_call = gimple_build_call(hook_decl, 4,
				addr_arg,
				size_arg,
				file_name_tree,
				line_num_tree);

  /* We are interested in the return value of MALLOC- and MMAP-style
     calls, so the hook must come after the call.  Conversely, we are
     interested in the argument to an MUNMAP-style call, which might
     no longer be valid after the call.  These calls have their hook
     before the call. */
  if (mem_func->semantics == KMALLOC || mem_func->semantics == KMAP || mem_func->semantics == KMEM) {
    if(mem_func->semantics == KMEM )
      fprintf(stderr,"alloc %s %d\n",input_filename,input_line); 
    gsi_insert_after(gsi, hook_call, GSI_SAME_STMT);
  }
  else if (mem_func->semantics == KUNMAP ) {
   
//    fprintf(stderr,"dealloc %s %d\n",input_filename,input_line); 
    gsi_insert_before(gsi, hook_call, GSI_SAME_STMT);
  }
  else
    gcc_unreachable();
}

/* This function does the actual instrumentation work for the current
   function. */
static void insert_alloc_hooks()
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

   func_name-[kmalloc|kmap|kunmap]-hook_name

   This function parses the description and adds it to
   mem_desc_vec. */
static void parse_mem_func_desc(const char *desc_string)
{
  char *fields[2];  /* There are three fields, separated by - characters. */
  const char *str_start;
  const char *str_end;
  int str_size;
  int i;

  struct mem_func_desc desc;

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
	  error("(Memory Trace) Invalid lock description");
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

  desc.name = xstrdup(fields[0]);
  /* Construct the description and push it on the list of
     mem_func_desc structs. */
  if (strcmp(fields[1], "kmalloc") == 0)
    desc.semantics = KMALLOC;
  else if (strcmp(fields[1], "kmem") == 0)
    desc.semantics = KMEM;
  else if (strcmp(fields[1], "kmap") == 0)
    desc.semantics = KMAP;
  else if (strcmp(fields[1], "kunmap") == 0)
    desc.semantics = KUNMAP;
  else
    {
      error("(Malloc Trace) Invalid allocation semantics: %s.  Specify kmalloc, kmap or kunmap.", fields[1]);
      return;
    }

  /* There should not be more than two dashes. */
  if (strchr(str_start, '-') != NULL)
    {
      error("(Malloc Trace) Invalid lock description");
      return;
    }

  desc.hook_func_name = xstrdup(fields[2]);
  VEC_safe_push(mem_func_desc, heap, mem_func_vec, &desc);

  if (verbose)
    {
      fprintf(stderr, "Memory Function Trace recognized memory function function description:\n");
      fprintf(stderr, "  Function name: %s\n", fields[0]);
      fprintf(stderr, "  Allocation semantics: %s\n", fields[1]);
      fprintf(stderr, "  Hook function: %s\n", fields[2]);
    }
}

static void handle_config_pair(const char *key, const char *value)
{
  if (strcmp(key, "trace") == 0)
    {
      parse_mem_func_desc(value);
    }
  else if (strcmp(key, "file") == 0)
    {
      VEC_safe_push(char_ptr, heap, file_vec, xstrdup(value));

      if (verbose)
	fprintf(stderr, "(Malloc Trace) Tracing locks in file: %s\n", value);
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
  error("(Field Trace) Failed to read config file %s: %s", filename, strerror(errno));
  return;

 out_parse_err:
  fclose(file);
  error("(Field Trace) Parse error in config file %s:%d", filename, config_lineno);
  return;
}

/* Does the given path match a reference path?  A path matches a
   reference if its trailing path components match all the components
   in the reference. */
bool is_matching_path(const char *path, const char *reference)
{
  while (path != NULL)
    {
      while (*path == '/')
	path++;

      if (strcmp(path, reference) == 0)
	return true;

      path = strchr(path, '/');
    };

  return false;
}

static bool is_instrumented_file()
{
  const char *file_name = DECL_SOURCE_FILE(current_function_decl);

  if (VEC_empty(char_ptr, file_vec))
    {
      /* If the user doesn't specify any files, instrument all files. */
      return true;
    }
  else
    {
      int i;
      const char *ref_file_name;
      for (i = 0 ; VEC_iterate(char_ptr, file_vec, i, ref_file_name) ; i++)
	  if (is_matching_path(file_name, ref_file_name))
	    return true;

      /* No matching reference file names.  Do not instrument anything
	 in this file. */
      return false;
    }
  
}

static unsigned int transform_gimple()
{
  const char *function_name;

  /* Since the last time we initialized mem_hook_type, the garbage
     collector may have destroyed it.  Set it to NULL and whoever
     needs it will initialize it on demand. */
  mem_hook_type = NULL;

  function_name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

  if (is_instrumented_file())
    {
      if (verbose)
	fprintf(stderr, "(Malloc Trace) Instrument function: %s\n", function_name);
    }
  else
    {
      return 0;  /* Do not instrument this function. */
    }
      

  if (lookup_attribute(NOINSTRUMENT_ATTR, DECL_ATTRIBUTES(cfun->decl)) != NULL)
    {
      if (verbose)
	fprintf(stderr, "Function %s marked as noinstrument.  Skipping.\n", function_name);
      return 0;
    }

  insert_alloc_hooks();

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

/* This is the last plug-in function called before GCC exits.  Cleanup
   all the memory we allocated. */
static void cleanup(void *event_date, void *data)
{
}

static struct opt_pass pass_instrument_lock_calls = {
  .type = GIMPLE_PASS,
  .name = "instr_allocs",
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

  mem_func_vec = VEC_alloc(mem_func_desc, heap, 10);
  file_vec = VEC_alloc(char_ptr, heap, 10);

#ifdef DEBUG
  fprintf(stderr, "Initializing Lock Trace plugin.\n");
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
	    error("(Malloc Trace) Must specify filename for -fplugin-arg-%s-config", plugin_name);
	}
      else if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	  fprintf(stderr, "Malloc Trace plugin running in verbose mode.\n");
	}
      else
	{
	  warning(0, "(Malloc Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
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
