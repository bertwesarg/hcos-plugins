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

/* Field Trace adds a logging function to every field access (e.g.,
   foo.bar or foo->bar) to specific structs.  A config file tells
   Field Trace which structs to instrument.  Take a look at the test/
   directory for an example configuration. */

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
#include "diagnostic.h"
#include "timevar.h"
#include "tree-iterator.h"
#include "tree-flow.h"
#include "tree-pass.h"
#include "plugin.h"
#include "gimple.h"
#include "c-common.h"

// TODO: Include output.h
extern void assemble_variable (tree, int, int, int);

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
static const char *config_file_name = "field-trace.config";

/* Field Trace takes field directives as instructions for its
   instrumentations.

   For each directive, Field Trace adds a call to its hook function
   for every field reference that matches the struct_name and
   field_name parameters.  A NULL struct_name matches any struct, and
   a NULL field_name matches any field. */
typedef struct field_directive
{
  char *struct_name;
  char *field_name;

  char *hook_func_name;
} field_directive;

DEF_VEC_O(field_directive);
DEF_VEC_ALLOC_O(field_directive, heap);
static VEC(field_directive, heap) *field_directive_vec;

tree field_hook_type = NULL;

static tree get_field_hook_type()
{
  if (field_hook_type == NULL)
    {
      /* Construct the C type for field-access hook functions.
       * Functions with this type have prototype:
       * void __report_field_access(void *record_ptr, const char *record, const char *field,
       *                            int field_index, int is_write, int is_marked,
       *                            unsigned long bitmask, int *scratch, const char *filename,
       *                            int lineno);
       */
      field_hook_type = build_function_type_list(void_type_node,
						 build_pointer_type(char_type_node),
						 build_pointer_type(char_type_node),
						 build_pointer_type(char_type_node),
						 integer_type_node,
						 integer_type_node,
						 integer_type_node,
						 long_unsigned_type_node,
						 build_pointer_type(integer_type_node),
						 build_pointer_type(char_type_node), /*File name*/
						 integer_type_node, /* Line number */
						 NULL_TREE);
    }

  return field_hook_type;
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
    type_name = TYPE_NAME(DECL_ORIGINAL_TYPE(type_name));
  gcc_assert(type_name == NULL || TREE_CODE(type_name) == IDENTIFIER_NODE);
  return type_name;
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

  while (TREE_CODE(record) == COMPONENT_REF &&
	 TREE_CODE(TREE_TYPE(record)) == UNION_TYPE &&
	 DECL_NAME(TREE_OPERAND(record, 1)) == NULL)
    {
      /* The record node is a field access to a union with no name: a
	 transparent union access.  Traverse down the left until we
	 find an honest-to-goodness named struct or union. */
      record = TREE_OPERAND(record, 0);
    }

  return record;
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

/* Given a GIMPLE COMPONENT_REF, find the name of the struct being
   accessed.
   The result is a const char pointer. */
static const char *get_record_name(tree node)
{
  tree record;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  record = get_record(node);
  return get_node_name(record);
}

/* Given a GIMPLE COMPONENT_REF, find the name of the struct field
   being accessed.
   The result is a const char pointer. */
static const char *get_field_name(tree node)
{
  tree field;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  field = TREE_OPERAND(node, 1);
  return IDENTIFIER_POINTER(DECL_NAME(field));
}

/* Given a GIMPLE COMPONENT_REF, find the name of the struct being
   accessed.
   The result is a string pointer obtained with build_string_ptr(). */
static tree get_record_name_ptr(tree node)
{
  return build_string_ptr(get_record_name(node));
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

/* Return the number of fields in a struct or union type. */
static int num_fields(tree node)
{
  int num = 0;
  tree field = TYPE_FIELDS(node);

  /* Inefficient, but it should be acceptable. */
  while (field != NULL)
    {
      if (DECL_NAME(field) != NULL || TREE_CODE(TREE_TYPE(field)) != UNION_TYPE)
	num++;  /* Count this as a regular field. */
      else  /* This field is a transparent union.  Count its fields as fields of this type. */
	num += num_fields(TREE_TYPE(field));
      field = TREE_CHAIN(field);
    }

  return num;
}

/* This recursive function does most of the dirty work for
   get_field_index. */
static int get_field_index_iterate(tree record_type, const char *field_name)
{
  /* Iterate through every field declaration in the struct until we
     find one that matches. */
  int field_index = 0;
  tree field = TYPE_FIELDS(record_type);
  while(field != NULL)
    {
      if (DECL_NAME(field) != NULL)
	{
	  if (strcmp(field_name, IDENTIFIER_POINTER(DECL_NAME(field))) == 0)
	    {
#ifdef DEBUG
	      fprintf(stderr, "Field %s has index %d\n", field_name, field_index);
#endif
	      return field_index;
	    }

	  field_index++;
	}
      else if (TREE_CODE(TREE_TYPE(field)) == UNION_TYPE)
	{
	  /* This field is a transparent union.  This union has no
	     name, but its fields are accessible as if they are the
	     fields of its parent struct.  Check inside the union to
	     see if it contains the field we're looking for.

	     It's possible to nest transparent unions, which is why
	     this function has to be recursive for completeness. */
	  int result = get_field_index_iterate(TREE_TYPE(field), field_name);
	  if (result >= 0)
	    return field_index + result;

	  field_index += num_fields(TREE_TYPE(field));
	}
      else
	{
	  /* It's not clear what this is, so we ignore it.  This case
	     should not occur. */
	  if (verbose)
	    fprintf(stderr, "Unrecognized field in struct.\n");
	  field_index++;
	}

      field = TREE_CHAIN(field);
    }

  /* Return -1 to indicate failure. */
  return -1;  
}

/* Given a GIMPLE_COMPONENT_REF, figure out the index of the
   referenced field.  For example, the COMPONENT_REF foo.bar will
   return 3 if bar is the 3rd field in foo's struct type (all indexing
   from 0). */
static int get_field_index(tree node)
{
  tree record;
  tree field;
  int result;

  const char *field_name;

  gcc_assert(TREE_CODE(node) == COMPONENT_REF);

  record = get_record(node);
  field = TREE_OPERAND(node, 1);
  field_name = IDENTIFIER_POINTER(DECL_NAME(field));

  result = get_field_index_iterate(TREE_TYPE(record), field_name);

  if (result < 0)
    fprintf(stderr, "Failed to find index for field %s\n", field_name);

  return result;
}

static tree build_static(tree type, const char* name, tree initial)
{
  tree ret = NULL;

  ret = build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier(name), type);

  TREE_STATIC(ret) = 1;
  DECL_INITIAL(ret) = initial;
  assemble_variable(ret, 0, 0, 0); // tree decl, int top_level, int at_end, int dont_output_data
  add_referenced_var(ret);

  return ret;
}

/* Create a GIMPLE statement assigning a reference to a temporary
   variable, add that statement at the iterator gsi, then return the
   temporary variable. */
static tree assign_ref_to_tmp(gimple_stmt_iterator *gsi, tree ref, const char *tmp_prefix)
{
  tree tmp = create_tmp_var(TREE_TYPE(ref), tmp_prefix);

  /* Construct an assign statement: tmp = ref; */
  gimple assign_stmt = gimple_build_assign(tmp, ref);

  /* The left side of the assignment should be an SSA_NAME, but we
     can't create the SSA_NAME until after we build the assign
     statement. */
  gimple_assign_set_lhs(assign_stmt, make_ssa_name(tmp, assign_stmt));

  gsi_insert_before(gsi, assign_stmt, GSI_SAME_STMT);

  return gimple_assign_lhs(assign_stmt);
}

static tree find_bitop(tree *node, int *walk_subtrees, void *arg)
{
  if (TREE_CODE(*node) == BIT_IOR_EXPR || TREE_CODE(*node) == BIT_AND_EXPR) {
    return *node;
  }
  else {
    return NULL;
  }
}

/* Use bitmask_mapping structs in an htab to annotate any tree node
   with a bitmask tree. */
struct bitmask_mapping {
  tree key;
  tree bitmask;
};

static hashval_t hash_bitmask_mapping(const void *key)
{
  return htab_hash_pointer(key);
}

static int eq_bitmask_mapping(const void *mapping_ptr, const void *key)
{
  const struct bitmask_mapping *mapping = (const struct bitmask_mapping *)mapping_ptr;
  return (mapping->key == key);
}

/* Given a variable, trace backwards through the chain of assignments
   that lead to it.  We want to know if the origin is a COMPONENT_REF.
   If it is, return that COMPONENT_REF. */
static tree trace_source(gimple_stmt_iterator back_it, tree start)
{
  if (start == NULL)
    return NULL;

  tree source = start;

  while (1) {
    if (TREE_CODE(source) == COMPONENT_REF) {
      if (verbose)
	fprintf(stderr, "Found source at line: %d\n", gimple_lineno(gsi_stmt(back_it)));
      return source;  /* We found it. */
    }

    /* Advance the iterator backwards if possible. */
    if (back_it.ptr->prev != NULL)
      gsi_prev(&back_it);
    else
      break;  /* Nevermind: we are done. */

    gimple back_it_stmt = gsi_stmt(back_it);
    if (gimple_code(back_it_stmt) == GIMPLE_ASSIGN &&
	gimple_op(back_it_stmt, 0) == source) {
      /* We've successfully traced this piece of data one step
	 back. */
      source = gimple_op(back_it_stmt, 1);

      if (TREE_CODE(source) == NOP_EXPR) {
	source = TREE_OPERAND(source, 0);
      }
    }
  }

  return NULL;  /* We couldn't trace back to a COMPONENT_REF. */
}

static tree trace_dest(gimple_stmt_iterator forward_it, tree start)
{
  if (start == NULL)
    return NULL;

  tree dest = start;

  while (1) {
    if (TREE_CODE(dest) == COMPONENT_REF)
      return dest;  /* We've successfully traced forwards to a COMPONENT_REF. */

    gsi_next(&forward_it);

    if (gsi_end_p(forward_it))
      return NULL;

    gimple stmt = gsi_stmt(forward_it);
    if (gimple_code(stmt) == GIMPLE_ASSIGN &&
	gimple_op(stmt, 1) == dest) {
      dest = gimple_op(stmt, 0);
    }
  }

  return NULL;  /* We couldn't trace forward to a COMPONENT_REF. */
}

/* varcmp() considers '\0' and '.' to be string terminators. */
static bool is_terminator(char c)
{
  return (c == '\0' || c == '.');
}

/* Compare two strings that are variables names.  This is special
   because variable names have different versions signified with a
   dot.  We ignore the dot and everything after it with this
   comparison.  For example, foo.1 is the same as foo.2. */
static int varcmp(const char *var1, const char *var2)
{
  while (1) {
    /* Are we at the end of either string? */
    if (is_terminator(*var1) && is_terminator(*var2))
      return 0;
    else if (is_terminator(*var1))
      return -1;
    else if (is_terminator(*var2))
      return 1;

    if (*var1 < *var2)
      return -1;
    else if (*var1 > *var2)
      return 1;

    var1++;
    var2++;
  }
}

static bool source_and_dest_match(tree source, tree dest)
{
  if (TREE_CODE(source) == COMPONENT_REF && TREE_CODE(dest) == COMPONENT_REF) {
    if (TREE_OPERAND(source, 1) != TREE_OPERAND(dest, 1)) {
      return false;
    }
    else
      return source_and_dest_match(TREE_OPERAND(source, 0),
				   TREE_OPERAND(dest, 0));
  }
  else if (TREE_CODE(source) == INDIRECT_REF && TREE_CODE(dest) == INDIRECT_REF) {
      return source_and_dest_match(TREE_OPERAND(source, 0),
				   TREE_OPERAND(dest, 0));
  }
  else if (TREE_CODE(source) == SSA_NAME && TREE_CODE(dest) == SSA_NAME) {
    return (source == dest);
  }
  else if (TREE_CODE(source) == VAR_DECL && TREE_CODE(dest) == VAR_DECL) {
    if (DECL_NAME(source) == NULL || DECL_NAME(dest) == NULL)
      return false;

    /* This will typically occur at -O0 (i.e., with SSA turned off).
       There's no obvious way to compare to VAR_DECLs other than by
       name. */
    return (varcmp(IDENTIFIER_POINTER(DECL_NAME(source)),
		   IDENTIFIER_POINTER(DECL_NAME(dest))) == 0);
  }
  else {
    return false;
  }
}

/* Create a mapping from a COMPONENT_REF to a bitmask. */
static void associate_bitmask(htab_t comp_ref_bitmasks, tree comp_ref, tree bitmask)
{
  struct bitmask_mapping *mapping = ggc_alloc(sizeof(struct bitmask_mapping));
  mapping->key = comp_ref;
  mapping->bitmask = bitmask;

  struct bitmask_mapping **mapping_slot =
    (struct bitmask_mapping **)htab_find_slot(comp_ref_bitmasks, mapping->key, INSERT);

  if (*mapping_slot == NULL)
    {
      *mapping_slot = mapping;
    }
  else
    {
      /* We shouldn't try to associate multiple bitmasks with the same
	 COMPONENT_REF.  Just forget about this mapping. */
      if ((*mapping_slot)->bitmask != bitmask)
	{
	  if (verbose)
	    fprintf(stderr, "Duplicate mapping.\n");
	  (*mapping_slot)->bitmask = NULL;
      }
    }
}

static void get_bitmasks(basic_block bb, htab_t comp_ref_bitmasks)
{
  gimple_stmt_iterator gsi;

  for (gsi = gsi_start_bb(bb) ; !gsi_end_p(gsi) ; gsi_next(&gsi))
    {
      gimple stmt;
      tree bitop;
      tree dest;
      tree left;
      tree right;
      enum tree_code bitop_code;

      stmt = gsi_stmt(gsi);

      if (gimple_code(stmt) != GIMPLE_ASSIGN)
	continue;  /* Only looking for GIMPLE_ASSIGN nodes. */

      /* In gcc 4.3 (whence this plug-in was ported), a bit operation
	 would be represented by an assign statement
	 (GIMPLE_MODIFY_STMT) with a bit expression tree node on its
	 right hand side.  New GIMPLE tuples can embed the expression
	 _within_ the GIMPLE_ASSIGN node!  So I guess we have to check
	 for that too. */
      bitop_code = gimple_assign_rhs_code(stmt);
      if (bitop_code == BIT_IOR_EXPR || bitop_code == BIT_AND_EXPR)
	{
	  left = gimple_op(stmt, 1);
	  right = gimple_op(stmt, 2);
	}
      else if ((bitop = walk_gimple_op(stmt, find_bitop, NULL)) != NULL)
	{
	  bitop_code = TREE_CODE(bitop);
	  left = TREE_OPERAND(bitop, 0);
	  right = TREE_OPERAND(bitop, 1);
	}
      else
	{
	  /* No bit operation here. */
	  continue;
	}

      if (verbose)
	fprintf(stderr, "Found bitop at line %d\n", gimple_lineno(stmt));

      dest = gimple_op(stmt, 0);

      tree source;
      tree bitmask;
      if (TREE_CODE(left) == COMPONENT_REF)
	{
	  source = left;
	  bitmask = right;
	}
      else if (TREE_CODE(right) == COMPONENT_REF)
	{
	  source = right;
	  bitmask = left;
	}
      else if (TREE_CODE(left) == VAR_DECL || TREE_CODE(left) == SSA_NAME)
	{
	  source = left;
	  bitmask = right;
	}
      else if (TREE_CODE(right) == VAR_DECL || TREE_CODE(right) == SSA_NAME)
	{
	  source = right;
	  bitmask = left;
	}
      else
	{
	  source = NULL;
	  bitmask = NULL;
	}

      /* We found a variable that is being masked with a bitwise
	 operator (along with the mask itself).  Let's trace back
	 through previous statements to find the variable's source.
	 We want to know if that source is a COMPONENT_REF. */
      source = trace_source(gsi, source);

      if (source != NULL)
	{
	  if (verbose)
	    fprintf(stderr, "Found bitmask source: %p.\n", source);

	  /* Build the bitmask */
	  bitmask = stabilize_reference(bitmask);
	  if (TREE_TYPE(bitmask) != long_unsigned_type_node) /* (unsigned long)bitmask */
	    bitmask = build1(NOP_EXPR, long_unsigned_type_node, bitmask);

	  /* Now we trace _forward_.  We want to know where the
	     resulting variable gets assigned.  We're trying to find
	     statements like this one:

	     inode->i_state |= I_DIRTY;
	  */
	  dest = trace_dest(gsi, dest);

	  if (verbose && dest != NULL)
	    fprintf(stderr, "Found bitmask destination: %p.\n", dest);


	  if (dest != NULL && source_and_dest_match(source, dest))
	    {
	      if (verbose)
		fprintf(stderr, "Matched source and destination.\n");

	      /* Invert the bitmask if necessary. */
	      if (bitop_code == BIT_AND_EXPR)
		bitmask = build1(BIT_NOT_EXPR, long_unsigned_type_node, bitmask); /* ~bitmask */

	      /* This is a read followed by an assign (like a |=
		 or &= operation).  Associate the bitmask with the
		 _destination_. */
	      associate_bitmask(comp_ref_bitmasks, dest, bitmask);

	      /* Associate an empty bitmask (0x0) with the source
		 read to indicate that it is _inert_. */
	      associate_bitmask(comp_ref_bitmasks, source,
				build_int_cst(long_unsigned_type_node, 0x0));
	    }
	  else
	    {
	      /* Invert the bitmask if necessary. */
	      if (bitop_code == BIT_IOR_EXPR)
		bitmask = build1(BIT_NOT_EXPR, long_unsigned_type_node, bitmask); /* ~bitmask */

	      /* This is just a straight read.  Associate the
		 bitmask with the _source_. */
	      associate_bitmask(comp_ref_bitmasks, source, bitmask);
	    }
	}
    }
}

/* Is this record node (left side of an a.b or a->b expression) a
   variable that has the marked custom attribute?*/
static int is_record_node_marked(tree record_node)
{
  if (DECL_P(record_node))
    {
      return (lookup_attribute(MARKED_ATTR, DECL_ATTRIBUTES(record_node)) != NULL);
    }
  else if (TREE_CODE(record_node) == SSA_NAME)
    {
      /* In the case of an SSA_NAME, we are really interested in the
	 original variable's attributes. */
      return is_record_node_marked(SSA_NAME_VAR(record_node));
    }
  else if (TREE_CODE(record_node) == INDIRECT_REF)
    {
      /* In the case of an indirect reference, we are really
	 interested in the dereferenced variable's attributes. */
      return is_record_node_marked(TREE_OPERAND(record_node, 0));
    }
  else
    {
      return false;
    }
}

/* Returns true if the given node is a DEBUG_EXPR or references a
   DEBUG_EXPR_DECL. */
static bool is_debug_ref(tree node)
{
  if (TREE_CODE(node) == INDIRECT_REF)
    return is_debug_ref(TREE_OPERAND(node, 0));
  else if (TREE_CODE(node) == DEBUG_EXPR_DECL)
    return true;
  else
    return false;
}

/* Return true if the given field directive indicates that we should
   instrument this COMPONENT_REF. */
static bool component_ref_matches_directive(tree node, struct field_directive *directive)
{
  /* Never match a DEBUG_EXPR_DECL. */
  if (is_debug_ref(get_record(node)))
    return false;

  /* Does the struct name match?  A NULL struct_name matches everything. */
  if (directive->struct_name && strcmp(get_record_name(node), directive->struct_name) != 0)
    return false;

  /* Does the field name match?  A NULL field_name matches everything. */
  if (directive->field_name && strcmp(get_field_name(node), directive->field_name) != 0)
    return false;

  /* Looks good! */
  return true;
}

/* Given two COMPONENT_REF nodes, find if one is an ancestor of the
   other.  A node is its own ancester. */
static bool is_component_ref_ancestor(tree ancestor, tree descendant)
{
  tree child;

  gcc_assert(TREE_CODE(ancestor) == COMPONENT_REF);
  gcc_assert(TREE_CODE(descendant) == COMPONENT_REF);

  if (ancestor == descendant)
    return true;

  child = TREE_OPERAND(ancestor, 0);
  if (TREE_CODE(child) == COMPONENT_REF)
    return is_component_ref_ancestor(child, descendant);
  else
    return false;
}

struct find_field_refs_args
{
  /* The field directive that tells find_field_refs() which field
     references to a hook to. */
  struct field_directive *directive;

  /* A mapping from COMPONENT_REF nodes to bitmask nodes. */
  htab_t comp_ref_bitmasks;

  /* This should be NULL initially.  find_field_refs() uses this field
     to keep track of nodes it finds on the left side of a
     GIMPLE_MODIFY_STMT (i.e., accesses that should be marked as
     writes). */
  tree write_ref;
};

static tree find_field_assigns(gimple_stmt_iterator *gsi, bool *handled_ops_p,
			       struct walk_stmt_info *wi)
{
  struct find_field_refs_args *args = wi->info;

  gimple stmt_node = gsi_stmt(wi->gsi);

  if (gimple_code(stmt_node) == GIMPLE_ASSIGN)
    {
      tree lvalue = gimple_op(stmt_node, 0);
      if (TREE_CODE(lvalue) == COMPONENT_REF)
	{
	  /* We found a COMPONENT_REF on the left side of an
	     assignment.  We remember that we found this here by
	     marking its address in write_ref.

	     If we add a hook to this node when we reach it, we'll
	     know to treat it as a write (not a read).

	     Because walk_tree uses a preorder traversal, there is no
	     chance that we'll encounter another GIMPLE_MODIFY_STMT
	     before this COMPONENT_REF, so we don't have to worry
	     about walk_ref getting clobbered before we need it. */
	  args->write_ref = lvalue;
	}
    }

  return NULL;
}

static tree find_field_refs(tree *node, int *walk_subtrees, void *data)
{
  struct walk_stmt_info *wi = data;
  struct find_field_refs_args *args = wi->info;
  
  gimple_stmt_iterator *iter = &wi->gsi;
  struct field_directive *directive = args->directive;

  /* Name every scratch variable with an index, so that each name is unique. */
  static unsigned int scratch_index = 0;

  if (TREE_CODE(*node) == COMPONENT_REF && component_ref_matches_directive(*node, directive))
    {
      int is_marked;
      gimple hook_call;

      /* Once we find one COMPONENT_REF that gets a hook, we no longer
	 wish to descend further looking for any more.*/
      *walk_subtrees = 0;

#ifdef DEBUG
      fprintf(stderr, "  Found component ref.\n");
#endif

      tree hook_func_decl = build_fn_decl(directive->hook_func_name, get_field_hook_type());

      /* Construct the first argument to the hook function, which is a
	 pointer to the accessed inode.

	 If the left operand of the COMPONENT_REF (which is the inode
	 we're looking for) is a decl, then it's ok to reference its
	 node directly.  Otherwise, we need to copy the node. */
      tree record_node = get_record(*node);
      is_marked = is_record_node_marked(record_node);
      if (!IS_TYPE_OR_DECL_P(record_node))
	{
#ifdef DEBUG
	  fprintf(stderr, "  (Non-DECL node.)\n");
#endif
	  /* It is ok for several nodes in the GIMPLE tree to share an
	     operand, if that operand is marked as DECL (or in some
	     other cases we do not consider).

	     If the node is not marked as DECL, however, we need make
	     an actual copy.  Previously we used copy_node() for this,
	     but copy_node() does not perform a deep copy, so we still
	     ended up sharing non-DECL nodes in some cases.

	     The stabilize_reference() function does one better.  It
	     knows exactly what to copy to prevent innappropriate
	     sharing. */
	  /*record_node = copy_node(record_node);*/
	  record_node = stabilize_reference(record_node);
	}
      tree record_addr = build1(ADDR_EXPR, build_pointer_type(TREE_TYPE(record_node)), record_node);

      tree record_name_ptr = get_record_name_ptr(*node);
      tree field_name_ptr = get_field_name_ptr(*node);
      int field_index = get_field_index(*node);
      int is_write = (args->write_ref != NULL &&
		      is_component_ref_ancestor(args->write_ref, *node));

      /* Is this node annotated with a bitmask? */
      tree bitmask_node;
      struct bitmask_mapping **mapping =
	(struct bitmask_mapping **)htab_find_slot(args->comp_ref_bitmasks, *node, NO_INSERT);
      if (mapping != NULL && (*mapping)->bitmask != NULL)
	{
	  if (verbose)
	    fprintf(stderr, "Found bitmask mapping at line %d.\n", input_line);
	  bitmask_node = (*mapping)->bitmask;
	  bitmask_node = assign_ref_to_tmp(iter, bitmask_node, "bitmask");
	}
      else
	{
	  /* Use the default bitmask (111...111b). */
	  bitmask_node = build_int_cst(long_unsigned_type_node, (unsigned long)-1);
	}

      /* Every hook gets a single int to act as scratch space. */
      char scratch_name[32];
      sprintf(scratch_name, "__field_trace_scratch_%u", scratch_index++);
      tree scratch_decl = build_static(integer_type_node, scratch_name, build_int_cst(integer_type_node, 0));
      tree scratch_addr = build1(ADDR_EXPR, build_pointer_type(TREE_TYPE(scratch_decl)), scratch_decl);

      /* File name and line number for this hook. */
      tree func_name_tree = build_string_ptr(input_filename);
      tree line_num_tree = build_int_cst(integer_type_node, input_line);

      record_addr = assign_ref_to_tmp(iter, record_addr, "record_addr");
      hook_call = gimple_build_call(hook_func_decl, 10,
				    record_addr,
				    record_name_ptr,
				    field_name_ptr,
				    build_int_cst(integer_type_node, field_index),
				    build_int_cst(integer_type_node, is_write),
				    build_int_cst(integer_type_node, is_marked),
				    bitmask_node,
				    scratch_addr,
				    func_name_tree,
				    line_num_tree);
      gsi_insert_before(iter, hook_call, GSI_SAME_STMT);

#ifdef DEBUG
      fprintf(stderr, "Inserted hook at line %d\n", input_line);
#endif
    } 

  /* NULL means keep traversing the tree. */
  return NULL;
}

/* A field directive instructs Field Trace to add function calls
   (hooks) at certain field accesses.  The directive should have the
   form:

   struct_name-field_name-func_name

   This function parses the directive. */
void parse_field_directive(const char *directive_string)
{
  char *args[3];
  const char *str_start;
  const char *str_end;
  int str_size;
  int i;

  struct field_directive directive;

  /* The first two arguments in the directive are terminated with a -.
     Use strchr to parse them. */
  str_start = directive_string;
  for (i = 0 ; i < 2 ; i++)
    {
      str_end = strchr(str_start, '-');
      if (str_end == NULL)
	{
	  error("Invalid field directive for Field Trace");
	  return;
	}

      str_size = (int)(str_end - str_start);
      args[i] = xmalloc(str_size + 1);
      memcpy(args[i], str_start, str_size);
      args[i][str_size] = '\0';

      str_start = str_end + 1;
    }

  /* The last argument ends with the end of the string. */
  str_size = strlen(str_start);
  args[2] = xmalloc(str_size + 1);
  memcpy(args[2], str_start, str_size);
  args[2][str_size] = '\0';

  /* There should not be more than two dashes. */
  if (strchr(str_start, '-') != NULL)
    {
      error("Invalid field directive for Field Trace");
      return;
    }

  /* If one of the first two args is a !, we replace it with a NULL
     pointer to indicate that any string should match. */
  if (strcmp(args[0], "!") == 0)
    {
      free(args[0]);
      args[0] = NULL;
    }

  if (strcmp(args[1], "!") == 0)
    {
      free(args[1]);
      args[1] = NULL;
    }

  /* Construct the directive and push it on the list of
     field_directive structs. */
  directive.struct_name = args[0];
  directive.field_name = args[1];
  directive.hook_func_name = args[2];
  VEC_safe_push(field_directive, heap, field_directive_vec, &directive);

  if (verbose)
    {
      fprintf(stderr, "Field Trace recognized directive:\n");
      if (args[0])
	fprintf(stderr, "  Struct name: %s\n", args[0]);
      else
	fprintf(stderr, "  Match all structs\n");
      if (args[1])
	fprintf(stderr, "  Field name: %s\n", args[1]);
      else
	fprintf(stderr, "  Match all fields\n");
      fprintf(stderr, "  Call hook function: %s\n", args[2]);
    }
}

/* This function does the actual instrumention work for the current
   function. */
void insert_field_hooks()
{
  basic_block my_basic_block;
  gimple_stmt_iterator gsi;

  FOR_EACH_BB(my_basic_block)
    {
      /* The comp_ref_bitmasks hash table maps relevant COMPONENT_REF
	 objects to bitmasks.  Note that we can rely on the garbage
	 collector to free this hash table and its contents.  This hash
	 table doesn't have any information that needs to persist across
	 different functions. */
      htab_t comp_ref_bitmasks =
	htab_create_ggc(10, hash_bitmask_mapping, eq_bitmask_mapping, NULL);

      get_bitmasks(my_basic_block, comp_ref_bitmasks);

      for (gsi = gsi_start_bb(my_basic_block);
	   !gsi_end_p(gsi);
	   gsi_next(&gsi)) 
	{
	  gimple my_statement = gsi_stmt(gsi);
	  if (gimple_has_location(my_statement))
	    input_location = gimple_location(my_statement);

	  struct field_directive *directive;
	  unsigned int i;

	  for (i = 0 ; VEC_iterate(field_directive, field_directive_vec, i, directive) ; i++)
	    {
	      struct find_field_refs_args args;
	      args.directive = directive;
	      args.comp_ref_bitmasks = comp_ref_bitmasks;
	      args.write_ref = NULL;

	      struct walk_stmt_info wi;
	      memset(&wi, 0, sizeof(wi));
	      wi.info = &args;

	      walk_gimple_stmt(&gsi, find_field_assigns, find_field_refs, &wi);
	    }
	}
    }
}

static void handle_config_pair(const char *key, const char *value)
{
  if (strcmp(key, "field") == 0)
    parse_field_directive(value);
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
  error("(Field Trace) Failed to read config file %s: %s", filename, strerror(errno));
  return;

 out_parse_err:
  fclose(file);
  error("(Field Trace) Parse error in config file %s:%d", filename, config_lineno);
  return;
}

static unsigned int transform_gimple()
{
  const char *function_name;

  /* Since the last time we initialized field_hook_type, the garbage
     collector may have destroyed it.  Set it to NULL and whoever
     needs it will initialize it on demand. */
  field_hook_type = NULL;

  function_name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));

  if (lookup_attribute(NOINSTRUMENT_ATTR, DECL_ATTRIBUTES(cfun->decl)) != NULL)
    {
      if (verbose)
	fprintf(stderr, "(Field Trace) Function %s marked as noinstrument.  Skipping.\n",
		function_name);
      return 0;
    }

#ifdef DEBUG
  fprintf(stderr, "Function %s\n", function_name);
#endif

  insert_field_hooks();

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

static struct attribute_spec marked_attr = {
  .name = MARKED_ATTR,
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
  register_attribute_once(&marked_attr);
}

/* This is the last plug-in function called before GCC exits.  Cleanup
   all the memory we allocated. */
static void cleanup(void *event_date, void *data)
{
  struct field_directive *directive;
  unsigned int i;

  for (i = 0 ; VEC_iterate(field_directive, field_directive_vec, i, directive) ; i++)
    {
      free(directive->struct_name);
      free(directive->field_name);
      free(directive->hook_func_name);
    }
  VEC_free(field_directive, heap, field_directive_vec);
}

static struct opt_pass pass_instrument_field_refs = {
  .type = GIMPLE_PASS,
  .name = "instr_fields",
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

  field_directive_vec = VEC_alloc(field_directive, heap, 10);

#ifdef DEBUG
  fprintf(stderr, "Initializing Field Trace plugin.\n");
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
	    error("(Field Trace) Must specify filename for -fplugin-arg-%s-config", plugin_name);
	}
      else if (strcmp(argv[i].key, "verbose") == 0)
	{
	  verbose = true;
	  fprintf(stderr, "Field Trace plugin running in verbose mode.\n");
	}
      else
	{
	  warning(0, "(Field Trace) Ignoring unrecognized option -fplugin-arg-%s-%s", plugin_name,
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
