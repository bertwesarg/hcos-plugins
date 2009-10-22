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

/* The verbose dumper is a diagnostic tool for GCC and GCC plug-in
   developers.  Verbose Dump does not transform any code; it outputs
   internal compiler information during compilation, including:

   For each file:
   1. Call graph: The graph of calls between functions within the
   file.

   For each function:
   2. c-trees: GCC's internal abstract syntax tree (AST).

   3. CFG: The control-flow graph for basic blocks in the function.

   For each basic block:
   4. GIMPLE: GCC's internal programming-language independent and
   architecture-independent intermediate representation.  GIMPLE is a
   three-address code. */

#include <inttypes.h>

/* Whether we want them or not (we don't), Autoconf _insists_ on
   defining these.  Since GCC's config.h (which we must include) also
   defines them, we have to undef them here. */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

/* Includes directly from GCC */
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
#include "real.h"  /* TODO: Get this into the plugin include directory. */
#include "gimple.h"
#include "c-common.h"

/* GCC only allows plug-ins that include this symbol. */
int plugin_is_GPL_compatible;

#define ENABLE_CAPPING

static int print_params(tree node, int depth, bool actually_print, char* id,tree target);
static void handle_bind_expr(tree bind, tree target);
static void handle_cond_expr(tree cond, tree target);
static void handle_switch_expr(tree switch_expr, tree target);
static void verbose_print_gimple_expr(gimple node, int depth, tree target);
void print_tree(tree);

static struct
{
  int	depth;
  bool	c_tree;
  bool  pass_list;
  FILE*	out_fp;
} globals = 
{
  .depth	= 0,
  .c_tree	= 0,
  .pass_list	= 0,
  .out_fp	= NULL
};

#define out_printf(...) fprintf(globals.out_fp, __VA_ARGS__)

static char* space(int depth)
{
  static char my_space[256];
  
  memset(my_space, ' ', 256);
  
  my_space[depth] = '\0';

  return my_space;
}

static void HANDLE_INT_CST_HIGH(tree node, char* name, unsigned int value, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%u\n", space(depth), acc, (uint32_t)value);
      else
        out_printf("%s%s=%u\n", space(depth), acc, (uint32_t)value);
    }
}

static void HANDLE_INTEGER(tree node, char* name, unsigned int value, int depth, bool print, char* acc, char* id,tree target)
{ 
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%u\n", space(depth), acc, (uint32_t)value);
      else
        out_printf("%s%s=%u\n", space(depth), acc, (uint32_t)value);
    }
}

static void HANDLE_INT_CST_LOW(tree node, char* name, unsigned int value, int depth, bool print, char* acc, char* id, tree target)
{ 
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%u\n", space(depth), acc, (uint32_t)value);
      else
        out_printf("%s%s=%u\n", space(depth), acc, (uint32_t)value);
    }
}

struct expr_level {
  tree current;
  struct expr_level* prev;
};

int find_expr(struct expr_level* expr, tree node)
{
  struct expr_level* curr;

  for(curr = expr; curr; curr = curr->prev)
    {
      if(node == curr->current)
        {
          return 1;
        }
    }

  return 0;
}

static void print_expr(tree node, int depth,tree target)
{
  static struct expr_level* prev = NULL;

  if(find_expr(prev, node))
    {
      out_printf("%s(loop) 0,0\n", space(depth));
      return;
    }

  struct expr_level curr_level;

  curr_level.current = node;
  curr_level.prev = prev;
  prev = &curr_level;

  int num_args = 0;
  char* id = NULL;

  #define DEFTREECODE(_id, _name, _flags, _num_args) case _id: num_args = _num_args; id = #_id; break;

  switch(TREE_CODE(node))
    {
      #include <tree.def>
    default:
      break;
    }

  #undef DEFTREECODE

  unsigned int i;

  switch(TREE_CODE(node))
    {
    case CALL_EXPR:
      {
        int special_args = TREE_INT_CST_LOW(TREE_OPERAND(node,0));
        int elements = print_params(node, depth, false, id, target);
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, special_args, node);
      }
      break;

    case CONSTRUCTOR:
      {
        int special_args = VEC_length(constructor_elt, CONSTRUCTOR_ELTS(node));
        int elements = print_params(node, depth, false, id, target);
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, special_args, node);
      }
      break;

    default:
      {
        int elements = print_params(node, depth, false, id,target);
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, num_args, node);
      }
    }

  print_params(node, depth, true, id,target);
    
  switch(TREE_CODE(node))
    {
    case CONSTRUCTOR:
      {
        tree index, val;
 
        FOR_EACH_CONSTRUCTOR_ELT(CONSTRUCTOR_ELTS(node), i, index, val)
          {
            out_printf("%sCONSTRUCTOR_ELT 0,2\n", space(depth));
            print_expr(index, depth + 1, target);
            print_expr(val, depth + 1, target);
          }
      }
      break;

    default:
      break;
    }

  for(i = 0; i < num_args; i++)
    {
      tree sub;
 
      sub = TREE_OPERAND(node, i);
      if(!sub)
        {
          out_printf("%s(null)\n", space(depth + 1));
        }
      else
        {
          print_expr(sub, depth + 1, target);
        }
    }

  if(TREE_CODE(node) == CALL_EXPR)
    {
      int j;

      for(j = 3; j < TREE_INT_CST_LOW(TREE_OPERAND(node, 0)); j++)
        {
          tree sub = TREE_OPERAND(node,j);
          if(!sub)
            {
              out_printf("%s(null)\n", space(depth + 1));
            }
          else
            {
              print_expr(sub, depth + 1,target);
            }
        }
    }

  prev = prev->prev;
}

static void HANDLE_TREE(tree node, char* name, tree data, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
    {
      if(data != NULL)
        {
          if(node == target)
            out_printf("$%s%s:\n", space(depth), acc);
          else
            out_printf("%s%s:\n", space(depth), acc);
          print_expr(data, depth + 1,target);
        }
      else
        {
          if(node == target)
            out_printf("$%s%s=NULL_TREE\n", space(depth), acc);
          else				
            out_printf("%s%s=NULL_TREE\n", space(depth), acc);
          return;
        }
    }
  else
    {
      return;
    }
}

#ifdef ENABLE_CAPPING
static void HANDLE_CAPPABLE(tree node, char* name, tree data, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=(capped)\n", space(depth), acc);
      else
        out_printf("%s%s=(capped)\n", space(depth), acc);
    }
  else
    {
      return;
    }
}
#else
#define HANDLE_CAPPABLE HANDLE_TREE
#endif

static void HANDLE_GIMPLE(tree node, char* name, gimple data, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
    {
      if (data != NULL)
        {
          out_printf("%s%s:\n", space(depth), acc);
          verbose_print_gimple_expr(data, depth + 1, target);
        }
      else
        {
          out_printf("%s%s=NULL_GIMPLE\n", space(depth), acc);
        }
    }
  else
    {
      return;
    }
}

static void HANDLE_BOOL(tree node, char* name, int data, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%d\n", space(depth), acc, data);
      else
        out_printf("%s%s=%d\n", space(depth), acc, data);
    }
}

static void HANDLE_MACHINE_MODE(tree node, char* name, enum machine_mode info, int depth, bool print, char* acc, char* id, tree target)
{
  char* mode_name;

  #define MODE(mode) case mode: mode_name = #mode; break;

  switch(info)
  {
    MODE(BImode)			
    MODE(QImode)
    MODE(HImode)
    //MODE(PSImode)
    MODE(SImode)
    //MODE(PDImode)
    MODE(DImode)
    MODE(TImode)
    //MODE(OImode)
    //MODE(QFmode)
    //MODE(HFmode)
    //MODE(TQFmode)
    MODE(SFmode)
    MODE(DFmode)
    MODE(XFmode)
    MODE(TFmode)
    MODE(CCmode)
    MODE(BLKmode)
    MODE(VOIDmode)
    //MODE(QCmode)
    //MODE(HCmode)
    MODE(SCmode)
    MODE(DCmode)
    MODE(XCmode)
    //MODE(TCMode)
    //MODE(CQImode)
    MODE(CHImode)
    MODE(CSImode)
    MODE(CDImode)
    MODE(CTImode)
    //MODE(COImode)
  default:
    mode_name = "unknown";
    break;
  }
  #undef MODE

  if(print)
  	out_printf("%s%s=%s\n", space(depth), acc, mode_name);
}

static void HANDLE_SIZE_T(tree node, char* name, size_t value, int depth, bool print, char* acc, char* id,tree target)
{
  if(print)
  	out_printf("%s%s=%llu\n", space(depth), acc, (long long unsigned)value);
}

static void HANDLE_REAL(tree node, char* name, REAL_VALUE_TYPE value, int depth, bool print, char* acc, char* id, tree target)
{
  static char rValue[100];

  real_to_decimal(rValue, &value, sizeof(rValue), 0, 1);

  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%s\n", space(depth), acc, rValue);
      else
        out_printf("%s%s=%s\n", space(depth), acc, rValue);
    }
}

static void HANDLE_STRING(tree node, char* name, const char* data, int depth, bool print, char* acc, char* id, tree target)
{
  if(print)
    {
			out_printf("%s%s=%s\n", space(depth), acc,data);
    }
}

static void HANDLE_OFF_T(tree node, char* name, off_t data, int depth, bool print, char* acc, char* id, tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%ld\n", space(depth), acc, data);
      else
        out_printf("%s%s=%ld\n", space(depth), acc, data);
    }
}

static void HANDLE_BUILT_IN_FUNCTION(tree node, char* name, enum built_in_function info, int depth, bool print, char* acc, char* id, tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%d\n", space(depth), acc, info);
      else
        out_printf("%s%s=%d\n", space(depth), acc, info);
    }
}

static void HANDLE_PHI_ARG(tree node, char* name, struct phi_arg_d arg, int depth, bool print, char* acc, char* id, tree target) __attribute__ ((unused));
static void HANDLE_PHI_ARG(tree node, char* name, struct phi_arg_d arg, int depth, bool print, char* acc, char* id, tree target)
{
  if(print)
    {
      if(node == target)
        out_printf("$%s%s=%p\n", space(depth), acc, &arg);
      else
        out_printf("%s%s=%p\n", space(depth), acc, &arg);
    }
}

static bool check_type(tree node, int types[])
{
  int i;

  for(i = 0; types[i] != -1; i++)
    {
      if(TREE_CODE(node) == types[i])
        {
          return true;
        }
    }
  return false;
}

static int print_params(tree node, int depth, bool actually_print, char* id, tree target)
{
  depth++;
  int local_elements = 0;
  #define DEFTREEPARAMETER(name, type, accessorMacro, ...)						\
    do													\
      {													\
        int curr_types [] = {__VA_ARGS__, -1};								\
        if(check_type(node, curr_types))								\
        {												\
          local_elements++;										\
          HANDLE_##type(node, #name, accessorMacro(node), depth, actually_print, #accessorMacro, id, target);	\
        }												\
      }													\
    while(0);

  #define DEFTREEPARAM_VECTOR(name, type, accessor, count, ...)						\
    do													\
      {													\
         int curr_types [] = {__VA_ARGS__, -1};								\
         int i = 0;											\
         if(check_type(node, curr_types))								\
           {												\
             while(i < count(node))									\
               {											\
                 i++;											\
               }											\
           }												\
      }													\
     while(0);

  enum printing_conditions { GIMPLE_ONLY, ALL };

  #define DEFTREEPARAM_CHAIN(name, conditions, accessorMacro, ...)					\
    do													\
      {													\
        int curr_types [] = {__VA_ARGS__, -1};								\
        if(check_type(node, curr_types))								\
          {												\
            local_elements++;										\
            if(actually_print)										\
              {												\
                if(conditions == GIMPLE_ONLY && globals.c_tree)						\
                  {											\
                    out_printf("%s%s=(capped)\n", space(depth), #accessorMacro);			\
                    break;										\
                  }											\
                tree cur_elt;										\
                int num_elts = 0;									\
                for(cur_elt = accessorMacro(node); cur_elt != NULL_TREE; cur_elt = TREE_CHAIN(cur_elt))	\
                  {											\
                    num_elts++;										\
                  }											\
                out_printf("%s%s:\n", space(depth), #accessorMacro);					\
                out_printf("%sTREE_CHAIN 0,%d\n", space(depth + 1), num_elts);				\
                for(cur_elt = accessorMacro(node); cur_elt != NULL_TREE; cur_elt = TREE_CHAIN(cur_elt))	\
                  {											\
                    print_expr(cur_elt, depth + 2, target);						\
                  }											\
              }												\
          }												\
      }													\
     while(0);

  #include "parameter.def"
  #undef DEFTREEPARAMETER
  #undef DEFTREEPARAM_VECTOR
  #undef DEFTREEPARAM_CHAIN

  return local_elements;
}

#if 0

void transform_ctrees(int argc, struct plugin_argument* argv,tree fndecl, tree target)
{
  globals.c_tree = true;
  tree saved_tree;
  saved_tree = DECL_SAVED_TREE(fndecl);
  tree list = BIND_EXPR_BODY(saved_tree); 

  if(TREE_CODE(list) != STATEMENT_LIST)
    {
      out_printf("C-Tree %s\n", IDENTIFIER_POINTER(DECL_NAME(fndecl)));
      out_printf("\n");
      out_printf("Depth:%d\n",globals.depth);
      out_printf("@");
      print_generic_stmt(globals.out_fp, list, 0);
      out_printf("@\n");
      print_expr(list, 1,target);
      out_printf("\n");
      out_printf("end %s\n", IDENTIFIER_POINTER(DECL_NAME(fndecl)));
      out_printf("\n");
      return;
    }
  
  out_printf("C-Tree %s\n", IDENTIFIER_POINTER(DECL_NAME(fndecl)));
  out_printf("\n");

  tree_stmt_iterator i;
  
  for(i = tsi_start(list); !tsi_end_p(i); tsi_next(&i))
    {
      tree temp;
      temp = tsi_stmt(i);

      if(temp != NULL)
        {
          switch(TREE_CODE(temp))
            {
            case COND_EXPR:
              handle_cond_expr(temp,target);
              break;
            case BIND_EXPR:
              handle_bind_expr(temp,target);
              break;
            case SWITCH_EXPR:
              handle_switch_expr(temp,target);
              break;
            default:
              out_printf("Depth:%d\n",globals.depth);
              out_printf("@");
              print_generic_stmt(globals.out_fp, temp, 0);
              out_printf("@\n");
              print_expr(temp, 1,target);
            }
        }
    }

  out_printf("\n");
  out_printf("end %s\n", IDENTIFIER_POINTER(DECL_NAME(fndecl)));
  out_printf("\n");
  globals.depth = 0;
  globals.c_tree = false;
} 

static void handle_switch_expr(tree switch_expr, tree target)
{
  tree switch_body = TREE_OPERAND(switch_expr,1);
  if(switch_body == NULL)
    {
      switch_body = TREE_OPERAND(switch_expr,2);
      int i;
      for(i = 0; i < TREE_VEC_LENGTH(switch_body); i++)
        {
          tree list = TREE_VEC_ELT(switch_body,i);
          out_printf("[stmt]");
          print_generic_stmt(globals.out_fp,list,0);
          //print_expr(list, 1);
        }
    }
  else
    {
      switch(TREE_CODE(switch_body))
        {
        case STATEMENT_LIST:
          {
            tree_stmt_iterator i;

            for(i = tsi_start(switch_body); !tsi_end_p(i); tsi_next(&i))
              {
                tree stmt = tsi_stmt(i);
                out_printf("Depth:%d\n",globals.depth);
                out_printf("@");
                print_generic_stmt(globals.out_fp, stmt, 0);
                out_printf("@\n");
                print_expr(stmt, 1,target);
              }
          }
          break;
        default:
          break;
        }
    }
}

static void handle_bind_expr(tree bind,tree target)
{
  out_printf("Depth:%d\n",globals.depth);
  out_printf("@");
  out_printf("{ };\n");
  out_printf("@\n");
  print_expr(bind, 1,target);
  globals.depth++;
  tree bind_body = BIND_EXPR_BODY(bind);

  tree_stmt_iterator i;

  for(i = tsi_start(bind_body); !tsi_end_p(i); tsi_next(&i))
    {
      tree temp;
      temp = tsi_stmt(i);
  
      if(temp != NULL)
        {
          if(TREE_CODE(temp) == COND_EXPR)
            {
              handle_cond_expr(temp,target);
            }
          else if(TREE_CODE(temp) == BIND_EXPR)
            {
              handle_bind_expr(temp,target);
            }
          else
            {
              out_printf("Depth:%d\n",globals.depth);
              out_printf("@");
              print_generic_stmt(globals.out_fp, temp, 0);
              out_printf("@\n");
              print_expr(temp, 1,target);
            }
        }
    }

  globals.depth--;
}

static void handle_cond_expr(tree cond, tree target)
{
  tree if_branch;
  tree else_branch;
  tree conditional;
  conditional = TREE_OPERAND(cond, 0);
  out_printf("Depth:%d\n",globals.depth);
  out_printf("@");
  out_printf("if ");
  print_generic_stmt(globals.out_fp, conditional, 0);
  out_printf("@\n");
  print_expr(cond, 1,target);
  if_branch = TREE_OPERAND(cond,1);
  globals.depth++;

  //Handle the body if the conditional is true
  if(TREE_CODE(if_branch) == STATEMENT_LIST)
    {
      tree_stmt_iterator cond_expr_body;

      for(cond_expr_body = tsi_start(if_branch);
          !tsi_end_p(cond_expr_body);
          tsi_next(&cond_expr_body))
        {
          tree stmt = tsi_stmt(cond_expr_body);

          if(TREE_CODE(stmt) == COND_EXPR)
            {
      	      handle_cond_expr(stmt,target);
            }
          else
            {
              out_printf("Depth:%d\n",globals.depth);
              out_printf("@");
              print_generic_stmt(globals.out_fp, stmt, 0);
              out_printf("@\n");
              print_expr(stmt, 1,target);
            }
        }
    }
  else if(TREE_CODE(if_branch) == COND_EXPR)
    {
      handle_cond_expr(if_branch,target);
    }
  else
    {
      out_printf("Depth:%d\n",globals.depth);
      out_printf("@");
      print_generic_stmt(globals.out_fp, if_branch, 0);
      out_printf("@\n");
      print_expr(if_branch, 1,target);
    } 

  //Handle the else if it exists
  else_branch = TREE_OPERAND(cond,2);
  if(else_branch == NULL)
    {
      return;
    }

  switch(TREE_CODE(else_branch))
    {
    case STATEMENT_LIST:
      {
        tree_stmt_iterator cond_expr_body;

        for(cond_expr_body = tsi_start(else_branch); !tsi_end_p(cond_expr_body); tsi_next(&cond_expr_body))
          {
            tree stmt = tsi_stmt(cond_expr_body);

            if(TREE_CODE(stmt) == COND_EXPR)
              {
                handle_cond_expr(stmt,target);
              }
            else
              {
                out_printf("Depth:%d\n",globals.depth);
                out_printf("@");
                print_generic_stmt(globals.out_fp, stmt, 0);
                out_printf("@\n");
                print_expr(stmt, 1,target);
              }
          }
      }
      break;
    case COND_EXPR:
      handle_cond_expr(else_branch,target);
      break;
    default:
      out_printf("Depth:%d\n",globals.depth);
      out_printf("@");
      print_generic_stmt(globals.out_fp, else_branch, 0);
      out_printf("@\n");
      print_expr(else_branch, 1,target);
    }

  globals.depth--;
}

void transform_cgraph()
{
  struct cgraph_node* current_node;
  struct varpool_node* current_var;
  
  out_printf("Graph Call_graph\n");  
  
  out_printf("%d nodes\n", cgraph_n_nodes);

  for(current_node = cgraph_nodes;
      current_node;
      current_node = current_node->next)
    {
      struct cgraph_edge* current_edge;

      out_printf(" Node %d (name %s, decl %p)\n", current_node->uid, cgraph_node_name(current_node), current_node->decl);

      out_printf("  Callers:\n");

      for(current_edge = current_node->callers;
          current_edge;
          current_edge = current_edge->next_caller)
        {
           out_printf("   uid %d\n", current_edge->caller->uid);
        }

      out_printf("  Callees:\n");

      for(current_edge = current_node->callees;
          current_edge;
          current_edge = current_edge->next_callee)
        {
           out_printf("   uid %d\n", current_edge->callee->uid);
        }
    }

  out_printf("Global variable pool:\n");

  for(current_var = varpool_nodes;
      current_var;
      current_var = current_var->next)
    {
      out_printf(" Variable %d (name %s, decl %p)\n", current_var->order, IDENTIFIER_POINTER(DECL_NAME(current_var->decl)), current_var->decl);
      //print_expr(current_var->decl, 2);
    }
  out_printf("\ngraph_end\n");
  out_printf("\n");
}

#endif

struct gimple_expr_level {
  gimple current;
  struct gimple_expr_level* prev;
};

static void verbose_print_gimple_expr(gimple node, int depth, tree target)
{
  char* id = NULL;

  #define DEFGSCODE(_id, _name, _structure) case _id: id = #_id; break;

  switch(gimple_code(node))
    {
      #include <gimple.def>
    default:
      break;
    }

  #undef DEFGSCODE

  unsigned int i;

  switch(gimple_code(node))
    {
    case GIMPLE_PHI:
      {
        int special_args = gimple_phi_num_args(node);
        int elements = 0; /*print_params(node, depth, false, id, target);*/
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, special_args, node);
      }
      break;
    case GIMPLE_CALL:
      {
        int special_args = gimple_call_num_args(node);
        int elements = 0; /*print_params(node, depth, false, id, target);*/
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, special_args, node);
      }
      break;
    default:
      {
        int num_ops = gimple_num_ops(node);
        int elements = 0; /*print_params(node, depth, false, id,target);*/
        out_printf("%s%s %d,%d,%p\n", space(depth), id, elements, num_ops, node);
      }
    }

  /*print_params(node, depth, true, id,target);*/
    
  switch(gimple_code(node))
    {
    case GIMPLE_PHI:
      {
        for(i = 0; i < gimple_phi_num_args(node); i++)
          {
            struct phi_arg_d* phi_arg = gimple_phi_arg(node, i);
            /* FIXME: This used to be depth instead of depth + 1,
               clearly an error.  Did the parser rely on this wrong
               behavior, though?*/
            print_expr(phi_arg->def, depth + 1, target);
          }
      }

    default:
      break;
    }

  for(i = 0; i < gimple_num_ops(node); i++)
    {
      tree sub;
 
      sub = gimple_op(node, i);
      if(!sub)
        {
          out_printf("%s(null)\n", space(depth + 1));
        }
      else
        {
          print_expr(sub, depth + 1, target);
        }
    }

  if(gimple_code(node) == GIMPLE_CALL)
    {
      int j;

      for(j = 0; j < gimple_call_num_args(node); j++)
        {
          tree sub = gimple_call_arg(node, j);
          if(!sub)
            {
              out_printf("%s(null)\n", space(depth + 1));
            }
          else
            {
              print_expr(sub, depth + 1, target);
            }
        }
    }
}

char* get_edge_flags_string (edge e)
{
  char* ret = xmalloc(1);
  size_t retlen = 0;

  ret[0] = '\0';

  #define HANDLE_FLAG(f)			\
    if(e->flags & f)				\
      {						\
        retlen += sizeof(#f) + 1;		\
        ret = xrealloc(ret, retlen);		\
        strcat(ret, #f " ");			\
      }

  HANDLE_FLAG(EDGE_FALLTHRU);
  HANDLE_FLAG(EDGE_ABNORMAL);
  HANDLE_FLAG(EDGE_ABNORMAL_CALL);
  HANDLE_FLAG(EDGE_EH);
  HANDLE_FLAG(EDGE_FAKE);
  HANDLE_FLAG(EDGE_DFS_BACK);
  HANDLE_FLAG(EDGE_CAN_FALLTHRU);
  HANDLE_FLAG(EDGE_IRREDUCIBLE_LOOP);
  HANDLE_FLAG(EDGE_SIBCALL);
  HANDLE_FLAG(EDGE_LOOP_EXIT);
  HANDLE_FLAG(EDGE_TRUE_VALUE);
  HANDLE_FLAG(EDGE_FALSE_VALUE);
  HANDLE_FLAG(EDGE_EXECUTABLE);
  HANDLE_FLAG(EDGE_CROSSING);
  HANDLE_FLAG(EDGE_COMPLEX);

  #undef HANDLE_FLAG

  return ret;
}

void print_tree(tree target)
{
  basic_block my_basic_block;
  gimple_stmt_iterator gsi;
  edge my_edge;
  edge_iterator mei;
  tree mpi;
  gimple phi;
  gimple_seq phis;

  if(!globals.out_fp)
    {
      globals.out_fp = globals.out_fp;
    }

  out_printf("Function %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));
  out_printf("\n");
  out_printf("Parameters:\n");

  for(mpi = DECL_ARGUMENTS(current_function_decl);
      mpi;
      mpi = TREE_CHAIN(mpi))
    {
      print_expr(mpi, 1, target);
    }

  out_printf("\n");

  out_printf("ENTRY_BLOCK_PTR %p\n", ENTRY_BLOCK_PTR);
  out_printf("%d successor(s):\n", EDGE_COUNT(ENTRY_BLOCK_PTR->succs));
  
  FOR_EACH_EDGE(my_edge, mei, ENTRY_BLOCK_PTR->succs)
  {
    out_printf("  %p\n", my_edge->dest);
  }

  out_printf("\n");

  out_printf("EXIT_BLOCK_PTR %p\n", EXIT_BLOCK_PTR);
  out_printf("%d predecessor(s):\n", EDGE_COUNT(EXIT_BLOCK_PTR->preds));

  FOR_EACH_EDGE(my_edge, mei, EXIT_BLOCK_PTR->preds)
  {
    out_printf("  %p\n", my_edge->src);
  }

  out_printf("\n");

  FOR_EACH_BB(my_basic_block)
  {
    out_printf("Basic block %p\n", my_basic_block);
    FOR_EACH_EDGE(my_edge, mei, my_basic_block->succs)
      {
      }
    
    out_printf("%d predecessors(s):\n", EDGE_COUNT(my_basic_block->preds));

    FOR_EACH_EDGE(my_edge, mei, my_basic_block->preds)
      {
        out_printf("  %p\n", my_edge->src);
      }

    out_printf("%d successor(s):\n", EDGE_COUNT(my_basic_block->succs));
      
    FOR_EACH_EDGE(my_edge, mei, my_basic_block->succs)
      {
        out_printf("  %p\n", my_edge->dest);

        char* flags_string = get_edge_flags_string(my_edge);
        out_printf("%s", flags_string);
        free(flags_string);

        out_printf("\n");
      }

    phis = phi_nodes(my_basic_block);
    for(gsi = gsi_start(phis); !gsi_end_p(gsi); gsi_next(&gsi))
      {
        phi = gsi_stmt(gsi);

        out_printf("[stmt] Unknown file and line\n");
        print_gimple_stmt(globals.out_fp, phi, 0, TDF_VERBOSE);
        verbose_print_gimple_expr(phi, 1, target);
      }

    for (gsi = gsi_start_bb(my_basic_block);
         !gsi_end_p(gsi);
         gsi_next(&gsi)) 
      {
        gimple my_statement = gsi_stmt(gsi);

        out_printf("[stmt] ");

        if(gimple_has_location(my_statement))
          {
            out_printf("File %s, line %u\n",
                   gimple_filename(my_statement),
                   gimple_lineno(my_statement));
          }
        else
          {
            out_printf("Unknown file and line\n");
          }

        switch(gimple_code(my_statement))
          {
          case GIMPLE_SWITCH:
            //handle_switch_expr(my_statement,target);
            out_printf("Todo: handle switch\n");
            break;
          default:
            print_gimple_stmt(globals.out_fp, my_statement, 0, TDF_VERBOSE);
            break;
          }

        verbose_print_gimple_expr(my_statement, 1, target);
      }

    out_printf("\n");
  }
}

#define HANDLE_FLAG(f)			\
  if (flags & f)			\
    {					\
      if (first_property)		\
	{				\
	  out_printf(#f);		\
	  first_property = false;	\
	}				\
      else				\
	{				\
	  out_printf("|%s", #f);	\
	}				\
    }

static void print_pass_properties(const char *field, unsigned int flags, int depth)
{
  bool first_property = true;

  out_printf("%s%s=(", space(depth), field);
  HANDLE_FLAG(PROP_gimple_any);
  HANDLE_FLAG(PROP_gimple_lcf);
  HANDLE_FLAG(PROP_gimple_leh);
  HANDLE_FLAG(PROP_cfg);
  HANDLE_FLAG(PROP_referenced_vars);
  HANDLE_FLAG(PROP_ssa);
  HANDLE_FLAG(PROP_no_crit_edges);
  HANDLE_FLAG(PROP_rtl);
  HANDLE_FLAG(PROP_gimple_lomp);
  HANDLE_FLAG(PROP_cfglayout);
  out_printf(")\n");
}

static void print_pass_todo(const char *field, unsigned int flags, int depth)
{
  bool first_property = true;

  out_printf("%s%s=(", space(depth), field);
  HANDLE_FLAG(TODO_dump_func);
  HANDLE_FLAG(TODO_ggc_collect);
  HANDLE_FLAG(TODO_verify_ssa);
  HANDLE_FLAG(TODO_verify_flow);
  HANDLE_FLAG(TODO_verify_stmts);
  HANDLE_FLAG(TODO_cleanup_cfg);
  HANDLE_FLAG(TODO_verify_loops);
  HANDLE_FLAG(TODO_dump_cgraph);
  HANDLE_FLAG(TODO_remove_functions);
  HANDLE_FLAG(TODO_rebuild_frequencies);
  HANDLE_FLAG(TODO_verify_rtl_sharing);
  out_printf(")\n");
}

#undef HANDLE_FLAG

static void print_pass_details(struct opt_pass* pass, int depth)
{
  out_printf("%s", space(depth));

  switch(pass->type)
    {
    case GIMPLE_PASS:
      out_printf("GIMPLE_PASS");
      break;
    case RTL_PASS:
      out_printf("RTL_PASS");
      break;
    case SIMPLE_IPA_PASS:
      out_printf("SIMPLE_IPA_PASS");
      break;
    case IPA_PASS:
      out_printf("IPA_PASS");
      break;
    default:
      out_printf("BAD PASS TYPE");
      break;
    }

  out_printf(" %s\n", (pass->name != NULL) ? pass->name : "(unnamed)");

  out_printf("%s.gate=%p\n", space(depth + 1), pass->gate);
  out_printf("%s.execute=%p\n", space(depth + 1), pass->execute);
  out_printf("%s.static_pass_number=%d\n", space(depth + 1), pass->static_pass_number);
  out_printf("%s.tv_id=%u\n", space(depth + 1), pass->tv_id);
  print_pass_properties(".properties_required", pass->properties_required, depth + 1);
  print_pass_properties(".properties_provided", pass->properties_provided, depth + 1);
  print_pass_properties(".properties_destroyed", pass->properties_destroyed, depth + 1);
  print_pass_todo(".todo_flags_start", pass->todo_flags_start, depth + 1);
  print_pass_todo(".todo_flags_finish", pass->todo_flags_finish, depth + 1);  
}

static void print_pass_list(struct opt_pass* pass, int depth)
{
  for (; pass != NULL; pass = pass->next)
    {
      print_pass_details(pass, depth);
      print_pass_list(pass->sub, depth + 2);
    }
}

static void print_all_passes()
{
  out_printf("all_lowering_passes\n\n");
  print_pass_list(all_lowering_passes, 0);

  out_printf("\nall_ipa_passes\n\n");
  print_pass_list(all_ipa_passes, 0);

  out_printf("\nall_passes\n\n");
  print_pass_list(all_passes, 0);
}

void pre_translation_unit(int argc, struct plugin_argument* argv)
{
  globals.out_fp = stdout;

  int i;

  char* out_path = NULL;

  for(i = 0; i < argc; i++)
    {
      if(!strcmp(argv[i].key, "file"))
        {
          if(argv[i].value)
            {
              out_path = argv[i].value;
            }
          else
            {
              #define GIMPLE_EXT ".out"
              char* gimple_file_name = xmalloc(strlen(main_input_filename) + sizeof(GIMPLE_EXT));
              strcpy(gimple_file_name, main_input_filename);
              char* dotptr = strrchr(gimple_file_name, '.');

              if(dotptr)
                {
                  *dotptr = '\0';
                }

              strcat(gimple_file_name, GIMPLE_EXT);
              #undef GIMPLE_EXT

              out_path = gimple_file_name;
            }
        }
      else if(!strcmp(argv[i].key, "dump-passes"))
	{
	  globals.pass_list = true;
	}
    }

  if(out_path)
    {
      globals.out_fp = fopen(out_path, "w");

      if(!globals.out_fp)
        {
          warning(0, "Opening output file %s failed: %s", out_path, strerror(errno));
          globals.out_fp = stdout;
        }
    }
}

static unsigned int transform_gimple()
{
  globals.c_tree = false;
  print_tree(NULL);

  return 0;
}

void post_translation_unit()
{
  if(globals.out_fp != stdout)
    {
      fclose(globals.out_fp);
    }
}

/***************************************************************************************************
 * New support code below
 ***************************************************************************************************/

static unsigned int transform_gimple();

static struct opt_pass pass_plugin_test = {
  .type = GIMPLE_PASS,
  .name = "my_test_pass",
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
  .todo_flags_finish = 0,
};

static struct plugin_pass pass_info = {
  .pass = &pass_plugin_test,
  .reference_pass_name = "*all_optimizations",
  .ref_pass_instance_number = 0,
  .pos_op = PASS_POS_INSERT_BEFORE,
};

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
  pre_translation_unit(plugin_info->argc, plugin_info->argv);

  /* Register the Verbose Dump GIMPLE pass. */
  register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  /* Register the cleanup code. */
  register_callback(plugin_info->base_name, PLUGIN_FINISH, post_translation_unit, NULL);

  /* Most dumping occurs in a specialized pass, but there is of course
     no appropriate pass for dumping the pass list itself. */
  if (globals.pass_list)
    print_all_passes();

  return 0;
}
