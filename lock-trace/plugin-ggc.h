#define GC_ROOT_TREE(V) tree V = NULL;		\
  static struct ggc_root_tab _gt_##V = {	\
    &V,						\
    1,						\
    sizeof(V),					\
    &gt_ggc_mx_tree_node,			\
    &gt_pch_nx_tree_node			\
}

#define GC_ROOT_TREE_HASH(V) htab_t V = NULL;	\
  static struct ggc_root_tab _gt_##V = {	\
    &V,						\
    1,						\
    sizeof(V),					\
    &gt_ggc_m_P9tree_node4htab,			\
    &gt_pch_n_P9tree_node4htab,			\
}

#define GC_ROOT_TREE_VEC(V) VEC(tree, gc) *V;	\
  static struct ggc_root_tab _gt_##V = {	\
    &V,						\
    1,						\
    sizeof(V),					\
    &gt_ggc_mx_VEC_tree_gc,			\
    &gt_pch_nx_VEC_tree_gc,			\
  }

#define register_root(V) ggc_add_plugin_root(&_gt_##V)
