/* nodes_weight returns int (signed). The % operator on signed types generates
 * sdiv which the BPF backend cannot select. Redefine to return unsigned. */
#undef nodes_weight
#define nodes_weight(nodemask) ((unsigned int)__nodes_weight(&(nodemask), MAX_NUMNODES))
