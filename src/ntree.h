/*
 * Created by benstone on 2024/1/6.
 */

#ifndef _NTREE_H_
#define _NTREE_H_

#define NTREE_NODE_CHAR_COUNT 6

typedef struct ntree_node {
	unsigned char arr_len;
	unsigned char str_len;
	char str[NTREE_NODE_CHAR_COUNT];
	struct ntree_node *nodes[];
} ntree_node_t;

/* initialize domain/host search tree */
extern ntree_node_t *ntree_init();

/* free the tree */
extern void ntree_free(ntree_node_t *);

/*
 * add domain/host to search tree
 * return: 1 - added; 0 - skipped; -1 - error
 */
extern int ntree_add(ntree_node_t *,const char *);
extern int ntree_add_n(ntree_node_t *,const char *,int);

/*
 * search the domain/host exist
 * return: 1 - found; 0 - not found
 */
extern int ntree_search(const ntree_node_t *,const unsigned char *);

extern size_t ntree_stat(const ntree_node_t *);

#endif