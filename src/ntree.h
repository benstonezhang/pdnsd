/* ntree.h - Dynamic tree handling

   Copyright (C) 2024 Benstone Zhang.

  This file is part of the pdnsd package.

  pdnsd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  pdnsd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with pdnsd; see the file COPYING. If not, see
  <http://www.gnu.org/licenses/>.
 */

#ifndef _NTREE_H_
#define _NTREE_H_

#define NTREE_NODE_CHAR_COUNT 6

typedef struct ntree_node {
	/* bit 7:   if a name end at node string
	 * bit 6:   reversed
	 * bit 5-0: length of node array
	 */
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
extern int ntree_add_n(ntree_node_t *,const char *,int);

/*
 * search the domain/host exist
 * return: length of the match in name elements.
 */
extern int ntree_find(const ntree_node_t *,const unsigned char *);

extern size_t ntree_stat(const ntree_node_t *);

#endif