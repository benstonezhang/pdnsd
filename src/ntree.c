/* ntree.c - Dynamic tree handling

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

#include <stddef.h>
#include <stdlib.h>
#include "ntree.h"
#include "dns.h"

static const char chars_offset[]={
	-1, // 0x00
	-1, // 0x01
	-1, // 0x02
	-1, // 0x03
	-1, // 0x04
	-1, // 0x05
	-1, // 0x06
	-1, // 0x07
	-1, // 0x08
	-1, // 0x09
	-1, // 0x0a
	-1, // 0x0b
	-1, // 0x0c
	-1, // 0x0d
	-1, // 0x0e
	-1, // 0x0f
	-1, // 0x10
	-1, // 0x11
	-1, // 0x12
	-1, // 0x13
	-1, // 0x14
	-1, // 0x15
	-1, // 0x16
	-1, // 0x17
	-1, // 0x18
	-1, // 0x19
	-1, // 0x1a
	-1, // 0x1b
	-1, // 0x1c
	-1, // 0x1d
	-1, // 0x1e
	-1, // 0x1f
	-1, // 0x20
	-1, // 0x21
	-1, // 0x22
	-1, // 0x23
	-1, // 0x24
	-1, // 0x25
	-1, // 0x26
	-1, // 0x27
	-1, // 0x28
	-1, // 0x29
	-1, // 0x2a
	-1, // 0x2b
	-1, // 0x2c
	27, // 0x2d, '-'
	26, // 0x2e, '.'
	-1, // 0x2f
	28, // 0x30, '0'
	29, // 0x31, '1'
	30, // 0x32, '2'
	31, // 0x33, '3'
	32, // 0x34, '4'
	33, // 0x35, '5'
	34, // 0x36, '6'
	35, // 0x37, '7'
	36, // 0x38, '8'
	37, // 0x39, '9'
	-1, // 0x3a
	-1, // 0x3b
	-1, // 0x3c
	-1, // 0x3d
	-1, // 0x3e
	-1, // 0x3f
	-1, // 0x40
	-1, // 0x41
	-1, // 0x42
	-1, // 0x43
	-1, // 0x44
	-1, // 0x45
	-1, // 0x46
	-1, // 0x47
	-1, // 0x48
	-1, // 0x49
	-1, // 0x4a
	-1, // 0x4b
	-1, // 0x4c
	-1, // 0x4d
	-1, // 0x4e
	-1, // 0x4f
	-1, // 0x50
	-1, // 0x51
	-1, // 0x52
	-1, // 0x53
	-1, // 0x54
	-1, // 0x55
	-1, // 0x56
	-1, // 0x57
	-1, // 0x58
	-1, // 0x59
	-1, // 0x5a
	-1, // 0x5b
	-1, // 0x5c
	-1, // 0x5d
	-1, // 0x5e
	-1, // 0x5f
	-1, // 0x60
	0, // 0x61, 'a'
	1, // 0x62, 'b'
	2, // 0x63, 'c'
	3, // 0x64, 'd'
	4, // 0x65, 'e'
	5, // 0x66, 'f'
	6, // 0x67, 'g'
	7, // 0x68, 'h'
	8, // 0x69, 'i'
	9, // 0x6a, 'j'
	10, // 0x6b, 'k'
	11, // 0x6c, 'l'
	12, // 0x6d, 'm'
	13, // 0x6e, 'n'
	14, // 0x6f, 'o'
	15, // 0x70, 'p'
	16, // 0x71, 'q'
	17, // 0x72, 'r'
	18, // 0x73, 's'
	19, // 0x74, 't'
	20, // 0x75, 'u'
	21, // 0x76, 'v'
	22, // 0x77, 'w'
	23, // 0x78, 'x'
	24, // 0x79, 'y'
	25, // 0x7a, 'z'
	-1, // 0x7b
	-1, // 0x7c
	-1, // 0x7d
	-1, // 0x7e
	-1, // 0x7f
};

static const ntree_node_t dummy_leaf={0};

#define CHAR_DOT '.'
#define NTREE_NODES_COUNT 38
#define NODE_ARRAY_LENGTH_MASK 0x3F
#define NODE_NAME_END_MASK 0x80

#define LEAF_SIZE(size) offsetof(ntree_node_t,str[(size)])
#define NODE_SIZE(size) offsetof(ntree_node_t,nodes[(size)])
#define NODE_OFFSET(c)  ((int)chars_offset[(unsigned char)(c)])
#define NODE_ARRAY_LENGTH(a) (((a)->arr_len)&NODE_ARRAY_LENGTH_MASK)
#define NODE_NAME_END(a) (((a)->arr_len)&NODE_NAME_END_MASK)

ntree_node_t *ntree_init(){
	ntree_node_t *root=calloc(1,NODE_SIZE(NTREE_NODES_COUNT));
	if (root!=NULL) {
		root->arr_len=NTREE_NODES_COUNT;
	}
	return root;
}

void ntree_free(ntree_node_t *base){
	int i,n,level=0;
	ntree_node_t *node,*node_stack[DNSNAMEBUFSIZE];
	unsigned char offset[DNSNAMEBUFSIZE];

	node_stack[0]=base;
	offset[0]=0;
	do {
		entry:
		base=node_stack[level];
		n=NODE_ARRAY_LENGTH(base);
		for (i=offset[level];i<n;i++) {
			node=base->nodes[i];
			if ((node!=NULL)&&(node!=base)&&(node!=&dummy_leaf)) {
				if (n) {
					// branch node
					offset[level]=i+1;
					level++;
					node_stack[level]=node;
					offset[level]=0;
					goto entry;
				}
				// leaf node
				free(node);
			}
		}
		free(base);
		level--;
	} while (level>=0);
}

static inline void ntree_revert_copy_str(char *dst,const char *src,const int l){
	int i=0,j=l;
	while (j) dst[i++]=src[--j];
}

static inline void ntree_node_copy_str(ntree_node_t *dst,const ntree_node_t *src,const int l){
	int i;
	for (i=0;i<l;i++) dst->str[i]=src->str[i];
	dst->str_len=l;
}

static inline int ntree_name_to_str(char *dst,const unsigned char *src){
	int i,n=0;
	unsigned char c;
	while (*src) {
		if (n) {
			*dst++=CHAR_DOT;
			n++;
		}
		c=*src++;
		for (i=0;i<c;i++) *dst++=*(char *)src++;
		n+=c;
	}
	*dst=0;
	return n;
}

static ntree_node_t *ntree_branch_create(const int size){
	ntree_node_t *node=calloc(1,NODE_SIZE(size));
	if (node!=NULL) node->arr_len=size;
	return node;
}

static ntree_node_t *ntree_branch_expand(ntree_node_t *node,const int size){
	node=realloc(node,NODE_SIZE(size));
	if (node!=NULL) {
		int i;
		for (i=NODE_ARRAY_LENGTH(node);i<size;i++) node->nodes[i]=NULL;
		node->arr_len=size|NODE_NAME_END(node);
	}
	return node;
}

static ntree_node_t *ntree_branch_expand_from_leaf(ntree_node_t *node,const int size){
	node=realloc(node,NODE_SIZE(size));
	if (node!=NULL) {
		int i;
		for (i=0;i<size;i++) node->nodes[i]=NULL;
		node->arr_len=size|NODE_NAME_END_MASK;
	}
	return node;
}

static ntree_node_t *ntree_leaf_create(const char *s,int l){
	ntree_node_t *node;
	if (l) {
		node=malloc(LEAF_SIZE(l));
		if (node!=NULL) {
			node->arr_len=0;
			node->str_len=l;
			ntree_revert_copy_str(node->str,s,l);
		}
	} else {
		node=(ntree_node_t *)&dummy_leaf;
	}
	return node;
}

static ntree_node_t *ntree_node_shrink(ntree_node_t *node,int l){
	int n=node->str_len,j=n-l;
	if (j) {
		int i,k;
		for (i=0,k=l;i<j;i++,k++) node->str[i]=node->str[k];
		node->str_len=j;
		if ((node->arr_len==0)&&(n>NTREE_NODE_CHAR_COUNT)) {
			node=realloc(node,LEAF_SIZE(j));
		}
	} else {
		if (node->arr_len) {
			node->str_len=0;
		} else {
			free(node);
			node=(ntree_node_t *)&dummy_leaf;
		}
	}
	return node;
}

int ntree_add_n(ntree_node_t *root,const char *s,const int n){
	ntree_node_t **base_ptr,*base,*node;
	int i,l,m,m1,m2;
	char c1,c2;

	if (n<3) return -1;

	// check chars, only limited chars allowed
	for (l=0;l<n;l++) if ((s[l]&0x80)||(NODE_OFFSET(s[l])<0)) return 0;

	// skip first dot char
	if (s[--l]==CHAR_DOT) l--;

	m2=NODE_OFFSET(s[l]);
	if ((base=root->nodes[m2])==NULL) {
		if ((node=ntree_leaf_create(s,l))) {
			root->nodes[m2]=node;
			return 1;
		}
		return -1;
	}

	base_ptr=&root->nodes[m2];
	l--;

	for (;;) {
		i=0;
		m=base->str_len;

		while (i<m) {
			c1=base->str[i];
			c2=s[l];

			if (c1!=c2) {
				// name differ with current node string, split current node
				m1=NODE_OFFSET(c1);
				m2=NODE_OFFSET(c2);
				node=base;
				if ((base=ntree_branch_create((m1>m2?m1:m2)+1))) {
					ntree_node_copy_str(base,node,i);
					base->nodes[m1]=node;
					*base_ptr=base;
					if ((node=ntree_node_shrink(node,i+1))) {
						base->nodes[m1]=node;
						if ((node=ntree_leaf_create(s,l))) {
							base->nodes[m2]=node;
							return 1;
						}
					}
				}
				return -1;
			}

			if (l==0) {
				if (i+1!=m) {
					// name shorter than node string, split current node
					m1=NODE_OFFSET(c1);
					node=base;
					if ((base=ntree_branch_create(m1+1))) {
						base->arr_len|=NODE_NAME_END_MASK;
						ntree_node_copy_str(base,node,i);
						base->nodes[m1]=node;
						*base_ptr=base;
						if ((node=ntree_node_shrink(node,i+1))) {
							base->nodes[m1]=node;
							return 1;
						}
					}
					return -1;
				}
				if (base->arr_len) {
					// name is same as branch node string
					base->arr_len|=NODE_NAME_END_MASK;
				}
				// else, it's duplicate name, skip it
				return 1;
			}

			if (i==NTREE_NODE_CHAR_COUNT) {
				// insert intermedia branch node
				m1=NODE_OFFSET(c1);
				node=base;
				if ((base=ntree_branch_create(m1+1))) {
					ntree_node_copy_str(base,node,NTREE_NODE_CHAR_COUNT);
					base->nodes[m1]=node;
					*base_ptr=base;
					if ((node=ntree_node_shrink(node,i+1))) {
						base->nodes[m1]=node;
						base_ptr=&base->nodes[m1];
						base=node;
						m-=NTREE_NODE_CHAR_COUNT;
						i=0;
						l--;
						continue;
					}
				}
				return -1;
			}

			i++;
			l--;
		}

		m2=NODE_OFFSET(s[l]);
		if (base==(ntree_node_t *)&dummy_leaf) {
			if ((base=ntree_branch_create(m2+1))) {
				base->arr_len|=NODE_NAME_END_MASK;
				*base_ptr=base;
				if ((node=ntree_leaf_create(s,l))) {
					base->nodes[m2]=node;
					return 1;
				}
			}
			return -1;
		}

		if (base->arr_len==0) {
			// leaf node, name longer than node string
			if ((base=ntree_branch_expand_from_leaf(base,m2+1))) {
				*base_ptr=base;
				if ((node=ntree_leaf_create(s,l))) {
					base->nodes[m2]=node;
					return 1;
				}
			}
			return -1;
		}

		// branch node, name longer than node string
		if (NODE_ARRAY_LENGTH(base)<=m2) {
			if ((base=ntree_branch_expand(base,m2+1))) {
				*base_ptr=base;
				if ((node=ntree_leaf_create(s,l))) {
					base->nodes[m2]=node;
					return 1;
				}
			}
			return -1;
		}

		if (base->nodes[m2]==NULL) {
			if ((node=ntree_leaf_create(s,l))) {
				base->nodes[m2]=node;
				return 1;
			}
			return -1;
		}

		// travel through child node
		base_ptr=&base->nodes[m2];
		base=base->nodes[m2];
		l--;
	}
}

int ntree_find(const ntree_node_t *base,const unsigned char *s){
	int i,m,n=0;
	unsigned char c1=0,c2;
	char buf[DNSNAMEBUFSIZE],*p;

	p=buf+ntree_name_to_str(buf,s);
	while (p!=buf) {
		for (i=0;i<base->str_len;i++) {
			c1=*--p;
			if ((c1==0)||(c1!=base->str[i])) return 0;
		}
		n+=base->str_len;
		c2=*--p;
		if ((c2&0x80)==0) {
			if (base->arr_len) {        // branch node
				if ((c1==CHAR_DOT)&&(NODE_NAME_END(base))) return n;
				m=NODE_OFFSET(c2);
				if ((m>=0)&&(m<NODE_ARRAY_LENGTH(base))&&(base=base->nodes[m])) {
					n++;
					c1=c2;
					continue;
				}
			} else {                // leaf node
				if ((c2==0)||(c1==CHAR_DOT)) return n;
			}
		}
		break;
	}
	return 0;
}

size_t ntree_stat(const ntree_node_t *root){
	int i,l,level=0;
	const ntree_node_t *base,*node,*node_stack[DNSNAMEBUFSIZE];
	unsigned char offset[DNSNAMEBUFSIZE];
	size_t n=NODE_SIZE(NTREE_NODES_COUNT)+sizeof(dummy_leaf);

	node_stack[0]=root;
	offset[0]=0;
	do {
		entry:
		base=node_stack[level];
		i=offset[level];
		l=NODE_ARRAY_LENGTH(base);
		while (i<l) {
			node=base->nodes[i];
			if ((node!=NULL)&&(node!=base)&&(node!=&dummy_leaf)) {
				if (node->arr_len==0) {        // leaf node
					n+=LEAF_SIZE(node->str_len);
				} else {                // branch node
					n+=NODE_SIZE(NODE_ARRAY_LENGTH(node));
					offset[level]=i+1;
					level++;
					node_stack[level]=node;
					offset[level]=0;
					goto entry;
				}
			}
			i++;
		}
		level--;
	} while (level>=0);
	return n;
}
