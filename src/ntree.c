/*
 * Created by benstone on 2024/1/6.
 */

#include <stddef.h>
#include <stdlib.h>
#include "ntree.h"
#include "dns.h"

static const char chars_offset[]={
	-1,        // 0x00
	-1,        // 0x01
	-1,        // 0x02
	-1,        // 0x03
	-1,        // 0x04
	-1,        // 0x05
	-1,        // 0x06
	-1,        // 0x07
	-1,        // 0x08
	-1,        // 0x09
	-1,        // 0x0a
	-1,        // 0x0b
	-1,        // 0x0c
	-1,        // 0x0d
	-1,        // 0x0e
	-1,        // 0x0f
	-1,        // 0x10
	-1,        // 0x11
	-1,        // 0x12
	-1,        // 0x13
	-1,        // 0x14
	-1,        // 0x15
	-1,        // 0x16
	-1,        // 0x17
	-1,        // 0x18
	-1,        // 0x19
	-1,        // 0x1a
	-1,        // 0x1b
	-1,        // 0x1c
	-1,        // 0x1d
	-1,        // 0x1e
	-1,        // 0x1f
	-1,        // 0x20
	-1,        // 0x21
	-1,        // 0x22
	-1,        // 0x23
	-1,        // 0x24
	-1,        // 0x25
	-1,        // 0x26
	-1,        // 0x27
	-1,        // 0x28
	-1,        // 0x29
	-1,        // 0x2a
	-1,        // 0x2b
	-1,        // 0x2c
	27,        // 0x2d, '-'
	26,        // 0x2e, '.'
	-1,        // 0x2f
	28,        // 0x30, '0'
	29,        // 0x31, '1'
	30,        // 0x32, '2'
	31,        // 0x33, '3'
	32,        // 0x34, '4'
	33,        // 0x35, '5'
	34,        // 0x36, '6'
	35,        // 0x37, '7'
	36,        // 0x38, '8'
	37,        // 0x39, '9'
	-1,        // 0x3a
	-1,        // 0x3b
	-1,        // 0x3c
	-1,        // 0x3d
	-1,        // 0x3e
	-1,        // 0x3f
	-1,        // 0x40
	-1,        // 0x41
	-1,        // 0x42
	-1,        // 0x43
	-1,        // 0x44
	-1,        // 0x45
	-1,        // 0x46
	-1,        // 0x47
	-1,        // 0x48
	-1,        // 0x49
	-1,        // 0x4a
	-1,        // 0x4b
	-1,        // 0x4c
	-1,        // 0x4d
	-1,        // 0x4e
	-1,        // 0x4f
	-1,        // 0x50
	-1,        // 0x51
	-1,        // 0x52
	-1,        // 0x53
	-1,        // 0x54
	-1,        // 0x55
	-1,        // 0x56
	-1,        // 0x57
	-1,        // 0x58
	-1,        // 0x59
	-1,        // 0x5a
	-1,        // 0x5b
	-1,        // 0x5c
	-1,        // 0x5d
	-1,        // 0x5e
	-1,        // 0x5f
	-1,        // 0x60
	0,        // 0x61, 'a'
	1,        // 0x62, 'b'
	2,        // 0x63, 'c'
	3,        // 0x64, 'd'
	4,        // 0x65, 'e'
	5,        // 0x66, 'f'
	6,        // 0x67, 'g'
	7,        // 0x68, 'h'
	8,        // 0x69, 'i'
	9,        // 0x6a, 'j'
	10,        // 0x6b, 'k'
	11,        // 0x6c, 'l'
	12,        // 0x6d, 'm'
	13,        // 0x6e, 'n'
	14,        // 0x6f, 'o'
	15,        // 0x70, 'p'
	16,        // 0x71, 'q'
	17,        // 0x72, 'r'
	18,        // 0x73, 's'
	19,        // 0x74, 't'
	20,        // 0x75, 'u'
	21,        // 0x76, 'v'
	22,        // 0x77, 'w'
	23,        // 0x78, 'x'
	24,        // 0x79, 'y'
	25,        // 0x7a, 'z'
	-1,        // 0x7b
	-1,        // 0x7c
	-1,        // 0x7d
	-1,        // 0x7e
	-1,        // 0x7f
};

static const int dot_index=26;
static const ntree_node_t domain_leaf={0};

#define CHAR_DOT '.'
#define NTREE_NODES_COUNT 38

#define LEAF_SIZE(size) offsetof(ntree_node_t,str[size])
#define NODE_SIZE(size) offsetof(ntree_node_t,nodes[size])
#define NODE_OFFSET(c)  ((int)chars_offset[(unsigned char)(c)])

ntree_node_t *ntree_init(void){
	ntree_node_t *root=calloc(1,NODE_SIZE(NTREE_NODES_COUNT));
	if (root!=NULL) {
		root->arr_len=NTREE_NODES_COUNT;
	}
	return root;
}

void ntree_copy_str(ntree_node_t *node,const unsigned char *s,int l){
	int i=0;
	node->str_len=l;
	do {
		l--;
		node->str[i]=s[l];
		i++;
	} while (l!=0);
}

ntree_node_t *ntree_branch_create(int size){
	ntree_node_t *node=calloc(1,NODE_SIZE(size));
	if (node!=NULL) {
		node->arr_len=size;
	}
	return node;
}

ntree_node_t *ntree_branch_expand(ntree_node_t *base,const int size){
	ntree_node_t *node=realloc(base,NODE_SIZE(size));
	if (node!=NULL) {
		for (int i=node->arr_len;i<size;i++) node->nodes[i]=NULL;
		node->arr_len=size;
	}
	return node;
}

ntree_node_t *ntree_leaf_create(const unsigned char *s,int l){
	ntree_node_t *node=malloc(LEAF_SIZE(l));
	if (node!=NULL) {
		node->arr_len=0;
		node->str_len=l;
		ntree_copy_str(node,s,l);
	}
	return node;
}

ntree_node_t *ntree_node_shrink(ntree_node_t *base,int l){
	int j=base->str_len-l;
	if (j>0) {
		for (int i=0;i<j;i++) base->str[i]=base->str[i+l];
		base->str_len=j;
	} else {
		base->str_len=0;
		j=0;
	}
	if (base->arr_len==0) base=realloc(base,LEAF_SIZE(j));
	return base;
}

ntree_node_t *ntree_node_split(ntree_node_t *base,const int l){
	int m=NODE_OFFSET(base->str[l]);
	ntree_node_t *node=ntree_branch_create(m+1);
	if (node!=NULL) {
		for (int i=0;i<l;i++) node->str[i]=base->str[i];
		node->str_len=l;
		node->nodes[m]=ntree_node_shrink(base,l+1);
	}
	return node;
}

int ntree_insert(ntree_node_t **base_ptr,const unsigned char *s,const int l){
	ntree_node_t *base=*base_ptr;
	int j=l-1,m,n=base->str_len;

	if (n) {
		ntree_node_t *node;
		int i,k,m1,m2;

		for (i=0;i<n;i++,j--) {
			if (base->str[i]!=s[j]) {
				// split current node
				m1=NODE_OFFSET(base->str[i]);
				m2=NODE_OFFSET(s[j]);
				m=m1>m2?m1:m2;
				node=ntree_branch_create(m+1);
				if (node==NULL) return -1;
				for (k=0;k<i;k++) node->str[k]=base->str[k];
				node->str_len=i;
				node->nodes[m1]=ntree_node_shrink(base,i+1);
				node->nodes[m2]=ntree_leaf_create(s,j);
				*base_ptr=node;
				return node->nodes[m2]?1:0;
			}
			if (j==0) {
				// current node string longer than name
				m=NODE_OFFSET(base->str[i]);
				if (m<dot_index) m=dot_index;
				node=ntree_branch_create(m+1);
				if (node==NULL) return -1;
				for (k=0;k<i;k++) node->str[k]=base->str[k];
				node->str_len=i;
				node->nodes[m]=ntree_node_shrink(base,i+1);
				node->nodes[dot_index]=(ntree_node_t *)&domain_leaf;
				return 1;
			}
		}
		m=NODE_OFFSET(s[j]);
		base->nodes[m]=ntree_leaf_create(s,j);
		return base->nodes[m]?1:0;
	} else {
		m=NODE_OFFSET(s[j]);
		if (base->arr_len<=m) {
			// enlarge base node
			if ((base=ntree_branch_expand(base,m+1))==NULL) return -1;
			*base_ptr=base;
		}

		if (base->nodes[m]!=NULL) {
			// travel through child node
			return ntree_insert(&base->nodes[m],s,j);
		} else {
			// create new child leaf node
			ntree_node_t *node=ntree_leaf_create(s,j);
			if (node==NULL) return -1;
			base->nodes[m]=node;
		}
	}

	return 1;
}

int ntree_add(ntree_node_t *root,const unsigned char *s){
	int l=0,m;

	// check chars, only limited chars allowed
	while (s[l]!=0) {
		if ((s[l]&0x80)||(NODE_OFFSET(s[l])<0)) return -1;
		l++;
	}
	l--;
	if (s[l]==CHAR_DOT) l--;
	m=NODE_OFFSET(s[l]);

	if (root->nodes[m]!=NULL) {
		return ntree_insert(&root->nodes[m],s,l);
	} else {
		root->nodes[m]=ntree_leaf_create(s,l);
		return root->nodes[m]!=NULL?1:-1;
	}
}

int ntree_add_n(ntree_node_t *root,const unsigned char *s,const int n){
	int l,m;

	// check chars, only limited chars allowed
	for (l=0;l<n;l++) {
		if ((s[l]&0x80)||(NODE_OFFSET(s[l])<0)) return -1;
	}
	l--;
	if (s[l]==CHAR_DOT) l--;
	m=NODE_OFFSET(s[l]);

	if (root->nodes[m]!=NULL) {
		return ntree_insert(&root->nodes[m],s,l);
	} else {
		root->nodes[m]=ntree_leaf_create(s,l);
		return root->nodes[m]!=NULL?1:-1;
	}
}

void ntree_free(ntree_node_t *root){
	ntree_node_t *node;
	for (int i=0;i<root->arr_len;i++) {
		node=root->nodes[i];
		if ((node!=NULL)&&(node!=root)&&(node!=&domain_leaf)) {
			ntree_free(root->nodes[i]);
			free(root->nodes[i]);
		}
	}
}

int ntree_search(const ntree_node_t *base,const unsigned char *s){
	int i,l,m;
	unsigned char c,buf[DNSNAMEBUFSIZE],*p;

	l=strlen(s);
	p=buf+l;
	while (*s) {
		c=*s++;
		for (i=0;i<c;i++) *--p=*s++;
		*--p=CHAR_DOT;
	}

	p=buf+1;
	while (*p) {
		i=0;
		while (i<base->str_len) {
			c=*p;
			if ((c==0)||(base->str[i]!=c)) return 0;
			i++;
			p++;
		}
		c=*p;
		if (base->arr_len==0) {
			// leaf node
			if ((c==0)||(base->str[base->str_len-1]==CHAR_DOT))
				return 1;
			else
				return 0;
		}
		// branch node
		if (c&0x80) return 0;
		m=NODE_OFFSET(c);
		if ((m<0)||(base->nodes[m]==NULL)) return 0;
		p++;
		base=base->nodes[m];
	}

	return 0;
}
