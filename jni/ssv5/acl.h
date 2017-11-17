
#ifndef _ACL_H
#define _ACL_H

#define BLACK_LIST 0
#define WHITE_LIST 1

int init_acl(const char *path, int mode);
void free_acl(void);

int acl_get_mode(void);
int acl_match_ip(const char *ip);
int acl_add_ip(const char *ip);
int acl_remove_ip(const char *ip);

#endif // _ACL_H
