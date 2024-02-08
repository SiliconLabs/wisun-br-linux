#ifndef RPL_STORAGE_H
#define RPL_STORAGE_H

struct rpl_root;
struct rpl_target;

/*
 * Functions for (re)storing RPL data from/to Non-Volatile Memory (NVM).
 * A file is created per target, containing transits with the relevant data.
 */

void rpl_storage_store_config(const struct rpl_root *root);
void rpl_storage_store_target(const struct rpl_root *root, const struct rpl_target *target);
void rpl_storage_del_target(const struct rpl_root *root, const struct rpl_target *target);

void rpl_storage_load_config(struct rpl_root *root, const char *filename);
void rpl_storage_load_target(struct rpl_root *root, const char *filename);
void rpl_storage_load(struct rpl_root *root);

#endif /* RPL_STORAGE_H */
