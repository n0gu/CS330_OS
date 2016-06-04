#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

void disk_read_with_cache(disk_sector_t, void *);
void disk_write_with_cache(disk_sector_t, const void *);
void cache_init(void);
void flush_cache(void);
void send_request(disk_sector_t);
#endif
