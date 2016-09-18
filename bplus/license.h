#ifndef _LICENSE_H
#define _LICENSE_H

#include "config.h"
#include "page.h"
#include "index.h"

#define LICENSE_MODE_NONE   0x00
/* Only work where the systems UUID matches the given UUID */
#define LICENSE_MODE_ID     0x01
/* Only check for a given list of IP networks */
#define LICENSE_MODE_IP     0x02
/* Enforce a expiry time */
#define LICENSE_MODE_TIME   0x04
/* Enforce softare to work only in certain directions */
#define LICENSE_MODE_IN     0x08
#define LICENSE_MODE_OUT    0x10
#define LICENSE_MODE_FWDIN  0x20
#define LICENSE_MODE_FWDOUT 0x40
/* Open an auxiillary port to permit out-of-band queries */
#define LICENSE_MODE_AUX    0x80

#define LICENSE_ID_SZ 64
#define LICENSE_PAGE_SIZE 12

typedef struct ipnet {
  /* The IP address */
  uint32_t addr;
  /* Any network mask restrictions on the address */
  uint8_t mask; 
} ipnet_t;

#define LICENSE_MAX_IPS \
    ((PAGESIZE - LICENSE_PAGE_SIZE) / sizeof(ipnet_t))

typedef struct license_page {
  /* Contains the license check mode */
  uint16_t mode;
  /* Typically stores the system UUID */
  uint8_t identification[LICENSE_ID_SZ];
  /* An arbitrary ID, possibly a customer ID */
  uint32_t uid;
  /* A timeout by which this database becomes invalid */
  uint32_t expiry;
  /* The number of IP addresses in the license */
  uint32_t ipsize;
  ipnet_t ips[LICENSE_MAX_IPS];
} license_page_t;


typedef struct licence {
  uint64_t offset;
  pagemap_t *map;
  index_t *index;
} license_t;


license_t * license_new(pagemap_t *map, index_t *index);
license_t * license_open(pagemap_t *map, index_t *index);
void license_close(license_t *license);
int license_ip_add(license_t *license, char *ip, char mask);
int license_uid_set(license_t *license, uint32_t uid);
int license_aux_set(license_t *license, char truth);
int license_flow_set(license_t *license, uint16_t flow);
int license_expiry_set(license_t *license, uint32_t expiry);
int license_identification_set(license_t *license, char *buf);
uint32_t license_uid_get(license_t *license);
uint16_t license_flow_get(license_t *license);
char license_aux_get(license_t *license);
uint32_t license_expiry_get(license_t *license);
int license_identification_get(license_t *license, char *buf, int sz);
int license_ip_get(license_t *license, ipnet_t **set, int *sz);
#endif
