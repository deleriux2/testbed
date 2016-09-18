#include "config.h"
#include "license.h"
#include "page.h"
#include "index.h"

static int read_license_header(license_t *license);
static int write_license_header(license_t *license);
static license_page_t * license_get_page(license_t *license);


static int read_license_header(
    license_t *license)
{
  assert(license);
  assert(license->map);

  struct iovec vecs[1];
  int64_t pageno;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);

  if (preadv(license->map->fd, vecs, 1, LICENSE_HDR_OFFSET) < 0)
    return 0;

  license->offset = pageno;
  return 1;
}


static int write_license_header(
    license_t *license)
{
  assert(license);
  assert(license->map);
  assert(license->offset >= 0);

  struct iovec vecs[1];

  int64_t pageno = license->offset;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);

  if (pwritev(license->map->fd, vecs, 1, LICENSE_HDR_OFFSET) < 0)
    return 0;

  return 1;
}


static license_page_t * license_get_page(
    license_t *license)
{
  assert(license);
  assert(license->map);
  assert(license->offset >= 0);
  assert(license->index);

  license_page_t *lpage;
  int64_t offset;

  offset = index_lookup(license->index, license->offset);
  if (offset < 0)
    return NULL;

  lpage = page_get_data_of(license->map, offset, BBDB_MAGIC_LICENSE);
  if (!lpage)
    return NULL;

  return lpage;
}





/* Set the permitted flow of the license */
int license_flow_set(
    license_t *license,
    uint16_t flow)
{
  assert(license);

  license_page_t *lpage;
  uint16_t tflow = 0;

  flow &= (LICENSE_MODE_IN|LICENSE_MODE_OUT
          |LICENSE_MODE_FWDIN|LICENSE_MODE_FWDOUT);

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  lpage->mode |= flow;
  return 1;
}



/* Set the aux flag */
int license_aux_set(
    license_t *license,
    char truth)
{
  assert(license);

  license_page_t *lpage;
  uint16_t tflow = 0;
  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  if (truth)
    lpage->mode |= LICENSE_MODE_AUX;
  else
    lpage->mode &= ~LICENSE_MODE_AUX;
  return 1;
}




/* Retrieve the flow */
uint16_t license_flow_get(
    license_t *license)
{
  assert(license);

  license_page_t *lpage;
  uint16_t flow;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  flow = lpage->mode;
  flow &= (LICENSE_MODE_IN|LICENSE_MODE_OUT
          |LICENSE_MODE_FWDIN|LICENSE_MODE_FWDOUT);
  return flow;
}






/* Get the aux flag */
char license_aux_get(
    license_t *license)
{
  assert(license);

  license_page_t *lpage;
  uint16_t aux;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  aux = lpage->mode;
  aux &= LICENSE_MODE_AUX;
  if (aux)
    return true;
  else
    return false;
}





/* Set the identification in the license */
int license_identification_set(
    license_t *license,
    char *identification)
{
  assert(license);
  assert(identification);

  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  strncpy(lpage->identification, identification, 63);
  lpage->mode |= LICENSE_MODE_ID|LICENSE_MODE_IN;
  return 1;
}



/* Retrieve the identification in the license */
int license_identification_get(
    license_t *license,
    char *identification,
    int size)
{
  assert(license);
  assert(identification);
  assert(size > 0);

  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  strncpy(identification, lpage->identification, size);
  return 1;
}



/* Set the expiry of the database */
int license_expiry_set(
    license_t *license,
    uint32_t expiry)
{
  assert(license);

  uint32_t now = time(NULL);

  if ((now+3600) > expiry)
    return 0;

  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  lpage->expiry = expiry;
  lpage->mode |= LICENSE_MODE_TIME|LICENSE_MODE_IN;
  return 1;
}




/* Get the expiry of the database */
uint32_t license_expiry_get(
    license_t *license)
{
  assert(license);

  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  return lpage->expiry;
}




/* Set the uid of the database */
int license_uid_set(
    license_t *license,
    uint32_t uid)
{
  assert(license);


  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  lpage->uid = uid;
  return 1;
}




/* Get the uid of the database */
uint32_t license_uid_get(
    license_t *license)
{
  assert(license);

  license_page_t *lpage;

  lpage = license_get_page(license);
  if (!lpage)
    return 0;

  return lpage->uid;
}




/* Get the IP addresses in the license */
int license_ip_get(
    license_t *license,
    ipnet_t **ips,
    int *size)
{
  assert(license);
  assert(*ips == NULL);
  assert(size);

  license_page_t *lpage;
  ipnet_t *ipnets_ptr;
  ipnet_t *ipnets;

  lpage = license_get_page(license);
  if (!lpage)
    return -1;

  if (lpage->ipsize < 0) {
    errno = EINVAL;
    return -1;
  }
  else if (lpage->ipsize == 0) {
    *size = 0;
    return 0;
  }

  ipnets = calloc(lpage->ipsize, sizeof(ipnet_t));
  if (!ipnets)
    return -1;

  ipnets_ptr = (void *)lpage + (sizeof(license_page_t));
  memcpy(ipnets, ipnets_ptr, lpage->ipsize * sizeof(ipnet_t));
  *ips = ipnets;
  *size = lpage->ipsize;
  return 1; 
}



/* Add an IP address onto the list */
int license_ip_add(
    license_t *license,
    char *ip_addr,
    char mask)
{
  assert(license);
  assert(ip_addr);
  assert(mask >= 8 && mask <= 32);

  license_page_t *lpage;
  ipnet_t *ipnets_ptr;

  lpage = license_get_page(license);
  if (!lpage)
    return -1;

  ipnets_ptr = (void *)lpage + (sizeof(license_page_t));
  ipnets_ptr += lpage->ipsize;

  if (!inet_pton(AF_INET, ip_addr, &ipnets_ptr->addr))
    return 0;
  ipnets_ptr->mask = mask;
  lpage->ipsize++;

  lpage->mode |= LICENSE_MODE_IN|LICENSE_MODE_IP;

  return 1;
}


/* Retrieve existing license */
license_t * license_open(
    pagemap_t *map,
    index_t *index)
{
  assert(map);
  assert(index);

  license_t *license;
  page_t *page;

  license = malloc(sizeof(license_t));
  if (!license)
    goto fail;

  /* Initialize */
  license->map = map;
  license->index = index;

  /* Read the header */
  if (!read_license_header(license))
    goto fail;

  return license;

fail:
  if (license)
    free(license);

  return NULL;  
}



/* Make a new license */
license_t * license_new(
    pagemap_t *map,
    index_t *index)
{
  assert(map);
  assert(index);

  license_t *license;
  page_t *page;

  license = malloc(sizeof(license_t));
  if (!license)
    goto fail;

  /* Initialize */
  license->map = map;
  license->index = index;

  /* Initialize the page */
  page = page_init(license->map, BBDB_MAGIC_LICENSE);
  if (!page)
    goto fail;

  license->offset = page_get_offset(map, page);

  if (!index_add(index, page))
    goto fail;

  /* Write out the header */
  if (!write_license_header(license))
    goto fail;

  return license;

fail:
  if (license)
    free(license);

  return NULL;  
}



void license_close(
    license_t *license)
{
  if (license)
    free(license);
}
