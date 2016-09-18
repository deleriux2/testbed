#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

#include "nfc_stats.h"

inline static int stats_sanity_check(struct nfc_stats_hdr *hdr);
inline static int32_t nfc_get_country_short(const char *country);

const char *nfc_countries_short[] = {
  "A1", "A2", "O1", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AP", "AQ", "AR",
  "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
  "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA",
  "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
  "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH",
  "ER", "ES", "ET", "EU", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE",
  "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW",
  "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ",
  "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP",
  "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
  "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP",
  "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF",
  "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH",
  "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU",
  "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
  "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ",
  "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US",
  "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA",
  "ZM", "ZW", "DEFAULT", NULL
};

const char *nfc_countries_long[] = {
  "Anonymous Proxy",  "Satellite Provider",  "Other Country",  "Andorra",  
  "United Arab Emirates",  "Afghanistan", "Antigua and Barbuda",  "Anguilla"
  "Albania",  "Armenia",  "Angola",  "Asia/Pacific Region",  "Antarctica", 
  "Argentina",  "American Samoa",  "Austria",  "Australia",  "Aruba", 
  "Aland Islands",  "Azerbaijan",  "Bosnia and Herzegovina",  "Barbados", 
  "Bangladesh",  "Belgium",  "Burkina Faso",  "Bulgaria",  "Bahrain", 
  "Burundi",  "Benin",  "Saint Bartelemey",  "Bermuda",  "Brunei Darussalam", 
  "Bolivia",  "Bonaire, Saint Eustatius and Saba",  "Brazil",  "Bahamas",  
  "Bhutan",  "Bouvet Island",  "Botswana",  "Belarus",  "Belize",  "Canada", 
  "Cocos (Keeling) Islands",  "Congo, The Democratic Republic of the", 
  "Central African Republic",  "Congo",  "Switzerland",  "Cote d'Ivoire", 
  "Cook Islands",  "Chile",  "Cameroon",  "China",  "Colombia",  "Costa Rica", 
  "Cuba",  "Cape Verde",  "Curacao",  "Christmas Island",  "Cyprus",  
  "Czech Republic",  "Germany",  "Djibouti",  "Denmark",  "Dominica", 
  "Dominican Republic",  "Algeria",  "Ecuador",  "Estonia",  "Egypt", 
  "Western Sahara",  "Eritrea",  "Spain",  "Ethiopia",  "Europe",  "Finland", 
  "Fiji",  "Falkland Islands (Malvinas)",  "Micronesia, Federated States of", 
  "Faroe Islands",  "France",  "Gabon",  "United Kingdom",  "Grenada",  "Georgia", 
  "French Guiana",  "Guernsey",  "Ghana",  "Gibraltar",  "Greenland",  "Gambia", 
  "Guinea",  "Guadeloupe",  "Equatorial Guinea",  "Greece", 
  "South Georgia and the South Sandwich Islands",  "Guatemala",  "Guam", 
  "Guinea-Bissau",  "Guyana",  "Hong Kong",  "Heard Island and McDonald Islands", 
  "Honduras", "Croatia",  "Haiti",  "Hungary",  "Indonesia",  "Ireland",  "Israel", 
  "Isle of Man",  "India",  "British Indian Ocean Territory",  "Iraq", 
  "Iran, Islamic Republic of",  "Iceland",  "Italy",  "Jersey",  "Jamaica",  "Jordan", 
  "Japan",  "Kenya",  "Kyrgyzstan",  "Cambodia",  "Kiribati",  "Comoros", 
  "Saint Kitts and Nevis",  "Korea, Democratic People's Republic of",  
  "Korea, Republic of",  "Kuwait",  "Cayman Islands",  "Kazakhstan",  
  "Lao People's Democratic Republic",  "Lebanon",  "Saint Lucia",  "Liechtenstein", 
  "Sri Lanka",  "Liberia",  "Lesotho",  "Lithuania",  "Luxembourg",  "Latvia", 
  "Libyan Arab Jamahiriya",  "Morocco",  "Monaco",  "Moldova, Republic of",  
  "Montenegro",  "Saint Martin",  "Madagascar",  "Marshall Islands", 
  "Macedonia",  "Mali",  "Myanmar",  "Mongolia",  "Macao",  
  "Northern Mariana Islands",  "Martinique",  "Mauritania",  "Montserrat", 
  "Malta",  "Mauritius",  "Maldives",  "Malawi",  "Mexico",  "Malaysia", 
  "Mozambique",  "Namibia",  "New Caledonia",  "Niger",  "Norfolk Island", 
  "Nigeria",  "Nicaragua",  "Netherlands",  "Norway",  "Nepal",  "Nauru", 
  "Niue",  "New Zealand",  "Oman",  "Panama",  "Peru",  "French Polynesia", 
  "Papua New Guinea",  "Philippines",  "Pakistan",  "Poland", 
  "Saint Pierre and Miquelon",  "Pitcairn",  "Puerto Rico",  
  "Palestinian Territory",   "Portugal",  "Palau",  "Paraguay",  "Qatar", 
  "Reunion",  "Romania",  "Serbia",  "Russian Federation",  "Rwanda", 
  "Saudi Arabia",  "Solomon Islands",  "Seychelles",  "Sudan",  "Sweden", 
  "Singapore",  "Saint Helena",  "Slovenia",  "Svalbard and Jan Mayen", 
  "Slovakia",  "Sierra Leone",  "San Marino",  "Senegal",  "Somalia", 
  "Suriname",  "South Sudan",  "Sao Tome and Principe",  "El Salvador", 
  "Sint Maarten",   "Syrian Arab Republic",   "Swaziland", 
  "Turks and Caicos Islands",  "Chad",  "French Southern Territories", 
  "Togo",  "Thailand",  "Tajikistan",  "Tokelau",  "Timor-Leste", 
  "Turkmenistan",  "Tunisia",  "Tonga",  "Turkey",  "Trinidad and Tobago", 
  "Tuvalu",  "Taiwan",  "Tanzania, United Republic of",  "Ukraine", 
  "Uganda",  "United States Minor Outlying Islands",  "United States", 
  "Uruguay",  "Uzbekistan",  "Holy See (Vatican City State)", 
  "Saint Vincent and the Grenadines",  "Venezuela",  "Virgin Islands, British", 
  "Virgin Islands, U.S.",  "Vietnam",  "Vanuatu",  "Wallis and Futuna", 
  "Samoa",  "Yemen",  "Mayotte",  "South Africa",  "Zambia",  "Zimbabwe",
  "Unknown", NULL
};

inline static int32_t nfc_get_country_short(
    const char *country)
{
  const char **p;
  int i=0;
  for (p=nfc_countries_short; p != NULL; p++) {
    if (strcmp(*p, country) == 0)
      return (int32_t)i;
    i++;
  }
  return -1;
}

inline static int stats_sanity_check(
  struct nfc_stats_hdr *hdr)
{
  assert(hdr);
  if (hdr->magic != NFC_STATS_MAGIC)
    return 0;

  if (memcmp(hdr->ident, NFC_STATS_IDENT, sizeof(hdr->ident)) != 0)
    return 0;

  if (hdr->version != NFC_STATS_VERSION)
    return 0;

  return 1;
}

/* Return stats entry for group */
nfc_stats_entry_t * nfc_stats_fetch(
    nfc_stats_t *stats,
    uint16_t group,
    const char *country)
{
  int i;
  int c;
  pthread_mutex_lock(&stats->lock);
  if (stats->hdr->nentries == 0) {
    pthread_mutex_unlock(&stats->lock);
    return NULL;
  }
  for (i=0; i < stats->hdr->nentries; i++) {
    if (stats->entries[i].group == group) {
      c = nfc_get_country_short(country);
      if (c == stats->entries[i].country_code) {
        pthread_mutex_unlock(&stats->lock);
        return &stats->entries[i];
      }
    }
  }
  pthread_mutex_unlock(&stats->lock);
  return NULL;
}

/* Removes all entries and resets state of stats */
int nfc_stats_reset(
    nfc_stats_t *st)
{
  assert(st);
  assert((st->fl & NFC_STATS_RDWR) == NFC_STATS_RDWR);
  int oldlen = st->len;
  pthread_mutex_lock(&st->lock);
  st->len = sizeof(*st->hdr);
  st->hdr->nentries = 0;
  st->entries = NULL;
  st->hdr = mremap(st->hdr, oldlen, st->len, MREMAP_MAYMOVE);
  if (st->hdr == MAP_FAILED) {
    pthread_mutex_unlock(&st->lock);
    return -1;
  }
  if (ftruncate(st->fd, st->len) < 0) {
    pthread_mutex_unlock(&st->lock);
    return -1;
  }
  pthread_mutex_unlock(&st->lock);
  return 0;
}

/* Adds a group to the stats */
int nfc_stats_add_group(
    nfc_stats_t *st, 
    uint16_t group, 
    const char *country, 
    int32_t verdict)
{
  assert(st);
  assert((st->fl & NFC_STATS_RDWR) == NFC_STATS_RDWR);

  int newlen = 0;
  int32_t hack;
  int c = -1;
  void *p = NULL;
  nfc_stats_entry_t *e;

  pthread_mutex_lock(&st->lock);

  newlen = st->len + sizeof(nfc_stats_entry_t);

  /* Fail if already exists */
  e = nfc_stats_fetch(st, group, country);
  if (e) {
    errno = EEXIST;
    goto fail;
  }
  
  /* Adjust the size of the file, remap data */
  if (ftruncate(st->fd, newlen) < 0)
    goto fail;
  p = mremap(st->hdr, st->len, newlen, MREMAP_MAYMOVE);
  if (st->hdr == MAP_FAILED)
    goto fail;
  /* Adjust entries pointer */
  st->entries = (nfc_stats_entry_t *)&st->hdr[1];

  e = &st->entries[st->hdr->nentries];
  e->group = group;
  if ((c = nfc_get_country_short(country)) < 0)
    c = nfc_get_country_short("DEFAULT");
  e->country_code = c;
  e->verdict = verdict;
  e->count = 0;
  st->hdr->nentries++;
  st->len = newlen;
 
  pthread_mutex_unlock(&st->lock);
  return 1;

fail:
  pthread_mutex_unlock(&st->lock);
  return 0;
}

/* Close the entry */
void nfc_stats_close(
    nfc_stats_t *st)
{
  if (!st)
    return;
  st->hdr->pid = 0;
  close(st->fd);
  munmap(st->hdr, st->len);
  pthread_mutex_destroy(&st->lock);
  free(st);
  return;
}

/* Fetches the counter */
int64_t nfc_stats_get_count(
    nfc_stats_t *st, uint16_t group, 
    const char *country)
{
  int64_t res;
  nfc_stats_entry_t *e = NULL;
  pthread_mutex_lock(&st->lock);

  e = nfc_stats_fetch(st, group, country);
  if (!e)
    goto fail;
  
  res = e->count;
  pthread_mutex_unlock(&st->lock);
  return res;

fail:
  pthread_mutex_unlock(&st->lock);
  return -1;
}

/* Adds 1 to the counter */
int64_t nfc_stats_inc_count(nfc_stats_t *st,
    uint16_t group,
    const char *country)
{
  int64_t res;
  nfc_stats_entry_t *e = NULL;
  pthread_mutex_lock(&st->lock);

  e = nfc_stats_fetch(st, group, country);
  if (!e)
    goto fail;
  
  e->count++;
  res = e->count;
  pthread_mutex_unlock(&st->lock);
  return res;

fail:
  pthread_mutex_unlock(&st->lock);
  return -1;
}

/* Retrieves the next country from the list */
const char *nfc_stats_get_next_country(
    nfc_stats_t *st)
{
  int i;
  nfc_stats_entry_t *e = NULL;
  pthread_mutex_lock(&st->lock);
  for (i=st->search.cpg->pos; i < st->hdr->nentries; i++) {
    e = &st->entries[i];
    if (e->group == st->search.cpg->group) {
      st->search.cpg->pos = (i+1);
      pthread_mutex_unlock(&st->lock);
      return nfc_countries_short[e->country_code]; 
    }
  }
  return NULL;
  pthread_mutex_unlock(&st->lock);
}

/* Retrieves each country per group */
const char *nfc_stats_get_countries_per_group(
    nfc_stats_t *st, 
    uint16_t group)
{
  pthread_mutex_lock(&st->lock);
  if (st->search.cpg)
    free(st->search.cpg);
  st->search.cpg = malloc(sizeof(nfc_countries_per_group_t));
  if (!st->search.cpg) {
    pthread_mutex_unlock(&st->lock);
    return NULL;
  }
  st->search.cpg->pos = 0;
  st->search.cpg->group = group;

  pthread_mutex_unlock(&st->lock);
  return nfc_stats_get_next_country(st); 
}

uint16_t nfc_stats_get_next_group(
   nfc_stats_t *st)
{
  uint16_t candidate_ent = USHRT_MAX;
  nfc_stats_entry_t *e;
  int i;
  pthread_mutex_lock(&st->lock);
  for (i=0; i < st->hdr->nentries; i++) {
    e = &st->entries[i];
    if (e->group > st->search.grp->group && e->group < candidate_ent) {
      candidate_ent = e->group;
    }
  }
  st->search.grp->group = candidate_ent;
  
  pthread_mutex_unlock(&st->lock);
  return candidate_ent;
}

uint16_t nfc_stats_get_all_groups(
    nfc_stats_t *st)
{
  int i;
  nfc_stats_entry_t *e;
  pthread_mutex_lock(&st->lock);
  if (st->search.grp)
    free(st->search.grp);
  st->search.grp = malloc(sizeof(nfc_groups_t));
  if (!st->search.grp) {
    pthread_mutex_unlock(&st->lock);
    return USHRT_MAX;
  }
  st->search.grp->group = USHRT_MAX;
  /* Find the group with the lowest number */
  for (i=0; i < st->hdr->nentries; i++) {
    e = &st->entries[i];
    if (e->group < st->search.grp->group)
      st->search.grp->group = e->group;
  }
  pthread_mutex_unlock(&st->lock);
  return st->search.grp->group;
}

/* Retrieves verdict */
int32_t nfc_stats_get_verdict(
    nfc_stats_t *st,
    uint16_t group,
    const char *country)
{
  int32_t res;
  nfc_stats_entry_t *e = NULL;
  pthread_mutex_lock(&st->lock);

  e = nfc_stats_fetch(st, group, country);
  if (!e)
    goto fail;
  
  res = e->verdict;
  pthread_mutex_unlock(&st->lock);
  return res;

fail:
  pthread_mutex_unlock(&st->lock);
  return -1;
}


/* Opens the stats file. Checks validity.
 * Allows creation if defined */
nfc_stats_t * nfc_stats_open(
    const char *path, 
    int flags)
{
  nfc_stats_t *stats = NULL;
  int fl = 0; /* open flags */
  int ma = 0; /* map flags */
  int e;
  pthread_mutexattr_t attr;

  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

  stats = malloc(sizeof(nfc_stats_t));
  if (!stats)
    goto fail;
  memset(stats, 0, sizeof(nfc_stats_t));
  stats->fd = -1;
  stats->len = 0;

  /* Fetch open mode */
  if ((flags & NFC_STATS_RDONLY) == NFC_STATS_RDONLY) {
    fl |= O_RDONLY;
    ma |= PROT_READ;
  }
  if ((flags & NFC_STATS_RDWR) == NFC_STATS_RDWR) {
    fl |= O_RDWR;
    ma |= PROT_READ|PROT_WRITE;
  }
  if ((flags & NFC_STATS_CREAT) == NFC_STATS_CREAT) {
    fl |= O_RDWR|O_CREAT|O_EXCL;
    ma |= PROT_READ|PROT_WRITE;
  }
  stats->fl = fl;

  /* We are making a new file. Unlink the old one, may not exist */
  /* Better to unlink than truncate. Truncate might invoke SIGBUS! */
  if ((flags & NFC_STATS_CREAT) == NFC_STATS_CREAT) {
    unlink(path);
    errno = 0;
  }

  /* Initialize the lock */
  pthread_mutex_init(&stats->lock, &attr);

  stats->fd = open(path, fl, 0600);
  if (stats->fd < 0)
    goto fail;

  /* In this case we must create a new file, just make header */
  if ((flags & NFC_STATS_CREAT) == NFC_STATS_CREAT) {
    if (ftruncate(stats->fd, sizeof(*stats->hdr)) < 0)
      goto fail;
    stats->len = sizeof(*stats->hdr);
    stats->hdr = mmap(NULL, stats->len, ma, MAP_SHARED, stats->fd, 0);
    if (stats->hdr == MAP_FAILED)
      goto fail;
    /* Define the header */
    stats->hdr->magic = NFC_STATS_MAGIC;
    memcpy(stats->hdr->ident, NFC_STATS_IDENT, sizeof(stats->hdr->ident));
    stats->hdr->version = NFC_STATS_VERSION;
    stats->hdr->nentries = 0;
  }
  else {
    stats->len = sizeof(*stats->hdr);
    stats->hdr = mmap(NULL, stats->len, ma, MAP_SHARED, stats->fd, 0);
    if (stats->hdr == MAP_FAILED)
      goto fail;
    /* Validate the header */
    if (!stats_sanity_check(stats->hdr))
      goto fail;
  }

  /* Update pid */
  if ((stats->fl & O_RDWR) == O_RDWR)
    stats->hdr->pid = getpid();
  else {
    if (kill(stats->hdr->pid, 0) < 0)
      if (errno == ESRCH) {
        fprintf(stderr, "WARNING: nfcountry is not running\n");
        errno = 0;
      }
      else {
        goto fail;
      }
  }

  /* Now, we remap the stats file based off of the
    stats entries we have */
  stats->hdr = mremap(
                 stats->hdr, stats->len, 
                 stats->len+(sizeof(*stats->entries) * stats->hdr->nentries),
                 MREMAP_MAYMOVE);
  if (stats->hdr == MAP_FAILED)
    goto fail;
  stats->entries = (nfc_stats_entry_t *)&stats->hdr[1];
  stats->len = stats->len+(sizeof(*stats->entries) * stats->hdr->nentries);
  stats->search.grp = NULL;

  return stats;

fail:
  e = errno;
  if (stats) {
    close(stats->fd);
    munmap(stats->hdr, stats->len);
    pthread_mutex_destroy(&stats->lock);
    free(stats);
  }
  errno = e;
  return NULL;
}

