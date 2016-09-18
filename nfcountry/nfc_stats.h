#ifndef _NFC_STATS_H
#define _NFC_STATS_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

#define NFC_STATS_MAGIC 0x0804
#define NFC_STATS_VERSION1  0x0010
#define NFC_STATS_VERSION NFC_STATS_VERSION1
#define NFC_STATS_IDENT "nfcstats"
#define NFC_STATS_RDONLY 0
#define NFC_STATS_RDWR   2
#define NFC_STATS_CREAT  4

#define NFC_STATS_PATH "/tmp/nfcstats.h"

typedef enum {
  A1, A2, O1, AD, AE, AF, AG, AI, AL, AM, AO, AP, AQ, AR, AS, AT, AU, AW, AX,
  AZ, BA, BB, BD, BE, BF, BG, BH, BI, BJ, BL, BM, BN, BO, BQ, BR, BS, BT, BV,
  BW, BY, BZ, CA, CC, CD, CF, CG, CH, CI, CK, CL, CM, CN, CO, CR, CU, CV, CW,
  CX, CY, CZ, DE, DJ, DK, DM, DO, DZ, EC, EE, EG, EH, ER, ES, ET, EU, FI, FJ,
  FK, FM, FO, FR, GA, GB, GD, GE, GF, GG, GH, GI, GL, GM, GN, GP, GQ, GR, GS,
  GT, GU, GW, GY, HK, HM, HN, HR, HT, HU, ID, IE, IL, IM, IN, IO, IQ, IR, IS,
  IT, JE, JM, JO, JP, KE, KG, KH, KI, KM, KN, KP, KR, KW, KY, KZ, LA, LB, LC,
  LI, LK, LR, LS, LT, LU, LV, LY, MA, MC, MD, ME, MF, MG, MH, MK, ML, MM, MN,
  MO, MP, MQ, MR, MS, MT, MU, MV, MW, MX, MY, MZ, NA, NC, NE, NF, NG, NI, NL,
  NO, NP, NR, NU, NZ, OM, PA, PE, PF, PG, PH, PK, PL, PM, PN, PR, PS, PT, PW,
  PY, QA, RE, RO, RS, RU, RW, SA, SB, SC, SD, SE, SG, SH, SI, SJ, SK, SL, SM,
  SN, SO, SR, SS, ST, SV, SX, SY, SZ, TC, TD, TF, TG, TH, TJ, TK, TL, TM, TN,
  TO, TR, TT, TV, TW, TZ, UA, UG, UM, US, UY, UZ, VA, VC, VE, VG, VI, VN, VU,
  WF, WS, YE, YT, ZA, ZM, ZW, DEFAULT
} nfc_country_codes;

typedef struct nfc_countries_per_group {
  int ccode;
  uint16_t group;
  int pos;
} nfc_countries_per_group_t;

typedef struct nfc_groups {
  uint16_t group;
} nfc_groups_t;

typedef struct nfc_stats_entry {
  uint16_t group;
  int32_t country_code;
  int32_t verdict;
  int64_t count;
} nfc_stats_entry_t;

struct nfc_stats_hdr {
  uint16_t magic;
  char ident[8];
  uint16_t version;
  uint32_t nentries;
  pid_t pid;
};

typedef struct nfc_stats {
  int fd;
  int len;
  int fl;
  struct {
    nfc_countries_per_group_t *cpg;
    nfc_groups_t *grp;
  } search;
  pthread_mutex_t lock;
  struct nfc_stats_hdr *hdr;
  nfc_stats_entry_t *entries;
} nfc_stats_t;

nfc_stats_t * nfc_stats_open(const char *path,int flags);
int nfc_stats_add_group(nfc_stats_t *st, uint16_t group, const char *country, int32_t verdict);
int nfc_stats_reset(nfc_stats_t *st);
nfc_stats_entry_t * nfc_stats_fetch(nfc_stats_t *stats, uint16_t group, const char *country);
int64_t nfc_stats_get_count(nfc_stats_t *st, uint16_t group, const char *country);
int64_t nfc_stats_inc_count(nfc_stats_t *st, uint16_t group, const char *country);
int32_t nfc_stats_get_verdict(nfc_stats_t *st, uint16_t group, const char *country);
const char *nfc_stats_get_countries_per_group(nfc_stats_t *st, uint16_t group);
const char *nfc_stats_get_next_country(nfc_stats_t *st);
uint16_t nfc_stats_get_all_groups(nfc_stats_t *st);
uint16_t nfc_stats_get_next_group(nfc_stats_t *st);
void nfc_stats_close(nfc_stats_t *st);


#endif

