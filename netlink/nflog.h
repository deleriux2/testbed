#ifndef _NFLOG_H_
#define _NFLOG_H_

#include "nflog_marshaller.h"

#define NFLOG_GROUPS_MAX 1024

void nflog_destroy(void);
int nflog_recv(void *data);
int nflog_start(void);
#endif
