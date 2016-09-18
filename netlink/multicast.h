#ifndef _MULTICAST_H
#define _MULTICAST_H

#include "config.h"
#include "nflog_marshaller.h"
#define MULTICAST_BUFLEN 1400

int multicast_init();

int multicast_send(struct config *conf, struct nflog_log *log);
#endif
