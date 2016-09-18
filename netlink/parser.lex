%{
#include <stdio.h>
#include "y.tab.h"
%}

%s NFLOGCONF

%% 

nflog			        return NFLOG;
\{              		{ BEGIN(NFLOGCONF); return OBRACE; }
<NFLOGCONF>group		return GROUP;
<NFLOGCONF>multicast_address	{ return MULTICAST; }
<NFLOGCONF>:                    return COLON;
<NFLOGCONF>interface		return INTERFACE;
<NFLOGCONF>local_address        return LOCALADDRESS;
<NFLOGCONF>payload_size         return PAYLOADSZ;
<NFLOGCONF>=			return EQUALS;
<NFLOGCONF>\}			{ BEGIN(INITIAL); return CBRACE; }
#.*				;
[\t\n ]+			;
[0-9]+			        { yylval.number=atoi(yytext); return NUMBER; }
[a-zA-Z0-9\.]+			{ yylval.string=strdup(yytext); return WORD; }
%%



