#define WORD 257
#define NUMBER 258
#define NFLOG 259
#define OBRACE 260
#define CBRACE 261
#define GROUP 262
#define EQUALS 263
#define COLON 264
#define LOCALADDRESS 265
#define MULTICAST 266
#define INTERFACE 267
#define PAYLOAD 268
#define PAYLOADSZ 269
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
  int number;
  char *string;
  char boolean;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
extern YYSTYPE yylval;
