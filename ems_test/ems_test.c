#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define WAF_ALERT_STRING "GET /cmd.exe HTTP/1.0\r\n\r\n"
#define WAF_ALERT_MATCH "This request has been blocked by website protection from Armor."
#define HOSTNAME "qa.partners.heroesinprevention.com"
#define PORT "443"
#define BUNDLE_PATH "/etc/ssl/certs/ca-bundle.crt"
#define WAF_CIPHER_PRIORITY "NORMAL:!DHE-RSA:!DHE-DSS:!ECDHE-RSA:!ANON-ECDH:!ANON-DH"
//#define WAF_CIPHER_PRIORITY "NORMAL"

gnutls_certificate_credentials_t cred = NULL;

static int make_tcp_connect(
   const char *host,
   const char *port)
{
  int rc;
  int fd = -1;
  struct addrinfo *ai = NULL;

  /* Attempt to resolve DNS */
  rc = getaddrinfo(host, port, NULL, &ai);
  if (rc != 0)
    errx(EXIT_FAILURE, "Unable to resolve hostname: %s: %s", host, gai_strerror(rc));

  /* Create the socket */
  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0)
    err(EXIT_FAILURE, "Unable to create socket");
  /* Disable NAGLE */
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &rc, sizeof(rc)) < 0)
    err(EXIT_FAILURE, "Cannot disable NAGLE on socket");
  /* Connect to the path */
  if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EXIT_FAILURE, "Cannot connect to %s", host);

  freeaddrinfo(ai);
  return fd;
}

void gnutls_load_cas(
    void)
{
  int rc;

  /* Load the Root CA list */
  rc = gnutls_certificate_allocate_credentials(&cred);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Initializing certificate list failed: %s\n", gnutls_strerror(rc));
  rc = gnutls_certificate_set_x509_trust_file(cred, BUNDLE_PATH, GNUTLS_X509_FMT_PEM);
  if (rc == 0) 
    errx(EXIT_FAILURE, "No root certificates found in: %s\n", BUNDLE_PATH);
  else if (rc < 0)
    errx(EXIT_FAILURE, "Loading root certificates failed: %s: %s\n", BUNDLE_PATH, gnutls_strerror(rc));
}

static gnutls_session_t gnutls_create_session(
    char *host,
    char *port,
    char *priorities)
{
  const char *p = NULL;
  int rc;
  int fd = -1;
  gnutls_session_t session;

  fd = make_tcp_connect(host, port);

  /* Create a session object */
  rc = gnutls_init(&session, GNUTLS_CLIENT);
  if (rc !=  GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "GNUTLS Initialization: %s", gnutls_strerror(rc));

  /* Set the priorities */
  rc = gnutls_priority_set_direct(session, priorities, &p);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "GNUTLS cipher selection failure at %s: %s", p, gnutls_strerror(rc));

  /* Load the Root CA list */
  rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

  /* Associate this connection with GNUTLS */
  gnutls_transport_set_int(session, fd);

  /* Setup SNI */
  rc = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Unable to setup SNI on hostname: %s: %s", host, gnutls_strerror(rc));

  /* Perform handshake */
  rc = gnutls_handshake(session);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "TLS handshake failure: %s", gnutls_strerror(rc));

  return session;
}

static void gnutls_session_destroy(
    gnutls_session_t session)
{
  /* IIS doesnt close properly so use SHUT_WR only */
  gnutls_bye(session, GNUTLS_SHUT_WR);
  close(gnutls_transport_get_int(session));
}

int main(
   const int argc,
   char **argv)
{
  int rc;
  int fd = -1;
  char priority[512];
  char buffer[8192];
  gnutls_session_t session;
  gnutls_certificate_credentials_t cred = NULL;

  memset(priority, 0, sizeof(priority));
  memset(buffer, 0, sizeof(buffer));

  /* Initialize library and load CAs */
  gnutls_global_init();
  gnutls_load_cas();

  /* Check the version of this library */
  if (gnutls_check_version("3.4.7") == NULL)
    errx(EXIT_FAILURE, "You must be using a version of GNUTLS of at least 3.4.7 but the version listed is too old");

  if (argc < 2)
    errx(EXIT_FAILURE, "You must pass in a valid hostname");

  /* Load the cipher string into the priority buffer */ 
  strncpy(priority, WAF_CIPHER_PRIORITY, sizeof(WAF_CIPHER_PRIORITY));
  strcat(priority, ":%NO_SESSION_HASH");

  session = gnutls_create_session(argv[1], PORT, priority);

  /* The first test involves checking that the WAF actually works in normal mode.. */

  printf("Checking if WAF support is enabled for this website                      ... ");
  fflush(stdout);

  /* Test to see whether we are using extended message secrets */
  rc = gnutls_session_ext_master_secret_status(session);
  if (rc != 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Extended master secret is enabled on the destination server yet we asked for it not to be!");
  }

  /* Attempt to emit a WAF alert */
  rc = gnutls_record_send(session, WAF_ALERT_STRING, strlen(WAF_ALERT_STRING)); 
  if (rc < 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Cannot send data over socket: %s", gnutls_strerror(rc));
  }

  rc = gnutls_record_recv(session, buffer, sizeof(buffer));
  if (rc < 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Cannot receive data over socket: %s", gnutls_strerror(rc));
  }

  gnutls_session_destroy(session);

  if (strstr(buffer, WAF_ALERT_MATCH))
    printf("Yes\n");
  else {
    printf("No\n");
    errx(EXIT_FAILURE, "As WAF support is not yet enabled, this test is now aborting.");
  }

  /* The next test checks to see if WAF support works when EMS is enabled. */
  memset(priority, 0, sizeof(priority));
  strcpy(priority, WAF_CIPHER_PRIORITY);

  session = gnutls_create_session(argv[1], PORT, priority);

  printf("Checking if WAF support is enabled with extended master secret turned on ... ");
  fflush(stdout);

  /* Test to see whether we are using extended master secrets */
  rc = gnutls_session_ext_master_secret_status(session);
  if (rc == 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Extended master secret extension is not enabled on this server.");
  }

  /* Attempt to emit a WAF alert */
  rc = gnutls_record_send(session, WAF_ALERT_STRING, strlen(WAF_ALERT_STRING));
  if (rc < 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Cannot send data over socket: %s", gnutls_strerror(rc));
  }

  rc = gnutls_record_recv(session, buffer, sizeof(buffer));
  if (rc < 0) {
    printf("No\n");
    errx(EXIT_FAILURE, "Cannot receive data over socket: %s", gnutls_strerror(rc));
  }

  gnutls_session_destroy(session);

  if (strstr(buffer, WAF_ALERT_MATCH) == NULL) {
    printf("Yes\n");
  }
  else {
    printf("No\n");
    errx(EXIT_FAILURE, "The WAF was unable to match on this block request.");
  }

  exit(0);
}
