#include "common.h"
#include "ndmp_common.h"

/* TODO
Add a parser and get rid of the environ crap. (application specific)

Add an API so you can feed environ arguments to the API without having to use
the ndmp_env primitives.

*/

#define HOST "192.168.122.53"
//#define HOST "nosuchdomainxxxxyyyyy.com"

int main() {
   char buf[128];
   int i;
   ndmp_server_info info;
   memset(&info, 0, sizeof(info));
   ndmp_session *sess = ndmp_init_session();
   if (!sess) {
      perror("Unable to initialize ndmp session");
      exit(1);   
   }

   /* Connect to ndmp data server */
   if (!ndmp_connect(sess, HOST, "10000", "matthew", "abc123"))
     goto fail;

   /* Create the mover system */
   if (!ndmp_mover_create(sess, "192.168.122.1", "10001"))
     goto fail;

   //ON_FALSE(fail, ndmp_backup(sess, "192.168.122.1", "10001"));
   
   /* Get some server info */
   if (!ndmp_get_server_info(sess, &info))
     goto fail;

   if (!ndmp_get_fsinfo(sess))
      goto fail;

   if (!ndmp_get_buinfo(sess))
      goto fail;

   printf("Server information: \n");
   printf(" Vendor Name: %s\n Product Name: %s\n Revision Number: %s\n",
            info.vendor_name, info.product_name, info.revision_number);

   printf("\n");
   printf("Filesystems available to backup:\n");
   printf("----------------------------------------"
          "----------------------------------------\n");
   printf("%-4s%-32s%-32s%-8s\n", "Id", "Name", "Mountpoint", "Filesystem Type");
   printf("----------------------------------------"
          "----------------------------------------\n");
   for (i=0; i < sess->fs_len; i++) {
      printf("%-4d%-32s%-32s%-8s\n", i, sess->fs[i].device, sess->fs[i].mountpoint, sess->fs[i].fstype);
   }

   printf("\n");
   printf("Backup systems available:\n");
   printf("----------------------------------------"
          "----------------------------------------\n");
   printf("%-4s%-32s\n", "Id", "Name");
   printf("----------------------------------------"
          "----------------------------------------\n");
   for (i=0; i < sess->bu_len; i++) {
      printf("%-4d%-32s\n", i, sess->bu[i].name);
   }
   printf("\n");

   ndmp_disconnect(sess);
   ndmp_free_session(sess);

   exit(0);
fail:
   printf("failure\n");
   memset(buf, 0, sizeof(buf));
   ndmp_print_error(sess, buf, sizeof(buf));
   fprintf(stderr, "%s\n", buf);
   exit(1);
}
