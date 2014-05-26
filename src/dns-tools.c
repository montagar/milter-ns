/*
 * DNS_TOOLS - Some tools for getting DNS information.
 */
/*
 * The following code was lifted almost verbatim from the diablotin.com site.
 * A few minor changes where made, i.e. remove exit() and replace with return().
 */
/****************************************************************
 * addNameServers -- Look at the resource records from a        *
 *     section.  Save the names of all name servers.            *
 ****************************************************************/
#include	"../config.h"
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<memory.h>
#include	<strings.h>
#include	<sys/types.h>
#include	<sysexits.h>
#include	<netinet/in.h>
#include	<netdb.h>
#include	<arpa/nameser.h>
#include	<resolv.h>
#include	<libmilter/mfapi.h>
#include	<syslog.h>
#include	<pthread.h>


void
addNameServers(nsList, nsNum, handle, section)
char *nsList[];
int  *nsNum;
ns_msg handle;
ns_sect section;
{
    int rrnum;  /* resource record number */
    ns_rr rr;   /* expanded resource record */

    int i, dup; /* misc variables */

    /*
     * Look at all the resource records in this section.
     */
    for(rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++)
    {
        /*
         * Expand the resource record number rrnum into rr.
         */
        if (ns_parserr(&handle, section, rrnum, &rr)) {
            fprintf(stderr, "ns_parserr: %s\n", strerror(errno));
        }

        /*
         * If the record type is NS, save the name of the
         * name server.
         */
        if (ns_rr_type(rr) == ns_t_ns) {

            /*
             * Allocate storage for the name.  Like any good
             * programmer should, we test malloc's return value,
             * and quit if it fails.
             */
            nsList[*nsNum] = (char *) malloc (MAXDNAME);
            if(nsList[*nsNum] == NULL){
                (void) fprintf(stderr, "malloc failed\n");
                return ;
            }

            /* Expand the name server's name */
            if (ns_name_uncompress(
                        ns_msg_base(handle),/* Start of the packet   */
                        ns_msg_end(handle), /* End of the packet     */
                        ns_rr_rdata(rr),    /* Position in the packet*/
                        nsList[*nsNum],     /* Result                */
                        MAXDNAME)           /* Size of nsList buffer */
                                  < 0) {    /* Negative: error       */
                (void) fprintf(stderr, "ns_name_uncompress failed\n");
                return ;
            }

            /*
             * Check the name we've just unpacked and add it to
             * the list of servers if it is not a duplicate.
             * If it is a duplicate, just ignore it.
             */
            for(i = 0, dup=0; (i < *nsNum) && !dup; i++)
                dup = !strcasecmp(nsList[i], nsList[*nsNum]);
            if(dup)
                free(nsList[*nsNum]);
            else
                (*nsNum)++;
        }
    }
}

/****************************************************************
 * findNameServers -- find all of the name servers for the      *
 *     given domain and store their names in nsList.  nsNum is  *
 *     the number of servers in the nsList array.               *
 ****************************************************************/
void
findNameServers(domain, nsList, nsNum)
char *domain;
char *nsList[];
int  *nsNum;
{
    union {
        HEADER hdr;              /* defined in resolv.h */
        u_char buf[NS_PACKETSZ]; /* defined in arpa/nameser.h */
    } response;                  /* response buffers */
    int responseLen;             /* buffer length */

    ns_msg handle;  /* handle for response packet */

    /*
     * Look up the NS records for the given domain name.
     * We expect the domain to be a fully qualified name, so
     * we use res_query().  If we wanted the resolver search
     * algorithm, we would have used res_search() instead.
     */
    if((responseLen =
           res_query(domain,      /* the domain we care about   */
                     ns_c_in,     /* Internet class records     */
                     ns_t_ns,     /* Look up name server records*/
                     (u_char *)&response,      /*response buffer*/
                     sizeof(response)))        /*buffer size    */
                                        < 0){  /*If negative    */
	*nsNum = 0 ;
    }

    /*
     * Initialize a handle to this response.  The handle will
     * be used later to extract information from the response.
     */
    if (ns_initparse(response.buf, responseLen, &handle) < 0) {
//        fprintf(stderr, "ns_initparse: %s\n", strerror(errno));
	*nsNum = 0 ;
        return;
    }

    /*
     * Create a list of name servers from the response.
     * NS records may be in the answer section and/or in the
     * authority section depending on the DNS implementation.
     * Walk through both.  The name server addresses may be in
     * the additional records section, but we will ignore them
     * since it is much easier to call gethostbyname() later
     * than to parse and store the addresses here.
     */

    /*
     * Add the name servers from the answer section.
     */
    addNameServers(nsList, nsNum, handle, ns_s_an);

    /*
     * Add the name servers from the authority section.
     */
    addNameServers(nsList, nsNum, handle, ns_s_ns);
}
