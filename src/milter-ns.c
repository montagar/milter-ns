/*
 * NSMILTER -- Given the large amount of spam received from some domains
 * registered with some registrars (Moniker and ENOM mostly), this milter
 * will reject mail where the domain is using their specific DNS servers.
 *
 * Checks are made on the domain name in the MAIL FROM: and in the HELO/EHLO.
 *
 * Author:	David L. Cathey
 * 		Montagar Software, Inc.
 * 		POBox 260772
 * 		Plano, TX 75026-0772
 *
 * References:
 * 	https://www.milter.org/developers
 * 	http://www.diablotin.com/librairie/networking/dnsbind/ch14_02.htm
 */
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

#define 	MILTER_SOCKET	"/var/run/milter-ns.sock"
#define		MILTER_NAME	PACKAGE_STRING

char	*name_servers[] = {
		".monikerdns.net",		// Had issues with Moniker registered domains, but not so much now
		".name-services.com",		// ENOM domains are banned
		".registrar-servers.com",	// ENOM domains are banned
		".bigrock.com",			// New registrar with problems
		"DANA.NS.CLOUDFLARE.COM",	// Having a little trouble with some new cloudflare DNS's domains
		"ROB.NS.CLOUDFLARE.COM",
		NULL
	} ;

/*
 * Our Milter private structure.  A flag to indicate we want to reject/tempfail the
 * message, and keep the host and helo for logging purposes.
 */
struct nameserver {
	int	flag ;
	char	host[512] ;
	char	helo[512] ;
	char	rcpt[512] ;
	char	from[512] ;
} ;

int checkNameServers(struct nameserver *mp, char *p)
{
	int	rtn = 0 ;
	char	*aNameServers[20] ;
	int	nNameServers ;	
	FILE	*fp ;

	nNameServers = 0 ;
	findNameServers(p, aNameServers, &nNameServers) ;
	if(nNameServers > 0) {
		int i ;

		for(i = 0 ; i < nNameServers && rtn == 0 ; i++) {
			int j ;
			for(j = 0 ; name_servers[j] != NULL && rtn == 0 ; j++) {
				if( strcasestr(aNameServers[i], name_servers[j])) {
					syslog(LOG_INFO, "%8.8x Domain %s found in banned DNS servers %s", mp, p, aNameServers[i]) ;
					rtn = 1 ;
				}
			}
		}
		for(i = 0 ; i < nNameServers ; i++) {
			if(aNameServers[i] != NULL) {
				free(aNameServers[i]) ;
				aNameServers[i] = NULL ;
			}
		}
	}
	return(rtn) ;
}

sfsistat mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *addr)
{
	struct nameserver *mp = malloc(sizeof(struct nameserver)) ;

	// Initialize our connection-specific context, and grab the Hostname
	memset(mp, '\0', sizeof(struct nameserver)) ;
	strncpy(mp->host, hostname, sizeof(mp->host)-1) ;
	smfi_setpriv(ctx, mp) ;
	return(SMFIS_CONTINUE) ;
}

sfsistat mlfi_helo(SMFICTX *ctx, char *helohost)
{
	char			*p ;
	int			status = SMFIS_CONTINUE ;
	struct nameserver	*mp = smfi_getpriv(ctx) ;

	// Save the HELO for later processing
	//
	// Note that we test for HELO being 'ylmf-pc', since this has 
	// been seen in a lot of places trying to brute-force accounts on
	// SMTP servers.  If found, we force reject on the reset of the 
	// connection.
	strncpy(mp->helo, helohost, sizeof(mp->helo)-1) ;
	if(strcmp(mp->helo, "ylmf-pc") == 0) {
		syslog(LOG_INFO, "Reject ylmf-pc: Host=%s", mp->host) ;
		status = SMFIS_REJECT ;
	}
	return(status) ;
}

sfsistat mlfi_mailfrom(SMFICTX *ctx, char **argv)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;
	char			domain[512] ;
	char			*p ;

	// Zero out the structures
	memset(domain, '\0', sizeof(domain)) ;
	memset(mp->from, '\0', sizeof(mp->from)) ;

	// Get the MAIL FROM: address issued by the remote
	strncpy(mp->from, "Unknown", sizeof(mp->from)-1) ;
	if(argv != NULL && argv[0] != NULL) {
		strncpy(mp->from, argv[0], sizeof(mp->from)-1) ;
	}

	// Get the Domain part, and check against the NameServers
	if(p = strchr(mp->from, '@')) {
		strncpy(domain, p+1, sizeof(domain)-1) ;
		if(p = strchr(domain, '>')) {
			*p = '\0' ;
			mp->flag |= checkNameServers(mp, domain) ;
		}
	}

	// If still not blocked, check the HELO domain against the NameServers
	// Note that we need to go through each part of the FQDN to find the
	// domain root with the NameServer
	if(mp->flag == 0) {
		for(p = mp->helo ; p != NULL && mp->flag == 0 ; p = strchr(p, '.')) {
			if(*p == '.') p++ ;
			if(strchr(p, '.') == NULL) break ;
			if(mp->flag |= checkNameServers(mp, p)) {
				break ;
			}
		}
	}

	return(status) ;
}

sfsistat mlfi_envrcpt(SMFICTX *ctx, char **argv)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;

	// Capture the RCPT TO: from the remote
	memset(mp->rcpt, '\0', sizeof(mp->rcpt)) ;
	if(argv[0] != NULL) {
		strncpy(mp->rcpt, argv[0], sizeof(mp->rcpt)-1) ;
	} else {
		strncpy(mp->rcpt, "Unknown", sizeof(mp->rcpt)-1) ;
	}

	// If HELO or MAIL FROM is flagged, issue a TEMPFAIL.  Maybe this will help
	// clog up the remote mailserver and slow down it's spamming?
	if(mp->flag == 1) {
		syslog(LOG_INFO, "%8.8x Reject: helo=%s, mail from=%s, rcpt to=%s", mp, mp->helo, mp->from, mp->rcpt) ;
		status = SMFIS_TEMPFAIL ;
	}
	return(status) ;
}

sfsistat mlfi_close(SMFICTX *ctx)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;

	// We are done with the connection, so free up our context
	if(mp != NULL) {
		free(mp) ;
		smfi_setpriv(ctx, NULL) ;
	}
	return(status) ;
}

sfsistat mlfi_abort(SMFICTX *ctx)
{
	struct nameserver	*mp = smfi_getpriv(ctx) ;
	int			status = SMFIS_CONTINUE ;

	// Do nothing here at this time...
	return(status) ;
}

struct smfiDesc smilter =
{
	"nsmilter",			/* Milter name */
	SMFI_VERSION,			/* Version Code */
	SMFIF_ADDHDRS,			/* Milter Flags */
	mlfi_connect,			/* initialize connection */
	mlfi_helo,			/* SMTP HELO command filter */
	mlfi_mailfrom,			/* MAIL FROM command filter */
	mlfi_envrcpt,			/* RCPT TO command filter */
	NULL,				/* Header filter */
	NULL,				/* End of Headers indicator */
	NULL,				/* Body Block Filter */
	NULL,				/* End of Message indicator */
	mlfi_abort,			/* Message Aborted */
	mlfi_close			/* shutdown connection */
} ;

main(int argc, char **argv)
{
	int	sts ;

//	Set up the Milter socket
	unlink(MILTER_SOCKET) ;
	smfi_setconn(MILTER_SOCKET) ;

	openlog(PACKAGE_NAME, LOG_PID, LOG_MAIL) ;
	syslog(LOG_INFO, "%s Initializing...", PACKAGE_STRING) ;

//	Register our milter callbacks
	if(smfi_register(smilter) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_register failed\n", argv[0]) ;
		exit(EX_UNAVAILABLE) ;
	}

//	And away we go!
	sts = smfi_main() ;
	closelog() ;
	return sts ;
}	
