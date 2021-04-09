///
/// file: asw8675_traceroute.c
///
/// description:
///     Program simulates traceroute like the one in Unix/Linux. Traceroute is used as
///     a diagnostic tool to find out the routes from the sender to the receiver. 
///     The sender generates a sequence of ICMP packets destined to the receiver with
///     TTL gradually increasing starting at 1 in order to discover the intermediate
///     routers. The intermediate routers issue an ICMP error message when TTL becomes
///     0, and return the message back to the sender.
///
///     The following options are supported:
///         -n: Print hop addresses numerically rather than symbolically and numerically.
///             (IPv4 address only; do not resolve hostname)
/// 
///         -q nqueries: Set the number of probes per TTL to nqueries.
///
///         -S: Print a summary of how many probes were not answered for each hop.
///
/// author:
///     Alex Wall (asw8675)
///
/// date:
///     4/15/2021 
///

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHKSM_SZ 2
#define ICMP_PAYLOAD_SZ 56
#define IP_LEN 15
#define HOPS_MAX 255
#define NQUERIES_MAX 10
#define RECV_TIMEOUT 3

#define UC unsigned char
#define UI unsigned int
#define UL unsigned long
#define US unsigned short


#define IP_ADDR( ip ) ip .sin_addr.s_addr


///
/// Calculate the checksum for ICMP header
///
/// According to RFC 792:
///
///   The checksum is the 16-bit ones's complement of the one's
///   complement sum of the ICMP message starting with the ICMP Type.
///   For computing the checksum , the checksum field should be zero.
///   If the total length is odd, the received data is padded with one
///   octet of zeros for computing the checksum.  This checksum may be
///   replaced in the future.
///
/// @param hdr: ICMP header struct
/// @param hdr_len: length of header struct
///
/// @return the checksum value
///
static US
calculate_checksum( void* hdr, size_t hdr_len ) 
{
    UI sum = 0;
    US* buf = ( US* ) hdr;

    while( hdr_len > 1 ) {
        sum += *buf++;
        hdr_len -= 2;
    }

    if ( hdr_len == 1 ) {
        sum += *( UC* ) buf;
    }

    // for converting 32 bit sum to 16 bit
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ( US ) ( ~sum );
}


///
/// Given an IP address, write IP to host buffer, or
/// given a hostname, get the corresponding IP address
///
/// @param dest: destination string
/// @param ip_buf: ip address buffer
/// @param host_buf: hostname buffer
///
/// @pre: 
///     dest is NOT null
///     size of ip_buf is IP_LEN+1
///     size of host_buf is NI_MAXHOST+ 1
///
/// @post:
///     ip_buf may be NULL or written
///     host_buf may be NULL or written
///
static void 
resolve( char* dest, char* ip_buf, char* host_buf ) 
{
    struct sockaddr_in sa;
    memset( &sa, 0, sizeof( struct sockaddr_in ) );  
    
    if ( inet_pton( AF_INET, dest, &sa.sin_addr ) == 1 ) {
        strncpy( ip_buf, dest, IP_LEN );
       
        // resolve IP to get name 
        socklen_t sa_len = sizeof( sa );
        sa.sin_family = AF_INET;
        if ( getnameinfo( ( struct sockaddr* ) &sa, sa_len, host_buf, NI_MAXHOST, 
            NULL, 0, NI_NAMEREQD ) )
            strncpy( host_buf, dest, IP_LEN ); 
    } else {
        strncpy( host_buf, dest, NI_MAXHOST );

        struct addrinfo hints, *addr_res = NULL;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = 0;
        hints.ai_family = AF_INET;
        hints.ai_protocol = 0;

        // resolve hostname to get IP address
        int err = getaddrinfo( host_buf, NULL, &hints, &addr_res );
        if ( err ) {
            fprintf( stderr, "traceroute: %s\n", gai_strerror( err ) );
        } else {
            struct sockaddr_in* sa = ( struct sockaddr_in* ) addr_res->ai_addr;
            inet_ntop( AF_INET, &sa->sin_addr, ip_buf, IP_LEN );
        }

        freeaddrinfo( addr_res );
    }
}


///
/// Main execution of traceroute, which sends ICMP packets for every incremental TTL
/// starting from 1 to 255. The incremental TTL represents a hop, which is queried
/// multiple times to measure the response. The program would receive an ICMP packet
/// in return that contains the reply IP address. By default, the program would wait
/// 3 seconds for a response before timing out and continuing with the next query/hop. 
///
/// @param sock_fd: the socket fd
/// @param ipaddr: destination IP address
/// @param is_resolved: is the IP address for each hop resolved to name?
/// @param nqueries: number of queries per hop
/// @param summary: is there a summary described in the header doc?
///
/// @pre all parameters are valid
///
static void
traceroute( int sock_fd, char* ipaddr, bool is_resolved, UC nqueries, bool summary )
{
    UC ttl = 0;
    struct timespec ts_sock_start, ts_sock_end;
 

    // ICMP data
    struct icmphdr hdr;
    size_t hdr_sz = sizeof( hdr );
    size_t buff_sz = hdr_sz + ICMP_PAYLOAD_SZ;
    char buff[buff_sz];
    memset( buff, 0, buff_sz ); 

    // Destination address
    struct sockaddr_in dest;
    memset( &dest, 0, sizeof( dest ) );
    dest.sin_port = 0;
    dest.sin_family = AF_INET;
    inet_pton( AF_INET, ipaddr, &dest.sin_addr );

    // Reply address
    struct sockaddr_in reply;
    socklen_t reply_sz = sizeof( reply );
    char name[NI_MAXHOST+1];
    memset( &reply, 0, reply_sz );
    memset( &name, 0, sizeof( name ) );


    // increment ttl until limit reached or destination matches reply
    while ( ttl++ != 255 && IP_ADDR( dest ) != IP_ADDR( reply ) ) {
        printf( "%d ", ttl );
        
        // queries - prepare ICMP data and send, receive reply
        for( int query = 0; query < nqueries; query++ ) {
            hdr.type = ICMP_ECHO;
            hdr.code = 0;
            hdr.checksum = 0;
            hdr.un.echo.id = getpid();
            hdr.un.echo.sequence = 0;

            memcpy( buff, &hdr, hdr_sz ); 
            hdr.checksum = calculate_checksum( buff, buff_sz );
            memcpy( buff+CHKSM_SZ, &hdr.checksum, CHKSM_SZ );

            clock_gettime( CLOCK_MONOTONIC, &ts_sock_start );


            clock_gettime( CLOCK_MONOTONIC, &ts_sock_end );

            size_t 
                secs = ts_sock_end.tv_sec - ts_sock_start.tv_sec,
                nsecs = ts_sock_end.tv_nsec - ts_sock_start.tv_nsec,
                msecs = 1000 * secs + nsecs / 1000000;

            if( IP_ADDR( reply ) ) {
                if ( msecs < 1 )
                    printf( "<1 ms   " );
                else
                    printf( "%lu ms   ", msecs );
            } else { 
                printf( "*   " );
            } 
            
        }
        printf( "\n" );

    }


}


///
/// main function to handle getting input arguments and
/// setting up the socket
///
/// @param argc: the number of arguments
///
/// @param argv: arguments from command line arguments
///
int 
main( int argc, char* argv[] )
{
    // should IP addresses be resolved?
    bool resolve_addr = true;

    // number of queries per TTL hop
    UC nqueries = 3;

    // print summary?
    bool summary = false;
    
    // destination node
    char* destination = NULL;
 
	int optflag;
	while( ( optflag = getopt( argc, argv, "nq:S" ) ) != -1 ) {
		switch( optflag ) {
            // numerical addresses
			case 'n': {
                resolve_addr = false;
				break;
            }
            // nqueries
			case 'q': {
                long tmp_nqueries = strtol( optarg, &optarg, 10 );
                if ( tmp_nqueries <= 0 || tmp_nqueries > NQUERIES_MAX || *optarg ) {
                    fprintf( stderr, "traceroute: invalid argument: '%ld': out of range 1 <= value <= %d\n", tmp_nqueries, NQUERIES_MAX );
                    return EXIT_FAILURE;
                }
                nqueries = ( UC ) tmp_nqueries;
				break;
            }
            // summary
			case 'S': {
                summary = true;
				break;
            }
			case '?':
				if ( isprint( optopt ) && !( optopt == 'n' || optopt == 'q' || optopt == 'S' ) )
					fprintf( stderr, "Unknown option '-%c'.\n", optopt );
		}
	}

    // get the destination address from cmd line args
    int dest_count = argc - optind;
    if ( dest_count != 1 ) {
        fprintf( stderr, "traceroute: invalid argument: %s destination address specified.\n", dest_count ? "more than one" : "no" );
        return EXIT_FAILURE;
    } else {
        destination = argv[optind];
        if ( strlen( destination ) > NI_MAXHOST ) {
            fprintf( stderr, "traceroute: %s: Name or service not known\n", destination );
            return EXIT_FAILURE;
        }
    }


    // get ip and hostname from destination arg
    char ip[IP_LEN + 1];
    memset( ip, 0, IP_LEN + 1 );

    char host[NI_MAXHOST+1];
    memset( host, 0, NI_MAXHOST+1 );

    resolve( destination, ip, host );

    // unknown hostname results in empty ip
    if ( !*ip ) {
        fprintf( stderr, "traceroute: %s: Name or service not known\n", destination );
        return EXIT_FAILURE;
    }

    // using ICMP echo packets for making the hops
    struct protoent* protocol = getprotobyname( "icmp" );
    if ( !protocol ) {
        fprintf( stderr, "traceroute: Failed to retrieve ICMP protocol\n" );
        return EXIT_FAILURE;
    } 

    // create the socket for sending packets
    int sock;
    if ( ( sock = socket( AF_INET, SOCK_RAW, protocol->p_proto ) ) < 0 ) {
        fprintf( stderr, "traceroute: socket() failed: %s\n", strerror( errno ) );
        return EXIT_FAILURE;
    }
   
    // perform traceroute routine  
    printf( "TRACEROUTE %s (%s), 255 hops max, 64 bytes packets\n", host, ip );
    traceroute( sock, ip, resolve_addr, nqueries, summary );

    close( sock );

    return EXIT_SUCCESS;
}
