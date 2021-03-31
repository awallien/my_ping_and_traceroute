///
/// file: asw8675_ping.c
///
/// description:
///     Program simulates the ping command just like the one in Unix/Linux.
///     Ping is used to check network connectivity and to see whether a remote
///     server is up and running. Ping sends an ICMP echo request packet to a
///     destination node which will in turn reply an ICMP echo replay packet to 
///     the sender with measures of elapsed time for the communication.
///
///     The following options are supported:
///         -c count: stop after sending (and receiving) count ECHO_RESPONSE packets.
///             Default is uninterrupted operation.
///
///         -i wait: seconds to wait between sending each packet. Default is to wait
///             1 second between each packet.
///
///         -s packet size: specify the number of data bytes to be sent. Default is 56
///             bytes, which translates into 64 ICMP data bytes with 8 bytes of ICMP
///             header data.
///
///         -t timeout: specify timeout, in seconds, before ping exits regardless of
///             how many packets have been received.  
///
/// author: 
///     Alex Wall (asw8675)
///
/// date:
///     4/15/2021
///

#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LL long long
#define UI unsigned int
#define UL unsigned long

/// boolean used to determine if pinging should stop
static volatile bool stop;


///
/// signal handler when the user inputs control c for this program, which
/// is to stop sending pings to a destination node
///
static void ctrl_c_handler( )
{
	stop = true;
	printf("stop!\n");
}



static void ping_loop( )
{

}


///
/// given an IP address, get the hostname string, or
/// given a hostname, get the corresponding IP address
///
/// @param dest: destination string
/// @param ip_buf: ip address buffer
/// @param host_buf: hostname buffer
///
static void resolve( char* dest, char* ip_buf, char* host_buf ) {

}


///
/// main function to handle getting input arguments and setting
/// setting the signal handler
///
/// @param argc: the number of arguments
///
/// @param argv: arguments from command line arguments
///
int 
main( int argc, char* argv[] )
{

	// for handling interrupted signals
	signal( SIGINT, ctrl_c_handler );

	// the number of seconds to wait, default 1 second
	double wait = 1.0;

	// the number of packets per execution
	// 0 means infinite until interrupted
	UL count = 0;

	// TTL for each ping, default is 255
	UI timeout = 255;

	// size of packets, default 56
	UL pkt_sz = 56;

	// IP address or hostname
	char* destination = NULL;


	int optflag;
	while( ( optflag = getopt( argc, argv, "c:i:s:t:" ) ) != -1 ) {
		switch( optflag ) {
			// count
			case 'c': {
				LL tmp_count = strtol( optarg, &optarg, 10 );
				if ( tmp_count <= 0 || *optarg ) {
					fprintf( stderr, "ping: bad number of packets to transmit.\n" );
					return EXIT_FAILURE;
				}
				count = ( UL ) tmp_count;
				break;
			}
			// wait
			case 'i': {
				double tmp_wait = strtod( optarg, &optarg );
				if ( tmp_wait < 0.2 || *optarg ) {
					fprintf( stderr, "ping: cannot flood; minimal interval allowed for user is 200ms\n");
					return EXIT_FAILURE;
				}
				wait = tmp_wait;
				break;
			}
			// packet size
			case 's': {
				LL tmp_pkt_sz = strtol( optarg, &optarg, 10 );
				if ( tmp_pkt_sz < 0 || tmp_pkt_sz > INT_MAX || *optarg ) {
					fprintf( stderr, "ping: invalid argument: '%lld': out of range: 0 <= value <= %d\n", tmp_pkt_sz, INT_MAX );
					return EXIT_FAILURE;
				}
				pkt_sz = ( UL ) tmp_pkt_sz;
				break;
			}
			// timeout (TTL)
			case 't': {
				LL tmp_timeout = strtol( optarg, &optarg, 10 );
				if ( tmp_timeout < 0 || tmp_timeout > UCHAR_MAX || *optarg ) {
					fprintf( stderr, "ping: invalid argument: '%lld' out of range 0 <= value <= %d\n", tmp_timeout, UCHAR_MAX );
					return EXIT_FAILURE;
				}
				timeout = ( UI ) tmp_timeout;
				break;
			}
			case '?':
				if ( isprint( optopt ) && !( optopt == 'c' || optopt == 'i' || optopt == 's' || optopt == 't' ) )
					fprintf( stderr, "Unknown option '-%c'.\n", optopt );
				return EXIT_FAILURE;
		}
	}

	// get the destination address from cmd line args
	int dest_count = argc - optind;
	if ( dest_count != 1 ) {
		fprintf( stderr, "ping: invalid argument: %s destination address specified.\n", dest_count ? "more than one" : "no" );
		return EXIT_FAILURE;
	} else {
		destination = argv[optind];
	}

	// get ip and hostname from destination arg
	char ip[15] = { '\0' };
	char host[HOST_NAME_MAX] = { '\0' };
	resolve( destination, ip, host );

	// unknown hostname results in empty ip
	if ( !*ip ) {
		fprintf( stderr, "ping: %s: Name or service not known\n", destination );
		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}