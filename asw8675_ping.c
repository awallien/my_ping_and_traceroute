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
///         -t TTL: specify timeout, in seconds, before ping exits regardless of
///             how many packets have been received.  
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
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#define IP_LEN 15

#define LL long long
#define UC unsigned char
#define UI unsigned int
#define UL unsigned long
#define US unsigned short

/// boolean used to determine if pinging should stop
static volatile bool stop = false;


///
/// signal handler when the user inputs control c for this program, which
/// is to stop sending pings to a destination node
///
static void 
ctrl_c_handler( )
{
	stop = true;
	printf("stop!\n");
}


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
calculate_checksum( struct icmphdr* hdr, size_t hdr_len ) {
	UC* hdr_buf = ( UC* ) hdr;
	int sum = 0;

	// get the sum of the ICMP message in 16 bit words
	while( hdr_len > 1 ) {
		sum += ( hdr_buf[0] << 8 ) | hdr_buf[1];
		hdr_buf += 2; hdr_len -= 2;
	}
	// for odd lengths, last octet is zeros
	if ( hdr_len == 1 ) {
		sum += ( hdr_buf[0] << 8 );
	}

	// for converting 32 bit sum to 16 bit
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ( US ) ( ~sum & 0xFFFF );
}


///
/// Handles making and sending the ICMP packets and receives ICMP replies, also
/// outputs the statistics of the whole ping execution
/// 
/// @param sock_fd: socket file descriptor for sending ICMP packets
/// @param ip: the ip address
/// @param count: the number of packets per ping execution
/// @param wait: the seconds to wait after sending each packet
/// @param pkt_sz: the size of packets to send to destination
/// @param timeout: TTL of packets
///
static void 
ping_loop( int sock_fd, char* ip, UL count, double wait, UL pkt_sz, UI timeout )
{
	bool count_set = count != 0;
	UL pkts_tx, pkts_rx;
	double rtt_min, rtt_avg, rtt_max, rtt_mdev;
	
	struct icmphdr icmp_hdr;
	memset( &icmp_hdr, 0, sizeof( icmp_hdr ) );
	
	// set the 'wait' timeout for the socket
	struct timeval time_wait;
	time_wait.tv_sec = (unsigned int) wait;
	time_wait.tv_usec = 0;
	if ( setsockopt( sock_fd, SOL_SOCKET, SO_RCVTIMEO, &time_wait, sizeof( time_wait ) ) ) {
		fprintf( stderr, "ping: setsockopt( SO_RCVTIMEO ) failed: %s\n", strerror( errno ) );
		return;
	}

	// set the ttl timeout for the socket
	if ( setsockopt( sock_fd, SOL_IP, IP_TTL, &timeout, sizeof( timeout ) ) ) {
		fprintf( stderr, "ping: setsockopt( IP_TTL ) failed: %s\n", strerror( errno ) );
		return;
	}

	while ( !stop ) {

		// break based off limited number of counts
		if ( count_set && count-- == 0 )
			break;


		// set up the ICMP header data, according to
		// https://tools.ietf.org/html/rfc792, page 13
		icmp_hdr.type = ICMP_ECHO;
		icmp_hdr.code = 0;
		icmp_hdr.checksum = calculate_checksum( &icmp_hdr, sizeof( icmp_hdr ) );
		icmp_hdr.un.echo.id = 0;
		icmp_hdr.un.echo.sequence = 0;

		// send the socket

		// any reply?

	}

	// all done, print statistics
	printf( "\n--- %s ping statistics ---\n", ip );
	printf( "%lu packets transmitted, %lu received, %.1f%% packet loss, time %lums\n", 
				pkts_tx, pkts_rx, ( ( pkts_tx - pkts_rx ) * 100.0 ) / pkts_tx,  (UL) 999 );
	
	fflush( stdout );
}


///
/// given an IP address, write IP to host buffer, or
/// given a hostname, get the corresponding IP address
///
/// @param dest: destination string
/// @param ip_buf: ip address buffer
/// @param host_buf: hostname buffer
///
/// @pre: 
/// 	dest is NOT null
/// 	size of ip_buf is IP_LEN+1
/// 	size of host_buf is HOST_NAME_MAX + 1
///
/// @post:
/// 	ip_buf may be NULL or written
///		host_buf may be NULL or written
///
static void 
resolve( char* dest, char* ip_buf, char* host_buf ) {
	struct sockaddr_in sa;
	if ( inet_pton( AF_INET, dest, &sa.sin_addr ) == 1 ) {
		strncpy( ip_buf, dest, IP_LEN );		
		strncpy( host_buf, ip_buf, IP_LEN );
	} else {
		strncpy( host_buf, dest, HOST_NAME_MAX );

		struct addrinfo hints, *addr_res = NULL;
		hints.ai_flags = AI_PASSIVE;
		hints.ai_socktype = 0;
		hints.ai_family = AF_INET;
		hints.ai_protocol = 0;

		// resolve hostname to get IP address
		int err = getaddrinfo( host_buf, NULL, &hints, &addr_res );
		if ( err ) {
			fprintf( stderr, "ping: %s\n", gai_strerror( err ) );
		} else {
			struct sockaddr_in* sa = ( struct sockaddr_in* ) addr_res->ai_addr;
			inet_ntop( AF_INET, &sa->sin_addr, ip_buf, IP_LEN );
		}

		freeaddrinfo( addr_res );
	}
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
		if ( strlen( destination ) > HOST_NAME_MAX ) {
			fprintf( stderr, "ping: %s: Name or service not known\n", destination );
			return EXIT_FAILURE;
		}
	}

	// get ip and hostname from destination arg
	char ip[IP_LEN + 1];
	memset( ip, 0, IP_LEN + 1 );

	char host[HOST_NAME_MAX + 1];
	memset( host, 0, HOST_NAME_MAX + 1 );

	resolve( destination, ip, host );

	// unknown hostname results in empty ip
	if ( !*ip ) {
		fprintf( stderr, "ping: %s: Name or service not known\n", destination );
		return EXIT_FAILURE;
	}

	int sock = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
	if( sock < 0 ) {
		fprintf( stderr, "ping: socket() failed: %s\n", strerror( errno ) );
		return EXIT_FAILURE;
	}

	printf("PING %s (%s) %lu(%lu) bytes of data.\n", host, ip, pkt_sz, pkt_sz + 28 );
	ping_loop( sock, ip, count, wait, pkt_sz, timeout );


	return EXIT_SUCCESS;
}
