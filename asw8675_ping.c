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
///         -i wait: seconds to wait between sending each packet. Default is two wait
///             1 second between each packet.
///
///         -s packetsize: specify the number of data bytes to be sent. Default is 56
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int 
main( int argc, char* argv[] )
{

	unsigned int count;
	int optflag;

	while( ( optflag = getopt( argc, argv, "c:i:s:t:" ) ) ) {
		switch( optflag ) {
			case 'c':
				break;
			case 'i':
				break;
			case 's':
				break;
			case 't':
				break;
			case '?':
				if ( optopt == 'c' || optopt == 'i' || optopt == 's' || optopt == 't' )
					fprintf( stderr, "Option '-%c' requires an argument.\n", optopt );
				else if ( isprint( optopt ) )
					fprintf( stderr, "Unknown option '-%c'.\n", optopt );
			default:
				abort( );
		}
	}
}
