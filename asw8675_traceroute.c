///
/// file: asw8675_traceroute.c
///
/// description:
///     Program simulates traceroute like the one in Unix/Linux. Traceroute is used as
///     a diagnostic tool to find out the routes from the sender to the receiver. 
///     The sender generates a sequence of UDP packets destined to the receiver with
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int 
main( int argc, char* argv[] )
{
	int optflag;

	while( ( optflag = getopt( argc, argv, "nq:S" ) ) ) {
		switch( optflag ) {
			case 'n':
				break;
			case 'q':
				break;
			case 'S':
				break;
			case '?':
				if ( optopt == 'q' )
					fprintf( stderr, "Option '-%c' requires an argument.\n", optopt );
				else if ( isprint( optopt ) )
					fprintf( stderr, "Unknown option '-%c'.\n", optopt );
			default:
				abort( );
		}
	}
}
