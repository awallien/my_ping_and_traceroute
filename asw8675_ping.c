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
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHKSM_SZ 2
#define IP_ICMP_HDR_SZ 28
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
/// given an IP address, write IP to host buffer, or
/// given a hostname, get the corresponding IP address
///
/// @param dest: destination string
/// @param ip_buf: ip address buffer
/// @param host_buf: hostname buffer
///
/// @pre: 
///     dest is NOT null
///     size of ip_buf is IP_LEN+1
///     size of host_buf is HOST_NAME_MAX + 1
///
/// @post:
///     ip_buf may be NULL or written
///     host_buf may be NULL or written
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
/// Given two timespec, get the time difference between the end timespec and
/// starting timespec
///
/// @param start: starting timespec
/// @param end: ending timespec
///
/// @return: the time difference in milliseconds
///
static double
time_difference( struct timespec start, struct timespec end )
{
    double secs = end.tv_sec - start.tv_sec, nsecs = end.tv_nsec - start.tv_nsec;
    return ( secs * 1000.0 ) + ( nsecs / 1000000.0 );
}


///
/// Handles making and sending the ICMP packets and receives ICMP replies, also
/// outputs the statistics of the whole ping execution
/// 
/// @param sock_fd: socket file descriptor for sending ICMP packets
/// @param ipaddr: valid ip address
/// @param count: the number of packets per ping execution
/// @param wait: the seconds to wait after sending each packet
/// @param pkt_sz: the size of packets to send to destination
/// @param timeout: TTL of packets
///
/// @pre all parameter arguments are valid
///
static void 
ping_loop( int sock_fd, char* ipaddr, UL count, double wait, UL pkt_sz, UI timeout )
{
    bool count_set = count != 0;
    UL pkts_tx = 0, pkts_rx = 0, pkts_err = 0;
    double rtt_min = INFINITY, rtt_total = 0, rtt_total2 = 0, rtt_max = 0;

    // timespecs for timing the whole ping program and each individual send
    // and recv ICMP packets
    struct timespec ts_stat_start, ts_stat_end, ts_sock_start, ts_sock_end;

    // Destination IP address
    struct sockaddr_in dest;
    memset( &dest, 0, sizeof( struct sockaddr_in ) );
    dest.sin_port = 0;
    dest.sin_family = AF_INET;
    inet_pton( AF_INET, ipaddr, &dest.sin_addr );


    // IP address in the echo reply packet
    struct sockaddr_in reply_addr;
    char domain_name[NI_MAXHOST +1];
    memset( &reply_addr, 0, sizeof( struct sockaddr_in ) );
    memset( domain_name, 0, NI_MAXHOST+1 );
    socklen_t reply_addr_sz = sizeof( reply_addr );


    // ICMP data
    // a buffer will be used to hold the ICMP header and any payload data
    struct icmphdr icmphdr_data;
    size_t data_sz = sizeof( icmphdr_data );
    size_t buff_sz = data_sz + pkt_sz;
    char buff[buff_sz+1];
    memset( buff, 0, buff_sz );

    // set 3 seconds of blocking on recvfrom
    struct timeval recv_timeout = { .tv_sec = 3, .tv_usec = 0 };
    if ( setsockopt( sock_fd, SOL_SOCKET, SO_RCVTIMEO, 
            &recv_timeout, sizeof( recv_timeout ) ) ) {
        fprintf( stderr, "ping: setsockopt( SO_RCVTIMEO ) failed: %s\n", strerror( errno ) );
        return;
    }

    // set the ttl for the socket
    if ( setsockopt( sock_fd, SOL_IP, IP_TTL, &timeout, sizeof( timeout ) ) ) {
        fprintf( stderr, "ping: setsockopt( IP_TTL ) failed: %s\n", strerror( errno ) );
        return;
    }

    // notice that sock start timespec would start at 0, throwing off the difference
    // so "initializing" it here
    clock_gettime( CLOCK_MONOTONIC, &ts_sock_start );

    clock_gettime( CLOCK_MONOTONIC, &ts_stat_start );

    while ( !stop ) {

        // break based off limited number of counts
        if ( count_set && count-- == 0 )
            break;

        // setting flag to determine if sending the ping packet was a success
        bool sent_flag = true;

        
        // initially set up the ICMP header data, according to
        // https://tools.ietf.org/html/rfc792, page 13
        icmphdr_data.type = ICMP_ECHO;
        icmphdr_data.code = 0;
        icmphdr_data.checksum = 0;     
        icmphdr_data.un.echo.id = getpid();
        icmphdr_data.un.echo.sequence = 0;

        // procedure is to copy the icmp header to buffer, calculate the checksum,
        // and then copy again to the buffer
        memcpy( buff, &icmphdr_data, data_sz );

        icmphdr_data.checksum = calculate_checksum( buff, buff_sz ); 
        memcpy( buff+CHKSM_SZ, &icmphdr_data.checksum, CHKSM_SZ );
 
        clock_gettime( CLOCK_MONOTONIC, &ts_sock_start );
    
        // send the request icmp
        if ( sendto( sock_fd, buff, buff_sz, 0, 
                    (struct sockaddr*) &dest, sizeof( dest ) ) <= 0 ) {
            perror( "ping: failed to send icmp request" );
            sent_flag = false;
        }

        pkts_tx += sent_flag ? 1 : 0;

        // any reply?
        int recv_status = recvfrom( sock_fd, buff, buff_sz, 0,
                (struct sockaddr*) &reply_addr, &reply_addr_sz );

        clock_gettime( CLOCK_MONOTONIC, &ts_sock_end );

        if ( recv_status < 0 ) {
            fprintf( stderr, "ping: received timeout\n" );
        } else if( recv_status == 0 ) {
            perror( "ping: received empty ICMP reply" );
        } else {
            getnameinfo( (struct sockaddr* )&reply_addr, 
                    reply_addr_sz, domain_name, NI_MAXHOST, 
                    NULL, 0, NI_NAMEREQD );

            // we got a reply, but is it from the destination address?
            // if not - TTL exceeded
            if ( reply_addr.sin_addr.s_addr != dest.sin_addr.s_addr ) {
                printf( "From %s (%s): icmp_seq=%d Time to live exceeded\n",
                        domain_name, inet_ntoa( reply_addr.sin_addr ), pkts_tx );
                pkts_err++;
            } else {
                double rtt = time_difference( ts_sock_start, ts_sock_end );
                printf( "%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%4.2f ms\n", 
                        recv_status, domain_name, inet_ntoa( reply_addr.sin_addr ), 
                        pkts_tx, timeout, rtt ); 

                // for statistics gathering
                pkts_rx++;
                rtt_min = rtt < rtt_min ? rtt : rtt_min;
                rtt_max = rtt > rtt_max ? rtt : rtt_max;
                rtt_total += rtt;
                rtt_total2 += rtt * rtt;
            } 
        }

        // delay before next request
        usleep( wait * 1000000 );

    }

    clock_gettime( CLOCK_MONOTONIC, &ts_stat_end );

    // all done, print statistics
    printf( "\n--- %s ping statistics ---\n", ipaddr );
    printf( "%lu packets transmitted, %lu received, ", pkts_tx, pkts_rx );
    if ( pkts_err ) {
        printf( "+%lu errors, ", pkts_err );
    }
    printf( "%.1f%% packet loss, time %4.2fms\n", ( ( pkts_tx - pkts_rx ) * 100.0 ) / pkts_tx, 
        time_difference( ts_stat_start, ts_stat_end ) );

    // only print the rtt statistics if we received any packets
    // info about mdev: https://serverfault.com/questions/333116/what-does-mdev-mean-in-ping8
    if ( pkts_rx ) {
        double rtt_avg = rtt_total / pkts_rx;
        rtt_total2 /= pkts_rx;
        rtt_total /= pkts_rx;
        double rtt_mdev = sqrt( rtt_total2 - rtt_total * rtt_total );
        printf( "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", rtt_min, rtt_avg, rtt_max, rtt_mdev ); 
    }

    fflush( stdout );
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
                if ( tmp_pkt_sz < 0 || tmp_pkt_sz > USHRT_MAX || *optarg ) {
                    fprintf( stderr, "ping: invalid argument: '%lld': out of range: 0 <= value <= %d\n", tmp_pkt_sz, USHRT_MAX );
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

    struct protoent* protocol = getprotobyname("icmp");
    if ( !protocol ) {
        fprintf( stderr, "ping: Failed to retrieve protocol\n" );
    }
    
    int sock = socket( AF_INET, SOCK_RAW, protocol->p_proto );
    if( sock < 0 ) {
        fprintf( stderr, "ping: socket() failed: %s\n", strerror( errno ) );
        return EXIT_FAILURE;
    }

    printf("PING %s (%s) %lu(%lu) bytes of data.\n", host, ip, pkt_sz, pkt_sz + IP_ICMP_HDR_SZ );
    ping_loop( sock, ip, count, wait, pkt_sz, timeout );

    close( sock );

    return EXIT_SUCCESS;
}

