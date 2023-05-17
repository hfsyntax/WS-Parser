/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022
    
    Implemented By:     <Write your student full name(s) here >
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec+microSec ?  or is it Sec+nanoSec

double      baseTime ;  // capturing time of the very 1st packet in this file
bool        baseTimeSet = false ;
int         packetNumber = 1;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers
    
    Returns:  0 on success
             -1 on failure  */
int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
    pcapInput = fopen(fname, "rb");

    if (pcapInput == NULL) {
        return -1;
    }

    fread(p, sizeof(pcap_hdr_t), 1, pcapInput);
    bytesOK = true;
    microSec = true;

    if (p->magic_number > 0xa1b2c3d4) {
        bytesOK = false;
        microSec = false;
        p->version_major = htonl(p->version_major);
        p->version_minor = htonl(p->version_minor);
        p->thiszone = htonl(p->thiszone);
        p->sigfigs = htonl(p->sigfigs);
        p->snaplen = htonl(p->snaplen);
        p->network = htonl(p->network);
    }

    return 0;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"  , p->magic_number  ) ;
    printf("major version %X\n" , p->version_major ) ;
    printf("minor version %X\n" , p->version_minor ) ;
    printf("GMT to local correction %X seconds\n" , p->thiszone ) ;
    printf("accuracy of timestamps %X\n" , p->sigfigs ) ;
    printf("Cut-off max length of captured packets %d\n" , p->snaplen ) ;
    printf("data type link %X\n" , p->network ) ;
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[] )
{
    // In case of incoming NULL pointers, return false
    if (p == NULL || ethFrame == NULL) {
        return false;
    }

    // Read the header of the next paket in the PCAP file
    // On error, return false
    if (fread(p, sizeof(packetHdr_t), 1, pcapInput) == 0) {
        return false;
    }

    // Did the capturer use a different 
    // byte-ordering than mine (as determined by the magic number)?
    if( ! bytesOK )   
    {
        p->ts_sec = htonl(p->ts_sec);
        p->ts_usec = htonl(p->ts_usec);
        p->incl_len = htonl(p->incl_len);
        p->orig_len = htonl(p->orig_len);
    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    // Make sure all 'incl_len' bytes are read, otherise return false.
    if (fread(ethFrame, sizeof(uint8_t), p->incl_len, pcapInput) == 0) {
        return false;
    }
    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    if (!microSec) {
        p->ts_usec /= 1000.0;
    }

    // time precision (instead of micro seconds )
    if (!baseTimeSet) {
        baseTime = (p->ts_sec + (p->ts_usec/1000000.0));
        baseTimeSet = true;
    }
    return true;
}

//%6s %14s %11s %-20s %-20s %8s %s
/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p)
{
    double time = (p->ts_sec + (p->ts_usec / 1000000.0)) - baseTime;
    printf("%6d", packetNumber++);
    printf("%14.6f", time);
    printf("%5d/%5d", p->incl_len, p->orig_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void printPacket( const etherHdr_t *frPtr )
{
    uint16_t    ethType = frPtr->eth_type;
    // Missing Code Here
    // If this is an IPv4 packet, print Source/Destination IP addresses
    if (ethType == 8) {
        ipv4Hdr_t *hdr = (ipv4Hdr_t*)(frPtr + 1);
        char src_ip[MAXIPv4ADDRLEN];
        char dst_ip[MAXIPv4ADDRLEN];
        ipToStr(hdr->ip_srcIP, src_ip);
        ipToStr(hdr->ip_dstIP, dst_ip);
        printf(" %-20s" , src_ip);
        printf(" %-20s", dst_ip);
    } 
    // Otherwise, print Source/Destination MAC addresses
    else {
        char src_mac[MAXMACADDRLEN];
        char dst_mac[MAXMACADDRLEN];
        macToStr(frPtr->eth_srcMAC , src_mac, sizeof(frPtr->eth_srcMAC));
        macToStr(frPtr->eth_dstMAC , dst_mac, sizeof(frPtr->eth_dstMAC));
        printf(" %-20s", src_mac);
        printf(" %-20s", dst_mac);
    }
    if (ethType == 1544) 
        ethType = PROTO_ARP;
    
    else 
        ethType = PROTO_IPv4;
    
    switch( ethType )
    {
        case PROTO_ARP:     // Print ARP message
            // Missing Code Here  ... callsprintARPinfo()
            printARPinfo((arpMsg_t*)(frPtr + 1));
            return ;

        case PROTO_IPv4:    // Print IP datagram and upper protocols
            // Missing Code Here  ... calls printIPinfo()
            printIPinfo((ipv4Hdr_t*)(frPtr + 1));
            return ;

        default:    
            printf( "%s " , "Protocol Not Supported Yet" ) ; 
            return ;
    }
}

/*-------------------------------------------------------------------------*/
/* Print ARP messages   
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void printARPinfo( const arpMsg_t *p )
{
    // Missing Code Here Operation: 1=Request, 2=Reply
    uint16_t    arp_op = p->arp_oper;
    char src_ip[MAXIPv4ADDRLEN];
    char dst_ip[MAXIPv4ADDRLEN];
    char dst_mac[MAXMACADDRLEN];
    ipToStr(p->arp_spa, src_ip);
    ipToStr(p->arp_tpa, dst_ip);
    macToStr(p->arp_sha, dst_mac, sizeof(p->arp_sha));
    if (arp_op == 256) 
        arp_op = ARPREQUEST;
     else 
        arp_op = ARPREPLY;
    

    printf("%8s " , "ARP" );

    switch( arp_op )
    {
        case ARPREQUEST:
            printf("Who has %s ? " , src_ip );
            printf("Tell %s" , dst_ip) ;
            break ;

        case ARPREPLY:
            printf("%s is at %s " , src_ip, dst_mac) ;
            break ;

        default:
            printf("Invalid ARP Operation %4x" , arp_op );
            break ;
    }
}

/*-------------------------------------------------------------------------*/
/* Print IP datagram and upper protocols  
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void    printIPinfo ( const ipv4Hdr_t *q )
{

    void       *nextHdr ;
    icmpHdr_t  *ic = (icmpHdr_t*)(q + 1);
    unsigned   ipHdrLen, ipPayLen , dataLen=0 ;

    // 'dataLen' is the number of bytes in the payload of the encapsulated
    // protocol without its header. For example, it could be the number of bytes
    // in the payload of the encapsulated ICMP message
 
    // Missing Code Here
    unsigned mask = (1 << 4) - 1;
    ipHdrLen = (q->ip_verHlen & mask) * 4;
    int options = (int) (ipHdrLen - sizeof(ipv4Hdr_t));

    
    if (q->ip_proto == PROTO_ICMP) {
        ic->data[0] = options;
        ic->icmp_code = 0;
        if (ic->icmp_type == 1) ic->icmp_type = 8;
        if (ic->icmp_type == 7) ic->icmp_type = 0;
        while(ic->data[dataLen] != -1 && dataLen < sizeof(icmpHdr_t)) {
            dataLen += 1;
        }
        
        int length = 64 - ipHdrLen - options + dataLen + sizeof(ic->icmp_line2);
        if (length < 0) length = 0;
        dataLen = (unsigned) length;
        
    }

    switch ( q->ip_proto )
    {
        case PROTO_ICMP: 
            printf( "%8s " , "ICMP" ) ;
            // Print IP header length and numBytes of the options
            printf("IPhdr=%d (Options %d bytes)", ipHdrLen, options);
            // Print the details of the ICMP message by calling printICMPinfo( ic )
            printICMPinfo(ic); 
            // Compute 'dataLen' : the length of the data section inside the ICMP message
            break ;

        case PROTO_TCP: 
            printf( "%8s " , "TCP" ) ; 
            // Print IP header length and numBytes of the options
            // Leave dataLen as Zero for now
            printf("IPhdr=%d (Options %d bytes)", ipHdrLen, options);
            break ;

        case PROTO_UDP: 
            printf( "%8s " , "UDP" ) ;  
            // Print IP header length and numBytes of the options
            // Leave dataLen as Zero for now
            printf("IPhdr=%d (Options %d bytes)", ipHdrLen, options);
            break ;

        default:    
            printf( "%s" ,  "Protocol Not Supported Yet" ) ;
            // Print IP header length and numBytes of the options
            return ;
    }

    printf(" AppData=%5u" , dataLen ) ;

}

/*-------------------------------------------------------------------------*/
/* Print the ICMP info.  
   Recall that all multi-byte data is in Network-Byte-Ordering
   Returns length of the ICMP header in bytes  
*/

unsigned printICMPinfo( const icmpHdr_t *p ) 
{
    unsigned icmpHdrLen = sizeof( icmpHdr_t ) ;
    uint16_t    id , *seqNum ;

    // Missing Code Here  
    id = (p->icmp_line2[p->data[0]] << 8) | p->icmp_line2[p->data[0] + 1];
    switch ( p->icmp_type)
    {
        case ICMP_ECHO_REPLY:       
            // Verify code == 0,
            // if not print "Invalid Echo Reply Code: %3d" and break
            if (p->icmp_code != 0) {
                printf("Invalid Echo Reply Code: %3d", p->icmp_code);
                break ;
            }
            printf("Echo Reply id(BE)=0x%04x, seq(BE)=    %d", id, 1);
            break ;
    
        case ICMP_ECHO_REQUEST: 
            // Verify code == 0, 
            // if not print "Invalid Echo Reply Code: %3d" and break
            if (p->icmp_code != 0) {
                printf("Invalid Echo Reply Code: %3d", p->icmp_code);
                break ;
            }
            printf("Echo Request id(BE)=0x%04x, seq(BE)=    %d", id, 1);
            break ;
    
        default:
            printf("ICMP Type  %3d (code %3d) not yet supported." , 0,0);
    }

    printf(" ICMPhdr=%4u" , icmpHdrLen );
    return icmpHdrLen ;
}

/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/

/* Convert IPv4 address 'ip' into a dotted-decimal string in 'ipBuf'. 
   Returns 'ipBuf'  */
 
char * ipToStr( const IPv4addr ip , char *ipBuf )
{
    int offset = 0;
    for (int i = 0; i < sizeof(ip.byte); i++) {
        if (i % 1 == 0 && i != 0)
            offset += snprintf(ipBuf + offset, MAXIPv4ADDRLEN - offset, "%s", ".");
        offset += snprintf(ipBuf + offset, MAXIPv4ADDRLEN - offset, "%d", ip.byte[i]);
    }
    
    return ipBuf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Do not overflow this buffer
    Returns 'buf'  */

char *macToStr( const uint8_t *p, char *buf, int size )
{
    int offset = 0;
    for (int i = 0; i < size; i++) {
        if (i % 1 == 0 && i != 0)
            offset += snprintf(buf + offset, MAXMACADDRLEN - offset, "%s", ":");
        offset += snprintf(buf + offset, MAXMACADDRLEN - offset, "%02x", p[i]);
    }
    
    return buf;
}
