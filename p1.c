/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022
    
    Implemented By:     Noah Kaiser
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-------------------------------------------------------------------------*/
void usage(char *cmd)
{
    printf("Usage: %s fileName\n" , cmd);
}

/*-------------------------------------------------------------------------*/

#define MAXBUF  10000           /* num Bytes in largest ethenet frame */

int main( int argc  , char *argv[] )
{
    char        *pcapIn ;
    uint8_t     data[MAXBUF] ;
    pcap_hdr_t  pcapHdr ;
    packetHdr_t pktHdr  ;
    uint8_t     ethFrame[MAXFRAMESZ] ;
    etherHdr_t  *frameHdrPtr = (etherHdr_t  *) ethFrame ;
    
    if ( argc < 2 )
    {
        usage( argv[0] ) ;
        exit ( EXIT_FAILURE ) ;
    }

    pcapIn = argv[1] ;
    // Read the global header of the pcapInput file
    // By calling readPCAPhdr(). 
    // If error occur, call errorExit("Failed to read global header from the PCAP file "  )

    // Print the global header of the pcap filer
    // using printPCAPhdr()

    if (readPCAPhdr(pcapIn, &pcapHdr) == -1) {
        errorExit("Failed to read global header from the PCAP file "  );
    }

    printPCAPhdr(&pcapHdr);

    // Print labels before any packets are printed
    puts("") ;
    printf("%6s %14s %11s %-20s %-20s %8s %s\n" ,
           "PktNum" , "Time Stamp" , "Org Len/Cap'd"  , 
           "Source" , "Destination" , "Protocol" , "info");

    // Read one packet at a time
    while (getNextPacket(&pktHdr, ethFrame) )
    {

        // Make sure the base time (logical time 0) is set
        //double baseTime = 0;
        // Use packetMetaDataPrint() to print the packet header data;
        // Use packetPrint( ) to print the actual content of the packet starting at the 
        // ethernet level and up
        puts("");
        printPacketMetaData(&pktHdr);
        printPacket(frameHdrPtr);
    }
    
    printf("\nReached end of PCAP file '%s'\n" , pcapIn ) ;
    cleanUp() ;    
}

