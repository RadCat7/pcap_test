#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>


//just cmd use
void usage() {
  printf("Wrong Use!!\n");
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  //error call
  char* dev = argv[1];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }


  //packet bytes print
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("--------------Network Capturing--------------");
    printf("Ethsrc : %02X:%02X:%02X:%02X:%02X:%02X\nEthdst : %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    if(packet[12]==8){
        uint16_t i=(packet[14]+20)%20;
        if(i > 0){
            printf("Ipsrc : %d.%d.%d.%d\nIpdst : %d.%d.%d.%d\n",
                   packet[26+i],packet[27+i],packet[28+i],packet[29+i],packet[30+i],packet[31+i],packet[32+i],packet[33+i]);
        }else{
            printf("Ipsrc : %d.%d.%d.%d\nIpdst : %d.%d.%d.%d\n",
                   packet[26],packet[27],packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]);
        }
    }
    if(packet[23]==6){
        uint16_t j=((packet[46]+20)%20);
        if(j>0){
            printf("Tcpsrc : %d\nTcpdst : %d\n",packet[34+j]*256+packet[35+j],packet[36+j]*256+packet[37+j]);
        }else{
            printf("Tcpsrc : %d\nTcpdst : %d\n",packet[34]*256+packet[35],packet[36]*256+packet[37]);
        }
    }
    printf("%u bytes captured\n",header->len);
  }
  pcap_close(handle);
  return 0;
}
