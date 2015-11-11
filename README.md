# ESP8266 packet injection/sniffer example

This example project utilizes sniffer capabilities of
ESP8266 to perform a simulated attack. The communication between the
victim and access point (AP) is traced by `wifi_set_promiscuous_rx_cb`
while packet injection is performed by `wifi_send_pkt_freedom`. A callback registered with `wifi_register_send_pkt_freedom_cb` will fire each time a packet is successfully sent.

### Running:
Changes to the Makefile are probably necessary. 

The rest of the code will compile and run without modification but for full functionality you should change the address variables in user/user_main.c L#19,22.

##### Why not send deauth packets?
Espressif has disabled sending management frames with `wifi_send_pkt_freedom`, see http://bbs.espressif.com/viewtopic.php?f=7&t=1357

### Requirements:
Minimum SDK version 1.4.0

A wifi card capable of monitor mode if you'd like to see sent packets