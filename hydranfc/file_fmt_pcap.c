/*
 * HydraBus/HydraNFC
 *
 * Copyright (C) 2012-2014 Benjamin VERNOUX
 * Copyright (C) 2015 Nicolas CHAUVEAU
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "file_fmt_pcap.h"
#include "file_fmt.h"

#include <stdarg.h>
#include <stdio.h> /* sprintf */

#include "ch.h"
#include "hal.h"
#include "shell.h"

#include "mcu.h"
#include "trf797x.h"
#include "types.h"

#include "hydranfc.h"
#include "hydranfc_cmd_sniff_iso14443.h"
#include "hydranfc_cmd_sniff_downsampling.h"

#include "common.h"
#include "microsd.h"
#include "ff.h"

static filename_t write_filename;

uint8_t tmp_sbuf[50];
uint32_t tmp_sbuf_idx;

void tprintp(const char *fmt, ...)
{
    va_list va_args;
    int real_size;
    #define TPRINTF_BUFF_SIZE (255)

    char tprintf_buff[TPRINTF_BUFF_SIZE+1];

    va_start(va_args, fmt);
    real_size = vsnprintf(tprintf_buff, TPRINTF_BUFF_SIZE, fmt, va_args);

    if (SDU1.config->usbp->state == USB_ACTIVE)
        chSequentialStreamWrite((BaseSequentialStream*)&SDU1, (uint8_t *)tprintf_buff, real_size);

    if (SDU2.config->usbp->state == USB_ACTIVE)
        chSequentialStreamWrite((BaseSequentialStream*)&SDU2, (uint8_t *)tprintf_buff, real_size);

    va_end(va_args);
}

FIL file_fmt_create_pcap()
{
	uint32_t i;
    FRESULT err;
    FIL FileObject;

    if (is_fs_ready()==FALSE)
    {
        if (mount() != 0)
        {
            tprintp("SD card mount error \r\n");
        }
    }
    else
    {
        umount();
        if (mount() != 0)
        {
            tprintp("SD card mount error \r\n");
        }
    }

    for(i=0; i<999; i++)
    {

       sprintf(write_filename.filename, "0:nfc_sniff_%ld.pcap", i);

       err = f_open(&FileObject, write_filename.filename, FA_WRITE | FA_CREATE_NEW);

        if (err == FR_OK)
        {
            break;
        }
    }
    tprintp("open_file %s \r\n", &write_filename.filename[2]);
	return FileObject;
}

int file_fmt_flush_close(FIL FileObject, uint8_t* buffer, uint32_t size)
{

    FRESULT err;
    uint32_t bytes_written;
    err = f_write(&FileObject, buffer, size, (void *)&bytes_written);
    tprintp("write_file %s \r\n", &write_filename.filename[2]);
    if (err != FR_OK)
        {
            f_close(&FileObject);
            umount();
            return -3;
        }

        err = f_close(&FileObject);
        if (err != FR_OK)
        {
            umount();
            return -4;
        }
    umount();
    return 0;
}

__attribute__ ((always_inline)) inline
void sniff_write_pcap_global_header() /*MSB*/
{
    uint32_t i;
    i = g_sbuf_idx;

    //magic_number nsecond resolution
    g_sbuf[i+0] = 0xa1;
    g_sbuf[i+1] = 0xb2;
    g_sbuf[i+2] = 0x3c;
    g_sbuf[i+3] = 0x4d;

    //version_major
    g_sbuf[i+4] = 0x0;
    g_sbuf[i+5] = 0x2;

    //version_minor
    g_sbuf[i+6] = 0x0;
    g_sbuf[i+7] = 0x4;

    //thiszone
    g_sbuf[i+8] = 0x0;
    g_sbuf[i+9] = 0x0;
    g_sbuf[i+10] = 0x0;
    g_sbuf[i+11] = 0x0;

    //sigfigs
    g_sbuf[i+12] = 0x0;
    g_sbuf[i+13] = 0x0;
    g_sbuf[i+14] = 0x0;
    g_sbuf[i+15] = 0x0;

    //snaplen
    g_sbuf[i+16] = 0x00;
    g_sbuf[i+17] = 0x00;
    g_sbuf[i+18] = 0xff;
    g_sbuf[i+19] = 0xff;

    //linktype
    g_sbuf[i+20] = 0x0;
    g_sbuf[i+21] = 0x0;
    g_sbuf[i+22] = 0x0;
    g_sbuf[i+23] = 0x93; /*(0x93=>0xa2)  private use*/

    g_sbuf_idx +=24;
}

__attribute__ ((always_inline)) inline
void sniff_write_pcap_packet_header(uint32_t nb_cycles_start) /*MSB*/
{
    uint32_t i;
	i = g_sbuf_idx;

    uint32_t second, nsecond, data_size;
    uint8_t val;

    second = nb_cycles_start/168000000;
    nsecond = (nb_cycles_start % 168000000)/168 *1000;

    //ts-sec
    //Epoch time:555d03e0 = 05/21/2015 00:00:00
    val = ((second & 0xFF000000) >> 24);
    g_sbuf[i+0] = 0x55 + val;
    val = ((second & 0x00FF0000) >> 16);
    g_sbuf[i+1] = 0x5d + val;
    val = ((second & 0x0000FF00) >> 8);
    g_sbuf[i+2] = 0x03 + val;
    val = (second & 0x000000FF);
    g_sbuf[i+3] = 0xe0 + val;

    //ts-nsec
    val = ((nsecond & 0xFF000000) >> 24);
    g_sbuf[i+4] = val;
    val = ((nsecond & 0x00FF0000) >> 16);
    g_sbuf[i+5] = val;
    val = ((nsecond & 0x0000FF00) >> 8);
    g_sbuf[i+6] = val;
    val = (nsecond & 0x000000FF);
    g_sbuf[i+7] = val;

    //data size
    if (tmp_sniffer_get_size() == 0) /*for ISO 7816*/
        {
            data_size = tmp_sniffer_get_size()+9;
        }
    else
    data_size = tmp_sniffer_get_size()+8; /*8 = header packet size*/

    val = ((data_size & 0xFF000000) >> 24);
    g_sbuf[i+8] = val;
    val = ((data_size & 0x00FF0000) >> 16);
    g_sbuf[i+9] = val;
    val = ((data_size & 0x0000FF00) >> 8);
    g_sbuf[i+10] = val;
    val = (data_size & 0x000000FF);
    g_sbuf[i+11] = val;

    val = ((data_size & 0xFF000000) >> 24);
    g_sbuf[i+12] = val;
    val = ((data_size & 0x00FF0000) >> 16);
    g_sbuf[i+13] = val;
    val = ((data_size & 0x0000FF00) >> 8);
    g_sbuf[i+14] = val;
    val = (data_size & 0x000000FF);
    g_sbuf[i+15] = val;

    g_sbuf_idx +=16;
}

__attribute__ ((always_inline)) inline
void sniff_write_data_header (uint8_t pow, uint32_t protocol, uint32_t speed, uint32_t nb_cycles_end, uint32_t parity)
{
    uint32_t i;
    i = g_sbuf_idx;

    // power
    g_sbuf[i+0] = pow;


    // norm
    switch (protocol)
    {
    case 1:  /*A PCD*/
        g_sbuf[i+1] = 0xb0;
        break;

    case 2:  /*A PICC*/
        g_sbuf[i+1] = 0xb1;
        break;

    default: /*Unknown*/
        g_sbuf[i+1] = 0xb2;
        break;
    }

    // speed
    if (protocol == 1 || protocol == 2)   /*A PCD && A PICC*/
        {
            switch (speed)
            {
            case 1:  /*106*/
                g_sbuf[i+2] = 0xc0;
                break;

            case 2:  /*212*/
                g_sbuf[i+2] = 0xc1;
                break;

            case 3:  /*424*/
                g_sbuf[i+2] = 0xc2;
                break;

            /*848 not supported*/
            }
        }
    else g_sbuf[i+2] = 0xc0;;               /* B PCD; B PICC;...*/

    //timestamp
    uint8_t val;

	val = ((nb_cycles_end & 0xFF000000) >> 24);
	g_sbuf[i+3] = val;
	val = ((nb_cycles_end & 0x00FF0000) >> 16);
	g_sbuf[i+4] = val;
	val = ((nb_cycles_end & 0x0000FF00) >> 8);
	g_sbuf[i+5] = val;
	val = (nb_cycles_end & 0x000000FF);
	g_sbuf[i+6] = val;


    //odd parity bit option
    if (parity == 0)
            g_sbuf[i+7] = 0xd0;
    else
            g_sbuf[i+7] = 0xd1;

    g_sbuf_idx +=8;
}

uint32_t tmp_sniffer_get_size(void)
{
    return tmp_sbuf_idx;
}

__attribute__ ((always_inline)) inline
void sniff_write_pcap_data(uint8_t data)
{
    uint32_t i;
    i = tmp_sbuf_idx;

    tmp_sbuf[i+0] = data;
    tmp_sbuf_idx +=1;
}

__attribute__ ((always_inline)) inline
void sniff_write_Parity_ASCII(uint8_t data)
{
	uint32_t i;
	i = g_sbuf_idx;

	g_sbuf[i+0] = data;
	g_sbuf_idx +=1;
}

const file_fmt_exec_t file_fmt_pcap_exec = {
.file_fmt_create = &file_fmt_create_pcap,
};
