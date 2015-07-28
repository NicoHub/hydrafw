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

#ifndef _FILE_FMT_PCAP_H_
#define _FILE_FMT_PCAP_H_

#include "ch.h"
#include "ff.h"
#include "file_fmt.h"

extern const file_fmt_exec_t file_fmt_pcap_exec;

extern uint8_t tmp_sbuf[50]; //16
extern uint32_t tmp_sbuf_idx;

//API
int sniff_create_pcap_file(uint8_t* buffer, uint32_t size);
FIL file_fmt_create_pcap(void);
int file_fmt_flush_close(FIL FileObject, uint8_t* buffer, uint32_t size);

__attribute__ ((always_inline)) inline
void sniff_write_pcap_global_header(void);

__attribute__ ((always_inline)) inline
void sniff_write_pcap_packet_header (uint32_t nb_cycles_start);

__attribute__ ((always_inline)) inline
void sniff_write_data_header (uint8_t pow, uint32_t protocol, uint32_t speed, uint32_t nb_cycles_end, uint32_t parity);

__attribute__ ((always_inline)) inline
void sniff_write_pcap_data(uint8_t data);

__attribute__ ((always_inline)) inline
void sniff_write_Parity_ASCII(uint8_t data);

uint32_t sniffer_get_size_pcap(void);

uint32_t sniffer_get_pcap_data_size (uint32_t g_sbuf_idx);

uint32_t tmp_sniffer_get_size(void);

#endif
