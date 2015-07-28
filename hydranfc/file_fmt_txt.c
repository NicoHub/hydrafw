/* Return 0 if OK else < 0 error code */
int sniff_write_file(uint8_t* buffer, uint32_t size)
{
	uint32_t i;
	FRESULT err;
	FIL FileObject;
	uint32_t bytes_written;

	if (size == 0) {
		return -1;
	}

	if (is_fs_ready()==FALSE) {
		if (mount() != 0) {
			return -5;
		}
	} else {
		umount();
		if (mount() != 0) {
			return -5;
		}
	}

	/* Save data in file */
	for(i=0; i<999; i++) {
		sprintf(write_filename.filename, "0:nfc_sniff_%ld.txt", i);				/*int sprintf(char *str, const char *format, ...) sends formated output to a string pointed to by str.*/
		err = f_open(&FileObject, write_filename.filename, FA_WRITE | FA_CREATE_NEW);			/* Open or Create a File. voir ff.c ligne 2415*/
		if (err == FR_OK) {
			break;
		}
	}
	if (err == FR_OK) {
		err = f_write(&FileObject, buffer, size, (void *)&bytes_written);			/*  Write File voir ff.c ligne 2641*/
		if (err != FR_OK) {
			f_close(&FileObject);													/*  Close File voir ff.c ligne 2822*/
			umount();
			return -3;
		}

		err = f_close(&FileObject);
		if (err != FR_OK) {
			umount();
			return -4;
		}
	} else {
		umount();
		return -2;
	}

	umount();
	return 0;
}

__attribute__ ((always_inline)) static inline
void sniff_write_pcd(void)
{
	/* Write output buffer 4 space (data format Miller Modified):
	  It means Reader/Writer (PCD – Proximity Coupling Device)
	*/
	uint32_t i, nb_cycles;
	uint8_t val;

	i = g_sbuf_idx;
	g_sbuf[i+0] = '\r';
	g_sbuf[i+1] = '\n';

	nb_cycles = get_cyclecounter();
	val = ((nb_cycles & 0xFF000000) >> 24);
	g_sbuf[i+2] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+3] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x00FF0000) >> 16);
	g_sbuf[i+4] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+5] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x0000FF00) >> 8);
	g_sbuf[i+6] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+7] = htoa[(val & 0x0F)];
	val = (nb_cycles & 0x000000FF);
	g_sbuf[i+8] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+9] = htoa[(val & 0x0F)];
	g_sbuf[i+10] = '\t';

	g_sbuf[i+11] = 'R';
	g_sbuf[i+12] = 'D';
	g_sbuf[i+13] = 'R';
	g_sbuf[i+14] = '\t';
	g_sbuf_idx +=15;
}

__attribute__ ((always_inline)) static inline
void sniff_write_picc(void)
{
	/* Write output buffer "TAG"+1 space (data format Manchester):
	  It means TAG(PICC – Proximity Integrated Circuit Card)
	*/
	uint32_t i, nb_cycles;
	uint8_t val;

	i = g_sbuf_idx;
	g_sbuf[i+0] = '\r';
	g_sbuf[i+1] = '\n';

	nb_cycles = get_cyclecounter();
	val = ((nb_cycles & 0xFF000000) >> 24);
	g_sbuf[i+2] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+3] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x00FF0000) >> 16);
	g_sbuf[i+4] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+5] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x0000FF00) >> 8);
	g_sbuf[i+6] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+7] = htoa[(val & 0x0F)];
	val = (nb_cycles & 0x000000FF);
	g_sbuf[i+8] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+9] = htoa[(val & 0x0F)];
	g_sbuf[i+10] = '\t';

	g_sbuf[i+11] = 'T';
	g_sbuf[i+12] = 'A';
	g_sbuf[i+13] = 'G';
	g_sbuf[i+14] = '\t';
	g_sbuf_idx +=15;
}

__attribute__ ((always_inline)) static inline
void sniff_write_unknown_protocol(uint8_t data)
{
	/* Unknown Protocol */
	/* TODO: Detect other coding */
	// In Freq of 3.39MHz => 105.9375KHz on 8bits (each bit is 848KHz so 2bits=423.75KHz)
	/*
	  data  = (downsample_4x[(f_data>>24)])<<6;
	  data |= (downsample_4x[((f_data&0x00FF0000)>>16)])<<4;
	  data |= (downsample_4x[((f_data&0x0000FF00)>>8)])<<2;
	  data |= (downsample_4x[(f_data&0x000000FF)]);
	*/
	uint32_t i, nb_cycles;
	uint8_t val;

	i = g_sbuf_idx;
	g_sbuf[i+0] = '\r';
	g_sbuf[i+1] = '\n';

	nb_cycles = get_cyclecounter();
	val = ((nb_cycles & 0xFF000000) >> 24);
	g_sbuf[i+2] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+3] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x00FF0000) >> 16);
	g_sbuf[i+4] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+5] = htoa[(val & 0x0F)];
	val = ((nb_cycles & 0x0000FF00) >> 8);
	g_sbuf[i+6] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+7] = htoa[(val & 0x0F)];
	val = (nb_cycles & 0x000000FF);
	g_sbuf[i+8] = htoa[(val & 0xF0) >> 4];
	g_sbuf[i+9] = htoa[(val & 0x0F)];
	g_sbuf[i+10] = '\t';

	g_sbuf[i+11] = 'U';
	g_sbuf[i+12] = htoa[(data & 0xF0) >> 4];
	g_sbuf[i+13] = htoa[(data & 0x0F)];
	g_sbuf[i+14] = '\t';
	g_sbuf_idx +=15;
}

__attribute__ ((always_inline)) static inline
void sniff_write_8b_ASCII_HEX(uint8_t data, bool add_space)					/* hexa -> 8 bits ASCII   */
{
	uint32_t i;

	i = g_sbuf_idx;
	g_sbuf[i+0] = htoa[(data & 0xF0) >> 4];
	g_sbuf[i+1] = htoa[(data & 0x0F)];
	if (add_space == TRUE) {
		g_sbuf[i+2] = ' ';
		g_sbuf_idx +=3;
	} else {
		g_sbuf_idx +=2;
	}
}
