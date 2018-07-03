/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined SWIFT || defined PDS_TOOL
#include "linux_redefines.h"
#include "stdlib.h"
#include "stddefs.h"
#include "stdio.h"
#else
#include <linux/module.h>
#include <linux/slab.h>
#endif

#include "pds.h"
#include "jsmn/jsmn.h"
#include "export/pds_parser_defs.h"

#define MAX_BUFFER_SIZE (1500)

u8 indexer_level;

/* Implictly initialised to NULL */
static char *file_content;
/* Implictly initialised to NULL */
static PDS_BUFFERS *pds_output_buffers;

static void remove_comments(void);

static char *pds_find_output_string(void);

static int pds_elem_cmp(jsmntok_t *element_array, const char *keyword);
static void pds_elem_write(char *output_string, jsmntok_t *element_array);
static bool pds_elem_write_key(char *output_string, jsmntok_t *element_array, bool *read_keys);
static int pds_array_write(char *output_string, jsmntok_t *element_array);
static int pds_obj_write(char *output_string, jsmntok_t *element_array);
static int pds_msgs_write(jsmntok_t *element_array);

static void pds_integer_to_hex_string(u32 decimal_number, char *convert_buffer);
static u32 pds_baseX_to_int(u8 base, const char *pds_value, u8 pds_value_len);

static void pds_convert_dict_entry(const char *pds_value, u8 pds_value_len);
static const char *pds_convert_value(const char *pds_value, u8 pds_value_ven);

/* PDS Dict :
 * [PDS_KEY][ENTRY_TYPE, ENTRY_VALUE]
 * PPDS_KEY is a string
 * ENTRY_TYPE is one of PDS_DICT_CONV_VALUE
 * ENTRY_VALUE is the dictionary value : a char or an integer
 *
 * Ex.
 * ["KEY1"][IS STR, CHAR_VALUE1, 0]
 * ["KEY2"][IS INT, INT_VALUE2]
 */
static const char *const pds_enum_dict[] = {
	"none",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_NO_PULL),
	"down",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_PULL_DOWN),
	"up",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_PULL_UP),
	"maintain",	 PDS_ENUM_CHAR_TO_STR(PDS_PIN_PULL_MAINTAIN),
	"disabled",	 PDS_ENUM_CHAR_TO_STR(PDS_DISABLED),
	"enabled",	 PDS_ENUM_CHAR_TO_STR(PDS_ENABLED),
	"tri",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_TRISTATE),
	"func",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_FUNC),
	"gpio",		 PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_GPIO),
	"debug",	 PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_DEBUG),
	"clock",	 PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_CLOCK),
	"no_debug",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_DISABLED),
	"debug_mux",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_MUX),
	"tx_iq_out",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_TX_IQ_OUT),
	"rx_iq_out",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_RX_IQ_OUT),
	"tx_iq_in",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_TX_IQ_IN),
	"rx_iq_in",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_RX_IQ_IN),
	"daisy_chained", PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_DCHAINED),
	"ARM9_only",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_ARM9_ONLY),
	"ARM0_only",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_ARM0_ONLY),
	"diag0",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_ANALOG_DIAG0),
	"diag1",	 PDS_ENUM_CHAR_TO_STR(PDS_DBG_ANALOG_DIAG1),
	"tx_cw",	 PDS_ENUM_CHAR_TO_STR(PDS_TEST_TX_CW),
	"tx_packet",	 PDS_ENUM_CHAR_TO_STR(PDS_TEST_TX_PACKET),
	"rx",		 PDS_ENUM_CHAR_TO_STR(PDS_TEST_RX),
	"sleep",	 PDS_ENUM_CHAR_TO_STR(PDS_TEST_SLEEP),
	"MM",		 PDS_ENUM_CHAR_TO_STR(PDS_TX_PACKET_HT_PARAM_MM),
	"GF",		 PDS_ENUM_CHAR_TO_STR(PDS_TX_PACKET_HT_PARAM_GF),
	"single",	 PDS_ENUM_CHAR_TO_STR(PDS_TX_CW_MODE_SINGLE),
	"dual",		 PDS_ENUM_CHAR_TO_STR(PDS_TX_CW_MODE_DUAL),
	"DSSS",		 PDS_ENUM_INT_TO_STR(PDS_MOD_DSSS),
	"CCK",		 PDS_ENUM_INT_TO_STR(PDS_MOD_CCK),
	"BPSK_1_2",  PDS_ENUM_INT_TO_STR(PDS_MOD_BPSK_1_2),
	"BPSK_3_4",  PDS_ENUM_INT_TO_STR(PDS_MOD_BPSK_3_4),
	"QPSK_1_2",  PDS_ENUM_INT_TO_STR(PDS_MOD_QPSK_1_2),
	"QPSK_3_4",  PDS_ENUM_INT_TO_STR(PDS_MOD_QPSK_3_4),
	"QAM16_1_2", PDS_ENUM_INT_TO_STR(PDS_MOD_16QAM_1_2),
	"QAM16_3_4", PDS_ENUM_INT_TO_STR(PDS_MOD_16QAM_3_4),
	"QAM64_1_2", PDS_ENUM_INT_TO_STR(PDS_MOD_64QAM_1_2),
	"QAM64_3_4", PDS_ENUM_INT_TO_STR(PDS_MOD_64QAM_3_4),
	"QAM64_5_6", PDS_ENUM_INT_TO_STR(PDS_MOD_64QAM_5_6),
	"B_1Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_B_1MBPS),
	"B_2Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_B_2MBPS),
	"B_5.5Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_B_5_5MBPS),
	"B_11Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_B_11MBPS),
	"G_6Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_6MBPS),
	"G_9Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_9MBPS),
	"G_12Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_12MBPS),
	"G_18Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_18MBPS),
	"G_24Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_24MBPS),
	"G_36Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_36MBPS),
	"G_48Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_48MBPS),
	"G_54Mbps",	 PDS_ENUM_INT_TO_STR(PDS_RATE_G_54MBPS),
	"N_MCS0",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS0),
	"N_MCS1",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS1),
	"N_MCS2",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS2),
	"N_MCS3",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS3),
	"N_MCS4",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS4),
	"N_MCS5",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS5),
	"N_MCS6",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS6),
	"N_MCS7",	 PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS7),
	"TX1_RX1",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX1_RX1),
	"TX2_RX2",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX2_RX2),
	"TX1_RX2",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX1_RX2),
	"TX2_RX1",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX2_RX1),
	"TX1&2_RX1&2",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX12_RX12),
	"internal",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_DIV_MODE_INTERNAL),
	"external",	 PDS_ENUM_CHAR_TO_STR(PDS_ATNA_DIV_MODE_EXTERNAL),
	NULL,		 NULL
};

static char convert_buffer[16];

#define DEC_TO_ASCII(DEC, HEX) \
	do { \
		if ((DEC) < 10) \
			HEX = (DEC) + '0'; \
		else \
			HEX = (DEC) + 'A' - 10; \
	} while (0)

static char *pds_find_output_string(void)

{
	u8 buffer_index;

	buffer_index = pds_output_buffers->nb_buffers_used;

	pds_output_buffers->output_strings[buffer_index] = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
	pds_output_buffers->output_strings[buffer_index][0] = 0;

	pds_output_buffers->nb_buffers_used++;

	return pds_output_buffers->output_strings[buffer_index];
}

static void pds_integer_to_hex_string(u32 decimal_number, char *convert_buffer)
{
	u32 remainder, quotient;
	u32 index = 0;
	u32 j;
	char revert_value[8];

	quotient = decimal_number;

	if (decimal_number > 15) {
		while (quotient != 0) {
			remainder = quotient % 16;
			DEC_TO_ASCII(remainder, revert_value[index]);

			quotient = quotient / 16;
			index++;
		}

		for (j = 0; j < index; j++)
			convert_buffer[j] = revert_value[index - j - 1];
		convert_buffer[index] = 0;
	} else {
		DEC_TO_ASCII(decimal_number % 16, convert_buffer[0]);
		convert_buffer[1] = 0;
	}
}

static u32 pds_baseX_to_int(u8 base, const char *pds_value,
			    u8 pds_value_len)
{
	u8 dec_value_index = 0;
	u8 char_value = 0;
	u32 dec_value = 0;
	u8 shift_coef = (base == 2 ? 1 : 4);

	while (dec_value_index != pds_value_len) {
		if (pds_value[dec_value_index] == ' ' || pds_value[dec_value_index] == '|') {
			dec_value_index++;
			continue;
		}
		char_value = pds_value[dec_value_index] - '0';
		if (char_value > (base - 1)) {
			convert_buffer[0] = 0;
			break;
		}

		if (base == 10)
			dec_value = (dec_value * 10) + char_value;
		else
			dec_value = (dec_value << shift_coef) + char_value;
		dec_value_index++;
	}

	return dec_value;
}

static void pds_convert_dict_entry(const char *pds_value, u8 pds_value_len)
{
	u8 dict_index;
	enum dict_conv;

	for (dict_index = 0; pds_enum_dict[dict_index * 2]; dict_index++) {
		if (strncmp(pds_enum_dict[dict_index * 2], pds_value, pds_value_len) == 0) {
			if (*pds_enum_dict[dict_index * 2 + 1] == PDS_DICT_ENTRY_VALUE_STR)
				strcpy(convert_buffer, pds_enum_dict[dict_index * 2 + 1] + 1);
			else if (*pds_enum_dict[dict_index * 2 + 1] == PDS_DICT_ENTRY_VALUE_INT)
				pds_integer_to_hex_string(
					*(pds_enum_dict[dict_index * 2 + 1] + 1),
					&convert_buffer[0]);

			break;
		}
	}
}

static const char *pds_convert_value(const char *pds_value, u8 pds_value_ven)
{
	u8 char_index = 0;
	u32 dec_value = 0;

	convert_buffer[0] = pds_value[0];

	if ((pds_value[0] == '-' || pds_value[0] == '+') &&
	    (pds_value[1] >= '0' && pds_value[1] <= '9')) {
		dec_value = pds_baseX_to_int(
			10, pds_value + 1,
			pds_value_ven - 1);
		pds_integer_to_hex_string(dec_value, &convert_buffer[1]);
	} else if (pds_value[0] >= '0' && pds_value[0] <= '9') {
		dec_value = pds_baseX_to_int(
			10, pds_value,
			pds_value_ven);
		pds_integer_to_hex_string(dec_value, &convert_buffer[0]);
	} else if (pds_value_ven != 1) {
		if (pds_value[0] == 'b') {
			dec_value = pds_baseX_to_int(2, &pds_value[1], pds_value_ven - 1);
			pds_integer_to_hex_string(dec_value, &convert_buffer[0]);
		} else if (pds_value[0] == 'x' || pds_value[0] == 'X' ||
			   pds_value[0] == 'h' || pds_value[0] == 'H') {
			while (char_index != (pds_value_ven - 1)) {
				convert_buffer[char_index] = pds_value[char_index + 1];
				char_index++;
			}
			convert_buffer[char_index] = 0;
		} else {
			pds_convert_dict_entry(pds_value, pds_value_ven);
		}
	}
	return convert_buffer;
}

static int pds_elem_cmp(jsmntok_t *element_array, const char *keyword)
{
	u8 keyword_length = strlen(keyword);
	u8 element_name_length =
		(u8)(element_array->end - element_array->start);
	u8 cmp_len = min(element_name_length, keyword_length);

	if (element_array->type == JSMN_STRING) {
		if ((int)strlen(keyword) <=
		    element_array->end - element_array->start) {
			if (strncmp(
				    &file_content[element_array->start],
				    keyword,
				    cmp_len) == 0
			    )
				return 0;
		}
	}
	return -1;
}

static void pds_elem_write(char *output_string, jsmntok_t *element_array)
{
	const char *compressed_value;

	compressed_value = pds_convert_value(
		&file_content[element_array->start],
		element_array->end - element_array->start);

	strncat(output_string, compressed_value, MAX_BUFFER_SIZE);
}

static bool pds_elem_write_key(char *output_string,
			       jsmntok_t *element_array, bool *read_keys)
{
	char key[2];
	int is_duplicate_key;

	key[0] = file_content[element_array->end - 1];
	key[1] = 0;

	if (!read_keys || !read_keys[key[0] - 'a']) {
		strncat(output_string, key, MAX_BUFFER_SIZE);

		if (read_keys)
			read_keys[key[0] - 'a'] = true;

		is_duplicate_key = false;
	} else {
		is_duplicate_key = true;
	}

	return is_duplicate_key;
}

static int pds_array_write(char *output_string, jsmntok_t *element_array)
{
	int element_lndex = 0;
	int global_elem_idx;
	int is_first_element = 1;

	strncat(output_string, "[", MAX_BUFFER_SIZE);

	global_elem_idx = 1;
	for (element_lndex = 0; element_lndex < element_array->size;
	     element_lndex++) {
		if (is_first_element != 1)
			strncat(output_string, ",", MAX_BUFFER_SIZE);
		switch (element_array[global_elem_idx].type) {
		case JSMN_OBJECT:
			global_elem_idx +=
				pds_obj_write(output_string, &element_array[global_elem_idx]);
			break;
		case JSMN_STRING:
		case JSMN_PRIMITIVE:
			if (pds_elem_cmp(&element_array[global_elem_idx], "// comment") == 0) {
				element_lndex++;
				global_elem_idx += 2;
			} else {
				pds_elem_write(output_string, &element_array[global_elem_idx]);
				global_elem_idx++;
			}
			break;
		case JSMN_ARRAY:
			pds_array_write(output_string, &element_array[global_elem_idx]);
			break;
		default:
			// Impossible JSMN_UNDEFINED is JSMN_PRIMITIVE.
			break;
		}

		is_first_element = 0;
	}
	strncat(output_string, "]", MAX_BUFFER_SIZE);

	return global_elem_idx;
}

static int pds_obj_write(char *output_string, jsmntok_t *element_array)
{
	int element_index = 1;
	int global_elem_idx;
	bool is_first_element = true;
	bool skip_next_coma = true;
	bool read_keys[32] = { false };

	indexer_level++;

	global_elem_idx = 1;
	if (indexer_level == 1)
		output_string = pds_find_output_string();

	if (output_string)
		strncat(output_string, "{", MAX_BUFFER_SIZE);

	for (; element_index < element_array->size * 2; element_index++) {
		if (pds_elem_cmp(&element_array[global_elem_idx], "// comment") == 0) {
			element_index++;
			global_elem_idx += 2;
		} else {
			if (!is_first_element && !skip_next_coma)
				strncat(output_string, ",", MAX_BUFFER_SIZE);

			skip_next_coma = false;

			switch (element_array[global_elem_idx + 1].type) {
			case JSMN_STRING:
			case JSMN_PRIMITIVE:
				/* Do not compress duplicate keys elements */
				if (!pds_elem_write_key(
					    output_string,
					    &element_array[global_elem_idx],
					    read_keys)) {

					strncat(output_string, ":", MAX_BUFFER_SIZE);

					pds_elem_write(
						output_string,
						&element_array[global_elem_idx + 1]);
				} else {
					skip_next_coma = 1;
				}
				global_elem_idx += 2;
				element_index++;
				break;

			case  JSMN_OBJECT:
				pds_elem_write_key(
					output_string,
					&element_array[global_elem_idx],
					NULL);

				strncat(output_string, ":", MAX_BUFFER_SIZE);

				global_elem_idx +=
					pds_obj_write(
						output_string,
						&element_array[global_elem_idx + 1]) + 1;
				element_index++;
				break;

			case JSMN_ARRAY:
				pds_elem_write_key(
					output_string,
					&element_array[global_elem_idx],
					NULL);

				strncat(output_string, ":", MAX_BUFFER_SIZE);

				global_elem_idx += pds_array_write(
					output_string,
					&element_array[global_elem_idx + 1]) + 1;
				element_index++;
				break;
			default:
				// Impossible JSMN_UNDEFINED is JSMN_PRIMITIVE.
				break;
			}
			is_first_element = false;
		}
	}

	if (output_string)
		strncat(output_string, "}", MAX_BUFFER_SIZE);

	indexer_level--;

	return global_elem_idx;
}

static int pds_msgs_write(jsmntok_t *element_array)
{
	int element_index = 1;
	int global_elem_idx;

	global_elem_idx = 1;

	for (; element_index < element_array->size * 2; element_index++) {
		if (pds_elem_cmp(&element_array[global_elem_idx], "// comment") == 0) {
			element_index++;
			global_elem_idx += 2;
		} else {
			if (element_array[global_elem_idx + 1].type ==
			    JSMN_OBJECT) {
				global_elem_idx += pds_obj_write(
					NULL,
					&element_array[global_elem_idx + 1]) + 1;
				element_index++;
			}
		}
	}

	return 0;
}

PDS_BUFFERS *pds_compress_json(const char *input_string, size_t size)
{
	int parser_result;
	jsmn_parser jsmn_parser;
	jsmntok_t *element_array;
	u16 nb_tokens = 256;

	element_array = kmalloc_array(nb_tokens, sizeof(jsmntok_t), GFP_KERNEL);
	pds_output_buffers = kmalloc(sizeof(PDS_BUFFERS), GFP_KERNEL);

	memset(pds_output_buffers, 0, sizeof(PDS_BUFFERS));

	file_content = kmalloc(sizeof(char) * (size + 1), GFP_KERNEL);
	memcpy(file_content, input_string, sizeof(char) * size);

	/* Make sure that s_pc_fileContent last character is a 0,
	 *  no matter what's in
	 */
	file_content[size] = 0;

	remove_comments();

	jsmn_init(&jsmn_parser);

	do {
		parser_result = jsmn_parse(
			&jsmn_parser,
			file_content, size,
			element_array,
			nb_tokens);

		if (parser_result == JSMN_ERROR_NOMEM) {
			nb_tokens += 256;
			element_array = (jsmntok_t *)krealloc(
				element_array,
				sizeof(jsmntok_t) * nb_tokens,
				GFP_KERNEL);
		}
	} while (parser_result == JSMN_ERROR_NOMEM);

	indexer_level = 0;
	pds_msgs_write(element_array);

	kfree(element_array);
	kfree(file_content);

	return pds_output_buffers;
}

void pds_release_buffers(PDS_BUFFERS *pds_buffers)
{
	u8 buffer_index;

	for (buffer_index = 0;
	     buffer_index < pds_buffers->nb_buffers_used;
	     buffer_index++)
		kfree(pds_output_buffers->output_strings[buffer_index]);
	kfree(pds_buffers);
}

#define PUTC(c) (file_content[index] = (c))
#define GETC() file_content[index]
#define GETC_NEXT() file_content[index + 1]

static void remove_comments(void)
{
	/*s_pc_fileContent */
	u32 index = 0;
	bool is_comment = true;

	while ((file_content[index + 1]) != 0) {
		if (GETC() == '/' && GETC_NEXT() == '/') {
			/* opening comment ? */
			is_comment = true;
			do {
				if (GETC() == 0x0A)
					is_comment = false;
				else
					/* replace comment with space */
					PUTC(' ');
				index++;
			} while (is_comment);
		}

		if (GETC() == '/' && GETC_NEXT() == '*') {
			/* opening comment ? */
			is_comment = true;
			do {
				if (GETC() == '*' && GETC_NEXT() == '/') {
					PUTC(' ');
					index++;
					PUTC(' ');
					is_comment = false;
				} else {
					/* replace comment with space */
					PUTC(' ');
				}
				index++;
			} while (is_comment);
		}

		if (GETC() == '\"') {
			index++;

			while (GETC() != '\"')
				index++;
		}

		if (GETC() == '\'') {
			index++;

			while (GETC() != '\'')
				index++;
		}

		index++;
	}
}
