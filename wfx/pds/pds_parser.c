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

u8 ui8_IndexerLevel;


static char *s_pc_fileContent = NULL;
static PDS_BUFFERS *s_ps_PdsOutputBuffers = NULL;

static void remove_comments(void);

static char * pds_find_output_string(u8 ui8_BufferIndex);

static int pds_elem_cmp(jsmntok_t *ps_ElementArray, const char *cpc_Keyword);
static void pds_elem_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static bool pds_elem_write_key(char* pc_OutputString, jsmntok_t *ps_ElementArray,bool *ab_readKeys);
static int pds_array_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static int pds_obj_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static int pds_msgs_write(jsmntok_t *ps_ElementArray);

static void pds_integer_to_hex_string(u32 decimalNumber, char *pc_convertBuffer);
static u32 pds_baseX_to_int(u8 ui8_base, const char* cpc_PdsValue, u8 ui8_PdsValueLen);

static void pds_convert_dict_entry(const char* cpc_PdsValue, u8 ui8_PdsValueLen);
static const char* pds_convert_value(const char* cpc_PdsValue, u8 ui8_PdsValueLen);

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
static const char* acpc_JsonValueDictionnary[] = {
        "none",      PDS_ENUM_CHAR_TO_STR(PDS_PIN_NO_PULL),
        "down",      PDS_ENUM_CHAR_TO_STR(PDS_PIN_PULL_DOWN),
        "up",        PDS_ENUM_CHAR_TO_STR(PDS_PIN_PULL_UP),
        "disabled",  PDS_ENUM_CHAR_TO_STR(PDS_DISABLED),
        "enabled",   PDS_ENUM_CHAR_TO_STR(PDS_ENABLED),
        "tri",       PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_TRISTATE),
        "func",      PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_FUNC),
        "gpio",      PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_GPIO),
        "debug",     PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_DEBUG),
        "clock",     PDS_ENUM_CHAR_TO_STR(PDS_PIN_MODE_CLOCK),
        "no_debug",  PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_DISABLED),
        "debug_mux", PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_MUX),
        "tx_iq_out", PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_TX_IQ_OUT),
        "rx_iq_out", PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_RX_IQ_OUT),
        "tx_iq_in",  PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_TX_IQ_IN),
        "rx_iq_in",  PDS_ENUM_CHAR_TO_STR(PDS_DBG_DIG_RX_IQ_IN),
        "daisy_chained", PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_DCHAINED),
        "ARM9_only",     PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_ARM9_ONLY),
        "ARM0_only",     PDS_ENUM_CHAR_TO_STR(PDS_DBG_JTAG_MODE_ARM0_ONLY),
        "diag0",     PDS_ENUM_CHAR_TO_STR(PDS_DBG_ANALOG_DIAG0),
        "diag1",     PDS_ENUM_CHAR_TO_STR(PDS_DBG_ANALOG_DIAG1),
        "tx_cw",     PDS_ENUM_CHAR_TO_STR(PDS_TEST_TX_CW),
        "tx_packet", PDS_ENUM_CHAR_TO_STR(PDS_TEST_TX_PACKET),
        "rx",        PDS_ENUM_CHAR_TO_STR(PDS_TEST_RX),
        "MM",       PDS_ENUM_CHAR_TO_STR(PDS_TX_PACKET_HT_PARAM_MM),
        "GF",       PDS_ENUM_CHAR_TO_STR(PDS_TX_PACKET_HT_PARAM_GF),
        "single",   PDS_ENUM_CHAR_TO_STR(PDS_TX_CW_MODE_SINGLE),
        "dual",     PDS_ENUM_CHAR_TO_STR(PDS_TX_CW_MODE_DUAL),
        "B_1Mbps",  PDS_ENUM_INT_TO_STR(PDS_RATE_B_1Mbps),
        "B_2Mbps",  PDS_ENUM_INT_TO_STR(PDS_RATE_B_2Mbps),
        "B_5.5Mbps",PDS_ENUM_INT_TO_STR(PDS_RATE_B_5_5Mbps),
        "B_11Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_B_11Mbps),
        "G_6Mbps",  PDS_ENUM_INT_TO_STR(PDS_RATE_G_6Mbps),
        "G_9Mbps",  PDS_ENUM_INT_TO_STR(PDS_RATE_G_9Mbps),
        "G_12Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_12Mbps),
        "G_18Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_18Mbps),
        "G_24Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_24Mbps),
        "G_36Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_36Mbps),
        "G_48Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_48Mbps),
        "G_54Mbps", PDS_ENUM_INT_TO_STR(PDS_RATE_G_54Mbps),
        "N_MCS0",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS0),
        "N_MCS1",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS1),
        "N_MCS2",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS2),
        "N_MCS3",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS3),
        "N_MCS4",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS4),
        "N_MCS5",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS5),
        "N_MCS6",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS6),
        "N_MCS7",   PDS_ENUM_INT_TO_STR(PDS_RATE_N_MCS7),
        "TX1_RX1",  PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX1_RX1),
        "TX2_RX2",  PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX2_RX2),
        "TX1_RX2",  PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX1_RX2),
        "TX2_RX1",  PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX2_RX1),
        "TX1&2_RX1&2",  PDS_ENUM_CHAR_TO_STR(PDS_ATNA_SEL_TX12_RX12),
        "internal", PDS_ENUM_CHAR_TO_STR(PDS_ATNA_DIV_MODE_INTERNAL),
        "external", PDS_ENUM_CHAR_TO_STR(PDS_ATNA_DIV_MODE_EXTERNAL),
        NULL, NULL };


static char ac_convertBuffer[16];

#define DEC_TO_ASCII(DEC,HEX) \
        if( (DEC) < 10) \
           HEX = (DEC) + '0'; \
        else \
            HEX = (DEC) + 'A' - 10 ; 

static char * pds_find_output_string(u8 ui8_BufferIndex)
{
    ui8_BufferIndex = s_ps_PdsOutputBuffers->u8_NbBuffersUsed;

    s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex] = (char*)kmalloc(MAX_BUFFER_SIZE,GFP_KERNEL);
    s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex][0] = 0;

    s_ps_PdsOutputBuffers->u8_NbBuffersUsed++;

    return s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex];
}

static void pds_integer_to_hex_string(u32 decimalNumber, char *pc_convertBuffer)
{
    u32 remainder,quotient;
    u32 index=0;
    u32 j;
    char ac_RevertValue[8];
    quotient = decimalNumber;

    if(decimalNumber > 15)
    {
        while(quotient!=0)
        {
            remainder = quotient % 16;
            DEC_TO_ASCII(remainder,ac_RevertValue[index]);

            quotient = quotient / 16;
            index++;
        }

        for (j = 0; j < index; j++)
        {
            pc_convertBuffer[j] = ac_RevertValue[index-j-1];
        }
        pc_convertBuffer[index] = 0;
    }
    else
    {
        DEC_TO_ASCII(decimalNumber%16,pc_convertBuffer[0]);
        pc_convertBuffer[1] = 0;
    }

    return;
}

static u32 pds_baseX_to_int(u8 ui8_base, const char* cpc_PdsValue, u8 ui8_PdsValueLen)
{
    u8 ui8_DecValueIndex = 0;
    u8 ui8_charValue = 0;
    u32 ui32_DecValue = 0;
    u8 ui8_shiftCoef = (ui8_base == 2 ? 1 : 4);

    while(ui8_DecValueIndex != ui8_PdsValueLen)
    {
        if(cpc_PdsValue[ui8_DecValueIndex] == ' ' || cpc_PdsValue[ui8_DecValueIndex] == '|')
        {
            ui8_DecValueIndex++;
            continue;
        }
        ui8_charValue = cpc_PdsValue[ui8_DecValueIndex] - '0';
        if (ui8_charValue > (ui8_base-1) )
        {
            ac_convertBuffer[0] = 0;
            break;
        }

        if( 10 == ui8_base)
        {
            ui32_DecValue = (ui32_DecValue * 10) + ui8_charValue;
        }
        else
        {
            ui32_DecValue = (ui32_DecValue << ui8_shiftCoef) + ui8_charValue;
        }
        ui8_DecValueIndex++;
    }

    return ui32_DecValue;
}

static void pds_convert_dict_entry(const char* cpc_PdsValue, u8 ui8_PdsValueLen)
{
    u8 ui8_DictIndex;

    for (ui8_DictIndex = 0; acpc_JsonValueDictionnary[ui8_DictIndex*2] != NULL; ui8_DictIndex++)
    {
        if(0 == strncmp(
                acpc_JsonValueDictionnary[ui8_DictIndex*2],
                cpc_PdsValue,
                ui8_PdsValueLen))
        {
            if(PDS_DICT_ENTRY_VALUE_STR == *acpc_JsonValueDictionnary[ui8_DictIndex*2+1])
            {
                strcpy( ac_convertBuffer,
                        acpc_JsonValueDictionnary[ui8_DictIndex*2+1]+1);
            }
            else if(PDS_DICT_ENTRY_VALUE_INT == *acpc_JsonValueDictionnary[ui8_DictIndex*2+1])
            {
                pds_integer_to_hex_string(
                        *(acpc_JsonValueDictionnary[ui8_DictIndex*2+1]+1),
                        &ac_convertBuffer[0]);
            }
            break;
        }
    }

    return;
}

static const char* pds_convert_value(const char* cpc_PdsValue, u8 ui8_PdsValueLen)
{
    u8 ui8_CharIndex = 0;
    u32 ui32_DecValue = 0;
    ac_convertBuffer[0] = cpc_PdsValue[0];

    if((cpc_PdsValue[0] == '-' || cpc_PdsValue[0] == '+') && (cpc_PdsValue[1] >= '0' && cpc_PdsValue[1] <= '9'))
    {
        ui32_DecValue = pds_baseX_to_int(10, cpc_PdsValue+1, ui8_PdsValueLen-1);
        pds_integer_to_hex_string(ui32_DecValue,&ac_convertBuffer[1]);
    }
    else if(cpc_PdsValue[0] >= '0' && cpc_PdsValue[0] <= '9')
    {
        ui32_DecValue = pds_baseX_to_int(10, cpc_PdsValue, ui8_PdsValueLen);
        pds_integer_to_hex_string(ui32_DecValue,&ac_convertBuffer[0]);
    }
    else if(1 != ui8_PdsValueLen)
    {
        if(cpc_PdsValue[0] == 'b')
        {
            ui32_DecValue = pds_baseX_to_int(2,&cpc_PdsValue[1],ui8_PdsValueLen-1);
            pds_integer_to_hex_string(ui32_DecValue,&ac_convertBuffer[0]);
        }
        else if(cpc_PdsValue[0] == 'x' ||  cpc_PdsValue[0] == 'X' ||
                cpc_PdsValue[0] == 'h' ||  cpc_PdsValue[0] == 'H')
        {
            while(ui8_CharIndex != (ui8_PdsValueLen-1))
            {
                ac_convertBuffer[ui8_CharIndex] = cpc_PdsValue[ui8_CharIndex+1];
                ui8_CharIndex++;
            }
            ac_convertBuffer[ui8_CharIndex] = 0;
        }
        else
        {
            pds_convert_dict_entry(cpc_PdsValue,ui8_PdsValueLen);
        }
    }
    return ac_convertBuffer;
}

static int pds_elem_cmp(jsmntok_t *ps_ElementArray, const char *cpc_Keyword)
{
    u8 ui8_KeywordLength = strlen(cpc_Keyword);
    u8 ui8_ElementNameLength =  (uint8_t)(ps_ElementArray->end - ps_ElementArray->start);
    u8 ui8_CmpLen = min(ui8_ElementNameLength,ui8_KeywordLength);

    if (ps_ElementArray->type == JSMN_STRING)
    {
        if((int) strlen(cpc_Keyword) <= ps_ElementArray->end - ps_ElementArray->start)
        {
            if(0 == strncmp(
                    &s_pc_fileContent[ps_ElementArray->start],
                    cpc_Keyword, 
                    ui8_CmpLen)
            )
            {
                return 0;
            }
        }
    }
    return -1;
}


static void pds_elem_write(char* pc_OutputString, jsmntok_t *ps_ElementArray)
{
    const char* cpc_compressedValue;

    cpc_compressedValue = pds_convert_value(
            &s_pc_fileContent[ps_ElementArray->start],
            ps_ElementArray->end - ps_ElementArray->start);

    snprintf(pc_OutputString,MAX_BUFFER_SIZE,
            "%s%s",
            pc_OutputString,
            cpc_compressedValue);
}

static bool pds_elem_write_key(char* pc_OutputString, jsmntok_t *ps_ElementArray, bool *pab_readKeys)
{
    char c_Key = s_pc_fileContent[ps_ElementArray->end-1];
    int b_IsDuplicateKey;

    if(NULL == pab_readKeys  || 0 == pab_readKeys[c_Key-'a'])
    {
        snprintf(pc_OutputString,MAX_BUFFER_SIZE,
                "%s%c",
               pc_OutputString,
               c_Key);
        if(pab_readKeys!= NULL)
        {
            pab_readKeys[c_Key-'a'] = true;
        }

        b_IsDuplicateKey = false;
    }
    else
    {
        b_IsDuplicateKey = true;
    }
    return b_IsDuplicateKey;
}

static int pds_array_write(char* pc_OutputString, jsmntok_t *ps_ElementArray)
{
    int ElementIndex=0;
    int GlobalElementIndex;
    int b_isFirstElement=1;
    
    snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s[",pc_OutputString);

    GlobalElementIndex = 1;
    for (ElementIndex = 0; ElementIndex < ps_ElementArray->size; ElementIndex++)
    {
        if(b_isFirstElement != 1)
        {
            snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s,",pc_OutputString);
        }

        if(ps_ElementArray[GlobalElementIndex].type == JSMN_OBJECT)
        {
            GlobalElementIndex +=
                    pds_obj_write(pc_OutputString,
                              &ps_ElementArray[GlobalElementIndex]);
        }
        else if(ps_ElementArray[GlobalElementIndex].type == JSMN_STRING ||
                    ps_ElementArray[GlobalElementIndex].type == JSMN_PRIMITIVE)
        {
            if (pds_elem_cmp(&ps_ElementArray[GlobalElementIndex], "// comment") == 0)
            {
                ElementIndex++;
                GlobalElementIndex+=2;
            }
            else
            {
                pds_elem_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex]);
                GlobalElementIndex++;
            }
        }
        else if(ps_ElementArray[GlobalElementIndex].type == JSMN_ARRAY)
        {
            pds_array_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex]);
        }

        b_isFirstElement = 0;
    }
    snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s]",pc_OutputString);

    return GlobalElementIndex;
}

static int pds_obj_write(char* pc_OutputString, jsmntok_t *ps_ElementArray) {
    int ElementIndex=1;
    int GlobalElementIndex;
    bool b_isFirstElement = true;
    bool b_SkipNextComa = true;
    bool ab_readKeys[32] = {false};
    u8 ui8_MsgBufferId;

    ui8_IndexerLevel++;

    GlobalElementIndex=1;
    if (ui8_IndexerLevel == 1)
    {
        pc_OutputString = pds_find_output_string(ui8_MsgBufferId);
    }

    if(NULL != pc_OutputString)
    {
        snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s{",pc_OutputString);
    }

    for (; ElementIndex < ps_ElementArray->size*2; ElementIndex++)
    {

        if (pds_elem_cmp(&ps_ElementArray[GlobalElementIndex], "// comment") == 0)
        {
            ElementIndex++;
            GlobalElementIndex+=2;
        }
        else
        {
            if(true != b_isFirstElement && false == b_SkipNextComa )
            {
                snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s,",pc_OutputString);
            }
            b_SkipNextComa = false;

            if(ps_ElementArray[GlobalElementIndex+1].type == JSMN_STRING ||
                    ps_ElementArray[GlobalElementIndex+1].type == JSMN_PRIMITIVE)
            {
                /* Do not compress duplicate keys elements */
                if(false == pds_elem_write_key(pc_OutputString, &ps_ElementArray[GlobalElementIndex],ab_readKeys))
                {
                    snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s:",pc_OutputString);
                    pds_elem_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex+1]);
                }
                else
                {
                    b_SkipNextComa = 1;
                }
                GlobalElementIndex+=2;
                ElementIndex++;
            }
            else if(ps_ElementArray[GlobalElementIndex+1].type == JSMN_OBJECT)
            {
                pds_elem_write_key(pc_OutputString, &ps_ElementArray[GlobalElementIndex],NULL);

                snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s:",pc_OutputString);
                GlobalElementIndex+=
                        pds_obj_write(pc_OutputString,
                                  &ps_ElementArray[GlobalElementIndex+1]) +1;
                ElementIndex++;
            }
            else if(ps_ElementArray[GlobalElementIndex+1].type == JSMN_ARRAY)
            {
                pds_elem_write_key(pc_OutputString, &ps_ElementArray[GlobalElementIndex],NULL);
                snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s:",pc_OutputString);
                GlobalElementIndex+=
                        pds_array_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex+1])  +1;
                ElementIndex++;
            }
            b_isFirstElement = false;
        }

    }
    
    snprintf(pc_OutputString,MAX_BUFFER_SIZE,"%s}",pc_OutputString);
    
    ui8_IndexerLevel--;
    

    return GlobalElementIndex;
}


static int pds_msgs_write(jsmntok_t *ps_ElementArray) {
    int ElementIndex=1;
    int GlobalElementIndex;
    GlobalElementIndex=1;

    for (; ElementIndex < ps_ElementArray->size*2; ElementIndex++)
    {

        if (pds_elem_cmp(&ps_ElementArray[GlobalElementIndex], "// comment") == 0)
        {
            ElementIndex++;
            GlobalElementIndex+=2;
        }
        else
        {
            if(ps_ElementArray[GlobalElementIndex+1].type == JSMN_OBJECT)
            {
                GlobalElementIndex+=
                        pds_obj_write(NULL,
                                  &ps_ElementArray[GlobalElementIndex+1]) +1;
                ElementIndex++;
            }
            else
            {

            }
        }
    }

    return 0;
}


PDS_BUFFERS *pds_compress_json(const char *cpc_InputString, size_t size)
{
    int i_ParserResult;
    jsmn_parser h_JsmnParser;
    jsmntok_t *ps_ElementArray;
    u16 ui16_NbTokens = 256;

    ps_ElementArray = (jsmntok_t*)kmalloc(sizeof(jsmntok_t) * ui16_NbTokens, GFP_KERNEL);
    s_ps_PdsOutputBuffers = (PDS_BUFFERS*)kmalloc(sizeof(PDS_BUFFERS),GFP_KERNEL);
    memset(s_ps_PdsOutputBuffers, 0, sizeof(PDS_BUFFERS));

    s_pc_fileContent = (char *) kmalloc(sizeof(char) * (size+1), GFP_KERNEL);
    memcpy(s_pc_fileContent, cpc_InputString, sizeof(char) * size);

    // Make sure that s_pc_fileContent last charater is a 0, no matter what's in
    // cpc_InputString.
    s_pc_fileContent[size] = 0;

    remove_comments();

    jsmn_init(&h_JsmnParser);

    do
    {
        i_ParserResult = jsmn_parse(&h_JsmnParser,
        		s_pc_fileContent, size,
                ps_ElementArray,
                ui16_NbTokens);

        if( JSMN_ERROR_NOMEM == i_ParserResult )
        {
            ui16_NbTokens += 256;
            ps_ElementArray = (jsmntok_t*) krealloc (
                    ps_ElementArray,
                    sizeof(jsmntok_t) * ui16_NbTokens,
                    GFP_KERNEL );
        }
    }
    while ( JSMN_ERROR_NOMEM == i_ParserResult );

    ui8_IndexerLevel = 0;
    pds_msgs_write(ps_ElementArray);

    kfree(ps_ElementArray);
    kfree(s_pc_fileContent);

    return s_ps_PdsOutputBuffers;
}


void pds_release_buffers(PDS_BUFFERS * p_PdsBuffers)
{
    u8 ui8_BufferIndex;

    for (ui8_BufferIndex=0; ui8_BufferIndex < p_PdsBuffers->u8_NbBuffersUsed; ui8_BufferIndex++)
    {
        kfree(s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex]);
    }
    kfree(p_PdsBuffers);
}


#define PUTC(c) s_pc_fileContent[ui32_Index] = c
#define GETC() s_pc_fileContent[ui32_Index]
#define GETC_NEXT() s_pc_fileContent[ui32_Index+1]

static void remove_comments(void)
{
    //s_pc_fileContent
    u32 ui32_Index = 0;
    bool b_IsComment = true;

    while ( ( s_pc_fileContent[ui32_Index+1]) != 0 )
    {
        
        if (GETC() == '/' && GETC_NEXT() == '/' )  /* opening comment ? */
        {   
        	b_IsComment = true;
            do
            {
                if( GETC() == 0x0A )
                {
                	b_IsComment = false;
                }
                else
                {
                    PUTC(' ');   /* replace comment with space */
                }
                ui32_Index++;
                
            } while (b_IsComment);
            
        }
        
        if (GETC() == '/' && GETC_NEXT() == '*' )  /* opening comment ? */
        {
        	b_IsComment = true;
            do
            {
                if( GETC() == '*' && GETC_NEXT() == '/' )
                {
                    PUTC(' ');
                    ui32_Index++;
                    PUTC(' ');
                    b_IsComment = false;
                }
                else
                {
                    PUTC(' ');   /* replace comment with space */
                }
                ui32_Index++;

            } while (b_IsComment);
        }

        if (GETC() == '\"')
        {
            ui32_Index++;
            
            while (GETC() != '\"' )
            {
                ui32_Index++;
            }
        }
        
        if (GETC() == '\'')
        {
            ui32_Index++;
            
            while (GETC() != '\'' )
            {
                ui32_Index++;
            }
        }
        
        ui32_Index++;
    }
}
