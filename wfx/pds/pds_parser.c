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
 




#include "jsmn/jsmn.h"
#include <linux/module.h>
#include "pds.h"
#include <linux/slab.h>

#define MAX_BUFFER_SIZE (1500)

u8 ui8_IndexerLevel;

static const char *s_cpc_fileContent = NULL;
static PDS_BUFFERS *s_ps_PdsOutputBuffers = NULL;


static char * pds_find_output_string(u8 ui8_BufferIndex);

static int pds_elem_cmp(jsmntok_t *ps_ElementArray, const char *cpc_Keyword);
static void pds_elem_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static bool pds_elem_write_key(char* pc_OutputString, jsmntok_t *ps_ElementArray,bool *ab_readKeys);
static int pds_array_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static int pds_obj_write(char* pc_OutputString, jsmntok_t *ps_ElementArray);
static int pds_msgs_write(jsmntok_t *ps_ElementArray);

static void pds_integer_to_hex_string(u32 decimalNumber);
static u32 pds_baseX_to_int(u8 ui8_base, const char* cpc_PdsValue, u8 ui8_PdsValueLen);
static const char* pds_convert_value(const char* cpc_PdsValue, u8 ui8_PdsValueLen);
#define JSON_VALUE_DICT_NB_ENTRY (10)
#define JSON_VALUE_DICT_ARRAY_LEN (JSON_VALUE_DICT_NB_ENTRY*2)
static const char* acpc_JsonValueDictionnary[JSON_VALUE_DICT_ARRAY_LEN] =
        {
                "none",     "0",
                "down",     "2",
                "up",       "3",
                "enable",   "1",
                "disable",  "0",
                "tri",      "0",
                "gpio",     "2",
                "func",     "1",
                "debug",    "3",
                "clock",    "4",
        };

static char ac_convertBuffer[16];

#define DEC_TO_ASCII(DEC,HEX) \
        if( (DEC) < 10) \
           HEX = (DEC) + '0'; \
        else \
            HEX = (DEC) + 'A' - 10 ; \

static char * pds_find_output_string(u8 ui8_BufferIndex)
{
    ui8_BufferIndex = s_ps_PdsOutputBuffers->u8_NbBuffersUsed;

    s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex] = (char*)kmalloc(MAX_BUFFER_SIZE,GFP_KERNEL);
    s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex][0] = 0;

    s_ps_PdsOutputBuffers->u8_NbBuffersUsed++;

    return s_ps_PdsOutputBuffers->apc_output_strings[ui8_BufferIndex];
}

static void pds_integer_to_hex_string(u32 decimalNumber)
{
    int remainder,quotient;
    int index=0,j;
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
            ac_convertBuffer[j] = ac_RevertValue[index-j-1];
        }
        ac_convertBuffer[index] = 0;
    }
    else
    {
        DEC_TO_ASCII(decimalNumber%16,ac_convertBuffer[0]);
        ac_convertBuffer[1] = 0;
    }

    return;
}

static u32 pds_baseX_to_int(u8 ui8_base, const char* cpc_PdsValue, u8 ui8_PdsValueLen)
{
    u8 ui8_DecValueIndex = 0;
    u8 ui8_charValue = 0;
    u16 ui16_DecValue = 0;
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
            ui16_DecValue = (ui16_DecValue * 10) + ui8_charValue;
        }
        else
        {
            ui16_DecValue = (ui16_DecValue << ui8_shiftCoef) + ui8_charValue;
        }
        ui8_DecValueIndex++;
    }

    return ui16_DecValue;
}

static const char* pds_convert_value(const char* cpc_PdsValue, u8 ui8_PdsValueLen)
{
    u8 ui8_DictIndex;
    u8 ui8_CharIndex = 0;
    u32 ui32_DecValue = 0;
    ac_convertBuffer[0] = cpc_PdsValue[0];

    if(cpc_PdsValue[0] >= '0' && cpc_PdsValue[0] <= '9')
    {
        ui32_DecValue = pds_baseX_to_int(10, cpc_PdsValue, ui8_PdsValueLen);
        pds_integer_to_hex_string(ui32_DecValue);
    }
    else if(cpc_PdsValue[0] == 'b')
    {
        ui32_DecValue = pds_baseX_to_int(2,&cpc_PdsValue[1],ui8_PdsValueLen-1);
        pds_integer_to_hex_string(ui32_DecValue);
    }
    else if(cpc_PdsValue[0] == 'x' ||  cpc_PdsValue[0] == 'X')
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
        for (ui8_DictIndex = 0; ui8_DictIndex < JSON_VALUE_DICT_NB_ENTRY; ui8_DictIndex++)
        {
            if(0 == strncmp(
                    acpc_JsonValueDictionnary[ui8_DictIndex*2],
                    cpc_PdsValue,
                    ui8_PdsValueLen))
            {
                strcpy(ac_convertBuffer,acpc_JsonValueDictionnary[ui8_DictIndex*2+1]);
                break;
            }
        }
    }

    return ac_convertBuffer;
}

static int pds_elem_cmp(jsmntok_t *ps_ElementArray, const char *cpc_Keyword)
{
    if (ps_ElementArray->type == JSMN_STRING)
    {
        if((int) strlen(cpc_Keyword) == ps_ElementArray->end - ps_ElementArray->start)
        {
            if(0 == strncmp(
                    &s_cpc_fileContent[ps_ElementArray->start],
                    cpc_Keyword, 
                    ps_ElementArray->end - ps_ElementArray->start) 
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
            &s_cpc_fileContent[ps_ElementArray->start],
            ps_ElementArray->end - ps_ElementArray->start);

    snprintf(pc_OutputString,MAX_BUFFER_SIZE,
            "%s%s",
            pc_OutputString,
            cpc_compressedValue);
}

static bool pds_elem_write_key(char* pc_OutputString, jsmntok_t *ps_ElementArray, bool *pab_readKeys)
{
    char c_Key = s_cpc_fileContent[ps_ElementArray->end-1];
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
        else if(ps_ElementArray[GlobalElementIndex].type == JSMN_STRING)
        {
            pds_elem_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex]);
            GlobalElementIndex++;
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

            if(ps_ElementArray[GlobalElementIndex+1].type == JSMN_STRING  ||
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
                pds_array_write(pc_OutputString, &ps_ElementArray[GlobalElementIndex+1]);
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


PDS_BUFFERS *pds_compress_json(const char *cpc_InputString)
{
    int i_ParserResult;
    jsmn_parser h_JsmnParser;
    jsmntok_t *ps_ElementArray;
    u16 ui16_NbTokens = 256;

    ps_ElementArray = (jsmntok_t*)kmalloc(sizeof(jsmntok_t) * ui16_NbTokens, GFP_KERNEL);
    s_ps_PdsOutputBuffers = (PDS_BUFFERS*)kmalloc(sizeof(PDS_BUFFERS),GFP_KERNEL);
    memset(s_ps_PdsOutputBuffers, 0, sizeof(PDS_BUFFERS));

    s_cpc_fileContent = cpc_InputString;

    jsmn_init(&h_JsmnParser);

    do
    {
        i_ParserResult = jsmn_parse(&h_JsmnParser,
                cpc_InputString, strlen(cpc_InputString),
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
