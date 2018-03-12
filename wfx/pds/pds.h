/*
 * Copyright Silicon Labs - 2017
 *
 * \brief
 */

typedef struct PDS_BUFFERS_T
{
    u8 u8_NbBuffersUsed;
    char * apc_output_strings[8];
}PDS_BUFFERS;


PDS_BUFFERS *pds_compress_json(const char *cpc_InputString, size_t size);
void pds_release_buffers(PDS_BUFFERS * p_PdsBuffers);
