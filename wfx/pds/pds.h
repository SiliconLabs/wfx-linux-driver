/*
 * Copyright Silicon Labs - 2017
 *
 * \brief
 */

typedef struct PDS_BUFFERS_T {
	u8	nb_buffers_used;
	char	*output_strings[8];
} PDS_BUFFERS;

PDS_BUFFERS *pds_compress_json(const char *input_string, size_t size);

void pds_release_buffers(PDS_BUFFERS *pds_buffers);
