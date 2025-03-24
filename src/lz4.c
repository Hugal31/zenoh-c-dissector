#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <glib.h>
#include <lz4.h>

/*
 * Uncompresses a lz4 compressed packet inside a message of tvb at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */
#define TVB_LZ4_MIN_BUFSIZ 65536
#define TVB_LZ4_MAX_BUFSIZ 1048576 * 10

tvbuff_t *zenoh_tvb_uncompress_lz4(tvbuff_t *tvb, const int offset, int comprlen)
{
    LZ4_streamDecode_t *decoder = LZ4_createStreamDecode();
    char const *input = (char const *)tvb_get_ptr(tvb, offset, comprlen);
    char *output = g_malloc(TVB_LZ4_MIN_BUFSIZ);
    int output_size = TVB_LZ4_MIN_BUFSIZ;
    // FIXME: This doesn't work if the decompressed output is greater than the output_size...
    int decoded = LZ4_decompress_safe_continue(decoder, input, output, comprlen, output_size);
    int total_decompressed = decoded;

    while (decoded == output_size)
    {
        DISSECTOR_ASSERT_HINT(output_size * 4 < TVB_LZ4_MAX_BUFSIZ, "TVB_LZ4_MAX_BUFSIZ exceeded");
        output = g_realloc(output, output_size * 4);
        output_size = output_size * 4;
        decoded = LZ4_decompress_safe_continue(
                decoder, NULL, output + total_decompressed, 0, output_size - total_decompressed);
        total_decompressed += decoded;
    }

    LZ4_freeStreamDecode(decoder);

    if (decoded < 0)
    {
        g_free(output);
        return NULL;
    }

    tvbuff_t *uncompr_tvb = tvb_new_real_data((uint8_t *)output, (unsigned)total_decompressed, total_decompressed);
    tvb_set_free_cb(uncompr_tvb, g_free);

    return uncompr_tvb;
}

tvbuff_t *zenoh_tvb_child_uncompress_lz4(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
    tvbuff_t *new_tvb = tvb_uncompress_lz4(tvb, offset, comprlen);
    if (new_tvb)
        tvb_set_child_real_data_tvbuff(parent, new_tvb);
    return new_tvb;
}
