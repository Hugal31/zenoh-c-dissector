#pragma once

#include <epan/tvbuff.h>

tvbuff_t *zenoh_tvb_uncompress_lz4(tvbuff_t *tvb, const int offset, int comprlen);
tvbuff_t *zenoh_tvb_child_uncompress_lz4(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen);
