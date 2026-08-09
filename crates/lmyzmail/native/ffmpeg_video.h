#ifndef LMYZMAIL_FFMPEG_VIDEO_H
#define LMYZMAIL_FFMPEG_VIDEO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lmyzmail_ffmpeg_video lmyzmail_ffmpeg_video;

/* Returns 0 for a decoded frame, 1 for EOF, and a negative value on error. */
int32_t lmyzmail_ffmpeg_video_next(
    lmyzmail_ffmpeg_video* video,
    uint8_t* output,
    size_t output_len);

int32_t lmyzmail_ffmpeg_video_open(
    const char* path,
    lmyzmail_ffmpeg_video** output,
    int32_t* width,
    int32_t* height);

const char* lmyzmail_ffmpeg_video_error(const lmyzmail_ffmpeg_video* video);
void lmyzmail_ffmpeg_video_close(lmyzmail_ffmpeg_video* video);

#ifdef __cplusplus
}
#endif

#endif
