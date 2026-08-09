#include "ffmpeg_video.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/error.h>
#include <libavutil/imgutils.h>
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>

struct lmyzmail_ffmpeg_video {
    AVFormatContext* format;
    AVCodecContext* codec;
    const AVCodec* decoder;
    struct SwsContext* scaler;
    AVFrame* frame;
    AVFrame* rgb_frame;
    AVPacket* packet;
    uint8_t* rgb_storage;
    int32_t width;
    int32_t height;
    int stream_index;
    int flushed;
    char error[256];
};

static void set_error(lmyzmail_ffmpeg_video* video, const char* message) {
    if (!video) return;
    snprintf(video->error, sizeof(video->error), "%s", message ? message : "FFmpeg error");
}

static void set_av_error(lmyzmail_ffmpeg_video* video, const char* operation, int error) {
    char detail[128];
    av_strerror(error, detail, sizeof(detail));
    snprintf(video->error, sizeof(video->error), "%s: %s", operation, detail);
}

static void destroy_partial(lmyzmail_ffmpeg_video* video) {
    if (!video) return;
    if (video->packet) av_packet_free(&video->packet);
    if (video->frame) av_frame_free(&video->frame);
    if (video->rgb_frame) av_frame_free(&video->rgb_frame);
    if (video->rgb_storage) av_free(video->rgb_storage);
    if (video->scaler) sws_freeContext(video->scaler);
    if (video->codec) avcodec_free_context(&video->codec);
    if (video->format) avformat_close_input(&video->format);
    free(video);
}

int32_t lmyzmail_ffmpeg_video_open(
    const char* path,
    lmyzmail_ffmpeg_video** output,
    int32_t* width,
    int32_t* height) {
    if (!path || !output || !width || !height) return -1;
    *output = NULL;
    *width = 0;
    *height = 0;

    lmyzmail_ffmpeg_video* video = (lmyzmail_ffmpeg_video*)calloc(1, sizeof(*video));
    if (!video) return -2;
    video->stream_index = -1;

    int error = avformat_open_input(&video->format, path, NULL, NULL);
    if (error < 0) {
        set_av_error(video, "avformat_open_input", error);
        destroy_partial(video);
        return -3;
    }
    error = avformat_find_stream_info(video->format, NULL);
    if (error < 0) {
        set_av_error(video, "avformat_find_stream_info", error);
        destroy_partial(video);
        return -3;
    }
    for (unsigned index = 0; index < video->format->nb_streams; ++index) {
        if (video->format->streams[index]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
            video->stream_index = (int)index;
            break;
        }
    }
    if (video->stream_index < 0) {
        set_error(video, "video stream not found");
        destroy_partial(video);
        return -3;
    }

    AVStream* stream = video->format->streams[video->stream_index];
    video->decoder = avcodec_find_decoder(stream->codecpar->codec_id);
    if (!video->decoder) {
        set_error(video, "video decoder not found");
        destroy_partial(video);
        return -3;
    }
    video->codec = avcodec_alloc_context3(video->decoder);
    if (!video->codec) {
        set_error(video, "avcodec_alloc_context3 failed");
        destroy_partial(video);
        return -2;
    }
    error = avcodec_parameters_to_context(video->codec, stream->codecpar);
    if (error < 0) {
        set_av_error(video, "avcodec_parameters_to_context", error);
        destroy_partial(video);
        return -3;
    }
    error = avcodec_open2(video->codec, video->decoder, NULL);
    if (error < 0) {
        set_av_error(video, "avcodec_open2", error);
        destroy_partial(video);
        return -3;
    }

    video->width = video->codec->width;
    video->height = video->codec->height;
    if (video->width <= 0 || video->height <= 0) {
        set_error(video, "invalid decoded video dimensions");
        destroy_partial(video);
        return -3;
    }
    video->scaler = sws_getContext(
        video->width,
        video->height,
        video->codec->pix_fmt,
        video->width,
        video->height,
        AV_PIX_FMT_RGB24,
        SWS_BILINEAR,
        NULL,
        NULL,
        NULL);
    if (!video->scaler) {
        set_error(video, "sws_getContext failed");
        destroy_partial(video);
        return -2;
    }
    video->frame = av_frame_alloc();
    video->rgb_frame = av_frame_alloc();
    video->packet = av_packet_alloc();
    if (!video->frame || !video->rgb_frame || !video->packet) {
        set_error(video, "FFmpeg frame allocation failed");
        destroy_partial(video);
        return -2;
    }
    int rgb_size = av_image_get_buffer_size(
        AV_PIX_FMT_RGB24, video->width, video->height, 1);
    if (rgb_size <= 0) {
        set_error(video, "invalid RGB frame size");
        destroy_partial(video);
        return -3;
    }
    video->rgb_storage = (uint8_t*)av_malloc((size_t)rgb_size);
    if (!video->rgb_storage || av_image_fill_arrays(
            video->rgb_frame->data,
            video->rgb_frame->linesize,
            video->rgb_storage,
            AV_PIX_FMT_RGB24,
            video->width,
            video->height,
            1) < 0) {
        set_error(video, "RGB frame buffer allocation failed");
        destroy_partial(video);
        return -2;
    }
    *output = video;
    *width = video->width;
    *height = video->height;
    return 0;
}

int32_t lmyzmail_ffmpeg_video_next(
    lmyzmail_ffmpeg_video* video,
    uint8_t* output,
    size_t output_len) {
    if (!video || !output) return -1;
    size_t expected = (size_t)video->width * (size_t)video->height * 3u;
    if (output_len != expected) {
        set_error(video, "RGB output buffer length is invalid");
        return -1;
    }

    while (1) {
        int error = avcodec_receive_frame(video->codec, video->frame);
        if (error == 0) break;
        if (error == AVERROR_EOF) return 1;
        if (error != AVERROR(EAGAIN)) {
            set_av_error(video, "avcodec_receive_frame", error);
            return -1;
        }
        if (video->flushed) return 1;
        while (1) {
            error = av_read_frame(video->format, video->packet);
            if (error < 0) {
                video->flushed = 1;
                error = avcodec_send_packet(video->codec, NULL);
                if (error < 0 && error != AVERROR_EOF) {
                    set_av_error(video, "avcodec_send_packet(flush)", error);
                    return -1;
                }
                break;
            }
            if (video->packet->stream_index == video->stream_index) {
                error = avcodec_send_packet(video->codec, video->packet);
                av_packet_unref(video->packet);
                if (error < 0 && error != AVERROR(EAGAIN)) {
                    set_av_error(video, "avcodec_send_packet", error);
                    return -1;
                }
                break;
            }
            av_packet_unref(video->packet);
        }
    }

    sws_scale(
        video->scaler,
        (const uint8_t* const*)video->frame->data,
        video->frame->linesize,
        0,
        video->height,
        video->rgb_frame->data,
        video->rgb_frame->linesize);
    for (int32_t row = 0; row < video->height; ++row) {
        memcpy(
            output + (size_t)row * (size_t)video->width * 3u,
            video->rgb_frame->data[0] + (size_t)row * (size_t)video->rgb_frame->linesize[0],
            (size_t)video->width * 3u);
    }
    av_frame_unref(video->frame);
    return 0;
}

const char* lmyzmail_ffmpeg_video_error(const lmyzmail_ffmpeg_video* video) {
    return video ? video->error : "FFmpeg video handle is null";
}

void lmyzmail_ffmpeg_video_close(lmyzmail_ffmpeg_video* video) {
    destroy_partial(video);
}
