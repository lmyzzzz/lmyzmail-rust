#include "asciiart.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 3 || argc > 7) {
        fprintf(stderr,
                "usage: %s VIDEO FRAME_INDEX [SIMD_MODE] [CONTRAST] [MAP_DITHER] [TARGET_FPS]\n",
                argv[0]);
        return 2;
    }
    char* end = NULL;
    long requested = strtol(argv[2], &end, 10);
    if (*end != '\0' || requested < 0) {
        fprintf(stderr, "invalid frame index\n");
        return 2;
    }

    long simd_mode = AA_SIMD_SCALAR;
    if (argc >= 4) {
        end = NULL;
        simd_mode = strtol(argv[3], &end, 10);
        if (*end != '\0' || simd_mode < AA_SIMD_AUTO || simd_mode > AA_SIMD_AVX512) {
            fprintf(stderr, "invalid SIMD mode\n");
            return 2;
        }
    }
    float contrast = 1.0f;
    if (argc >= 5) {
        end = NULL;
        contrast = strtof(argv[4], &end);
        if (*end != '\0' || contrast <= 0.0f) {
            fprintf(stderr, "invalid contrast\n");
            return 2;
        }
    }
    long map_dither = -1;
    if (argc >= 6) {
        end = NULL;
        map_dither = strtol(argv[5], &end, 10);
        if (*end != '\0' || map_dither < -1 || map_dither > 2) {
            fprintf(stderr, "invalid map dither mode\n");
            return 2;
        }
    }
    float target_fps = 30.0f;
    if (argc >= 7) {
        end = NULL;
        target_fps = strtof(argv[6], &end);
        if (*end != '\0' || target_fps <= 0.0f) {
            fprintf(stderr, "invalid target FPS\n");
            return 2;
        }
    }

    mc_config config;
    mc_config_default(&config);
    config.width = 256;
    config.height = 256;
    config.simd_mode = (int32_t)simd_mode;
    config.contrast = contrast;
    config.target_fps = target_fps;

    mc_ctx* context = mc_create(&config);
    mc_video* video = context ? mc_video_open(context, argv[1]) : NULL;
    if (!video) {
        fprintf(stderr, "failed to open video: %s\n", context ? mc_last_error(context) : "out of memory");
        mc_destroy(context);
        return 1;
    }

    for (long index = 0; index <= requested; ++index) {
        mc_frame* frame = NULL;
        int32_t status = mc_video_next_frame(video, &frame);
        if (status == AA_EOF) {
            fprintf(stderr, "video ended before requested frame\n");
            mc_video_close(video);
            mc_destroy(context);
            return 1;
        }
        if (status != AA_OK || !frame) {
            fprintf(stderr, "video decode failed: %s\n", mc_last_error(context));
            mc_video_close(video);
            mc_destroy(context);
            return 1;
        }
        if (index == requested) {
            size_t pixels = (size_t)frame->width * (size_t)frame->height;
            const uint8_t* output = frame->colors;
            size_t bytes = pixels * 3u;
            uint8_t* map_colors = NULL;
            if (map_dither >= 0) {
                map_colors = (uint8_t*)malloc(pixels);
                if (!map_colors || mc_rgb_to_map_colors(
                        frame->colors,
                        map_colors,
                        (int32_t)pixels,
                        frame->width,
                        (int32_t)map_dither,
                        (int32_t)simd_mode) != AA_OK) {
                    fprintf(stderr, "map conversion failed\n");
                    free(map_colors);
                    mc_frame_free(frame);
                    mc_video_close(video);
                    mc_destroy(context);
                    return 1;
                }
                output = map_colors;
                bytes = pixels;
            }
            if (fwrite(output, 1, bytes, stdout) != bytes) {
                free(map_colors);
                mc_frame_free(frame);
                mc_video_close(video);
                mc_destroy(context);
                return 1;
            }
            free(map_colors);
        }
        mc_frame_free(frame);
    }

    mc_video_close(video);
    mc_destroy(context);
    return 0;
}
