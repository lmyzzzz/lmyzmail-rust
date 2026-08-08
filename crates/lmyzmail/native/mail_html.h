#ifndef LMYZMAIL_NATIVE_MAIL_HTML_H
#define LMYZMAIL_NATIVE_MAIL_HTML_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LMYZMAIL_MAIL_HTML_ABI_VERSION 1u
#define LMYZMAIL_MAIL_HTML_MAX_RESOURCES 40u

typedef struct lmyzmail_mail_html_context lmyzmail_mail_html_context;

/* Return nonzero when work should stop. The callback must not throw or unwind. */
typedef int32_t (*lmyzmail_mail_html_cancel_fn)(void* userdata);

typedef struct lmyzmail_mail_html_config {
    uint32_t struct_size;
    uint32_t viewport_width;
    uint32_t max_document_height;
    float base_font_size;
    uint32_t background_rgb;
    uint32_t reserved[3];
    lmyzmail_mail_html_cancel_fn cancel;
    void* cancel_userdata;
} lmyzmail_mail_html_config;

/*
 * cid is the exact, case-sensitive identifier without the "cid:" prefix.
 * rgba points to straight-alpha RGBA rows. The caller owns all pointed-to
 * storage and must keep it immutable until the context is destroyed.
 */
typedef struct lmyzmail_mail_html_resource {
    const uint8_t* cid;
    size_t cid_len;
    const uint8_t* rgba;
    size_t rgba_len;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t reserved;
} lmyzmail_mail_html_resource;

enum lmyzmail_mail_html_status {
    LMYZMAIL_MAIL_HTML_OK = 0,
    LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT = 1,
    LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED = 2,
    LMYZMAIL_MAIL_HTML_CANCELLED = 3,
    LMYZMAIL_MAIL_HTML_RENDER_ERROR = 4,
    LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY = 5
};

uint32_t lmyzmail_mail_html_abi_version(void);

/*
 * Parses and lays out UTF-8 HTML. Context calls are single-threaded: callers
 * must serialize query/render/destroy and retain all input storage through
 * destroy. Duplicate CIDs preserve the first resource.
 */
int32_t lmyzmail_mail_html_create(
    const lmyzmail_mail_html_config* config,
    const uint8_t* html,
    size_t html_len,
    const lmyzmail_mail_html_resource* resources,
    size_t resource_count,
    lmyzmail_mail_html_context** out_context,
    char* error,
    size_t error_capacity);

int32_t lmyzmail_mail_html_query_size(
    const lmyzmail_mail_html_context* context,
    uint32_t* out_width,
    uint32_t* out_height,
    char* error,
    size_t error_capacity);

/*
 * Draws the absolute document range beginning at y_start into caller-owned
 * RGB24 rows. Pixels below the laid-out document remain the configured
 * background color. output_len must cover output_stride * output_height.
 */
int32_t lmyzmail_mail_html_render_range(
    lmyzmail_mail_html_context* context,
    uint32_t y_start,
    uint32_t output_width,
    uint32_t output_height,
    uint8_t* output_rgb,
    size_t output_len,
    size_t output_stride,
    char* error,
    size_t error_capacity);

int32_t lmyzmail_mail_html_destroy(
    lmyzmail_mail_html_context* context,
    char* error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
