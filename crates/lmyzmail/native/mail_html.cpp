#include "mail_html.h"

#include "container_cairo.h"
#include <cairo-ft.h>
#include <cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <litehtml.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(__linux__) || !defined(__x86_64__)
#error "lmyzmail mail HTML rendering supports only Linux x86_64"
#endif

static_assert(sizeof(void*) == 8U, "lmyzmail mail HTML ABI requires 64-bit pointers");
static_assert(sizeof(lmyzmail_mail_html_config) == 48U,
              "unexpected lmyzmail mail HTML config ABI layout");
static_assert(sizeof(lmyzmail_mail_html_resource) == 48U,
              "unexpected lmyzmail mail HTML resource ABI layout");

namespace {

constexpr size_t kMaxHtmlBytes = 4U * 1024U * 1024U;
constexpr size_t kMaxCidBytes = 1024U;
constexpr uint32_t kMaxImageDimension = 4096U;
constexpr uint64_t kMaxImagePixels = 4ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxResourcePixels = 16ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxRenderPixels = 16ULL * 1024ULL * 1024ULL;
constexpr uint32_t kMaxViewportWidth = 4096U;
constexpr uint32_t kMaxDocumentHeight = 32768U;
constexpr float kMaxCoordinate = 16777216.0F;

constexpr const char* kSansRegular =
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf";
constexpr const char* kSansBold =
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf";
constexpr const char* kMonoRegular =
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf";
constexpr const char* kMonoBold =
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf";

class StatusError final : public std::runtime_error {
public:
    StatusError(int32_t status, const std::string& message)
        : std::runtime_error(message), status_(status) {}

    int32_t status() const noexcept { return status_; }

private:
    int32_t status_;
};

[[noreturn]] void fail(int32_t status, const std::string& message) {
    throw StatusError(status, message);
}

void write_error(char* error, size_t capacity, std::string_view message) noexcept {
    if (error == nullptr || capacity == 0U) {
        return;
    }
    const size_t count = std::min(capacity - 1U, message.size());
    if (count != 0U) {
        std::memcpy(error, message.data(), count);
    }
    error[count] = '\0';
}

template <typename Function>
int32_t ffi_boundary(char* error, size_t capacity, Function&& function) noexcept {
    if (capacity != 0U && error == nullptr) {
        return LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT;
    }
    write_error(error, capacity, {});
    try {
        function();
        return LMYZMAIL_MAIL_HTML_OK;
    } catch (const StatusError& exception) {
        write_error(error, capacity, exception.what());
        return exception.status();
    } catch (const std::bad_alloc&) {
        write_error(error, capacity, "native mail HTML renderer ran out of memory");
        return LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY;
    } catch (const std::exception& exception) {
        write_error(error, capacity, exception.what());
        return LMYZMAIL_MAIL_HTML_RENDER_ERROR;
    } catch (...) {
        write_error(error, capacity, "unknown native mail HTML renderer failure");
        return LMYZMAIL_MAIL_HTML_RENDER_ERROR;
    }
}

void check_cancel(const lmyzmail_mail_html_config& config) {
    if (config.cancel == nullptr) {
        return;
    }
    bool cancelled = false;
    try {
        cancelled = config.cancel(config.cancel_userdata) != 0;
    } catch (...) {
        fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "cancellation callback threw an exception");
    }
    if (cancelled) {
        fail(LMYZMAIL_MAIL_HTML_CANCELLED, "native mail HTML rendering cancelled");
    }
}

bool valid_utf8(const uint8_t* bytes, size_t length,
                const lmyzmail_mail_html_config& config) {
    size_t index = 0U;
    while (index < length) {
        if ((index & 4095U) == 0U) {
            check_cancel(config);
        }
        const uint8_t first = bytes[index];
        if (first == 0U) {
            return false;
        }
        if (first <= 0x7FU) {
            ++index;
            continue;
        }

        size_t continuation_count = 0U;
        uint8_t second_min = 0x80U;
        uint8_t second_max = 0xBFU;
        if (first >= 0xC2U && first <= 0xDFU) {
            continuation_count = 1U;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            continuation_count = 2U;
            if (first == 0xE0U) {
                second_min = 0xA0U;
            } else if (first == 0xEDU) {
                second_max = 0x9FU;
            }
        } else if (first >= 0xF0U && first <= 0xF4U) {
            continuation_count = 3U;
            if (first == 0xF0U) {
                second_min = 0x90U;
            } else if (first == 0xF4U) {
                second_max = 0x8FU;
            }
        } else {
            return false;
        }

        if (continuation_count > length - index - 1U) {
            return false;
        }
        const uint8_t second = bytes[index + 1U];
        if (second < second_min || second > second_max) {
            return false;
        }
        for (size_t offset = 2U; offset <= continuation_count; ++offset) {
            const uint8_t continuation = bytes[index + offset];
            if (continuation < 0x80U || continuation > 0xBFU) {
                return false;
            }
        }
        index += continuation_count + 1U;
    }
    return true;
}

size_t checked_multiply(size_t left, size_t right, const char* label) {
    if (left != 0U && right > std::numeric_limits<size_t>::max() / left) {
        fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED, label);
    }
    return left * right;
}

struct ResourceView {
    std::string cid;
    const uint8_t* rgba;
    size_t rgba_len;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
};

std::vector<ResourceView> validate_inputs(
    const lmyzmail_mail_html_config& config,
    const uint8_t* html,
    size_t html_len,
    const lmyzmail_mail_html_resource* resources,
    size_t resource_count) {
    if (config.struct_size != sizeof(lmyzmail_mail_html_config)) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "invalid mail HTML config size");
    }
    if (config.viewport_width == 0U || config.viewport_width > kMaxViewportWidth) {
        fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED, "mail HTML viewport width is out of range");
    }
    if (config.max_document_height == 0U ||
        config.max_document_height > kMaxDocumentHeight) {
        fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
             "mail HTML maximum document height is out of range");
    }
    if (!std::isfinite(config.base_font_size) || config.base_font_size < 1.0F ||
        config.base_font_size > 256.0F) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "invalid mail HTML base font size");
    }
    if (config.reserved[0] != 0U || config.reserved[1] != 0U ||
        config.reserved[2] != 0U) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML config reserved fields must be zero");
    }
    if (html_len > kMaxHtmlBytes) {
        fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED, "mail HTML input exceeds 4 MiB");
    }
    if (html_len != 0U && html == nullptr) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML pointer is null");
    }
    if (html_len != 0U && !valid_utf8(html, html_len, config)) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT,
             "mail HTML input is not NUL-free valid UTF-8");
    }
    if (resource_count > LMYZMAIL_MAIL_HTML_MAX_RESOURCES) {
        fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED, "too many mail HTML resources");
    }
    if (resource_count != 0U && resources == nullptr) {
        fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML resource pointer is null");
    }

    check_cancel(config);
    std::vector<ResourceView> validated;
    validated.reserve(resource_count);
    uint64_t cumulative_pixels = 0U;
    for (size_t index = 0U; index < resource_count; ++index) {
        check_cancel(config);
        const lmyzmail_mail_html_resource& resource = resources[index];
        if (resource.reserved != 0U) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT,
                 "mail HTML resource reserved field must be zero");
        }
        if (resource.cid == nullptr || resource.cid_len == 0U ||
            resource.cid_len > kMaxCidBytes) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "invalid mail HTML resource CID");
        }
        if (!valid_utf8(resource.cid, resource.cid_len, config)) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT,
                 "mail HTML resource CID is not NUL-free valid UTF-8");
        }
        if (resource.rgba == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGBA pointer is null");
        }
        if (resource.width == 0U || resource.height == 0U ||
            resource.width > kMaxImageDimension || resource.height > kMaxImageDimension) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
                 "mail HTML resource dimensions are out of range");
        }

        const uint64_t pixels = static_cast<uint64_t>(resource.width) * resource.height;
        if (pixels > kMaxImagePixels) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
                 "mail HTML resource exceeds per-image pixel budget");
        }
        if (cumulative_pixels > kMaxResourcePixels - pixels) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
                 "mail HTML resources exceed cumulative pixel budget");
        }
        cumulative_pixels += pixels;

        const size_t minimum_stride =
            checked_multiply(static_cast<size_t>(resource.width), 4U,
                             "mail HTML RGBA row size overflow");
        if (resource.stride < minimum_stride) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGBA stride is too small");
        }
        const size_t required =
            checked_multiply(static_cast<size_t>(resource.stride),
                             static_cast<size_t>(resource.height),
                             "mail HTML RGBA buffer size overflow");
        if (resource.rgba_len < required) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGBA buffer is too short");
        }

        validated.push_back(ResourceView{
            std::string(reinterpret_cast<const char*>(resource.cid), resource.cid_len),
            resource.rgba,
            resource.rgba_len,
            resource.width,
            resource.height,
            resource.stride,
        });
    }
    check_cancel(config);
    return validated;
}

struct CairoSurfaceDeleter {
    void operator()(cairo_surface_t* surface) const noexcept {
        if (surface != nullptr) {
            cairo_surface_destroy(surface);
        }
    }
};

struct CairoContextDeleter {
    void operator()(cairo_t* context) const noexcept {
        if (context != nullptr) {
            cairo_destroy(context);
        }
    }
};

using UniqueSurface = std::unique_ptr<cairo_surface_t, CairoSurfaceDeleter>;
using UniqueCairo = std::unique_ptr<cairo_t, CairoContextDeleter>;

void require_surface(cairo_surface_t* surface, const char* operation) {
    if (surface == nullptr) {
        fail(LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY, operation);
    }
    const cairo_status_t status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fail(status == CAIRO_STATUS_NO_MEMORY ? LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY
                                              : LMYZMAIL_MAIL_HTML_RENDER_ERROR,
             std::string(operation) + ": " + cairo_status_to_string(status));
    }
}

void require_context(cairo_t* context, const char* operation) {
    if (context == nullptr) {
        fail(LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY, operation);
    }
    const cairo_status_t status = cairo_status(context);
    if (status != CAIRO_STATUS_SUCCESS) {
        fail(status == CAIRO_STATUS_NO_MEMORY ? LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY
                                              : LMYZMAIL_MAIL_HTML_RENDER_ERROR,
             std::string(operation) + ": " + cairo_status_to_string(status));
    }
}

bool valid_coordinate(float value) {
    return std::isfinite(value) && std::abs(value) <= kMaxCoordinate;
}

bool valid_position(const litehtml::position& position, bool positive_size) {
    if (!valid_coordinate(position.x) || !valid_coordinate(position.y) ||
        !valid_coordinate(position.width) || !valid_coordinate(position.height) ||
        position.width < 0.0F || position.height < 0.0F) {
        return false;
    }
    return !positive_size || (position.width > 0.0F && position.height > 0.0F);
}

class MailContainer final : public container_cairo {
public:
    MailContainer(const lmyzmail_mail_html_config& config,
                  std::vector<ResourceView> resources)
        : config_(config) {
        for (ResourceView& resource : resources) {
            resources_.emplace(resource.cid, std::move(resource));
        }
        try {
            initialize_fonts();
            measure_surface_ = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
            require_surface(measure_surface_, "failed to create font measurement surface");
            measure_context_ = cairo_create(measure_surface_);
            require_context(measure_context_, "failed to create font measurement context");
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~MailContainer() override { cleanup(); }

    MailContainer(const MailContainer&) = delete;
    MailContainer& operator=(const MailContainer&) = delete;

    void checkpoint() const { check_cancel(config_); }

    litehtml::uint_ptr create_font(const litehtml::font_description& description,
                                   const litehtml::document*,
                                   litehtml::font_metrics* metrics) override {
        checkpoint();
        if (metrics == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "litehtml requested null font metrics");
        }
        auto font = std::make_unique<FontHandle>();
        font->size = std::max(1, static_cast<int>(description.size + 0.5F));
        font->italic = description.style == litehtml::font_style_italic;
        font->decoration = description.decoration_line;
        font->face = select_face(description.family, description.weight >= 700);

        cairo_save(measure_context_);
        apply_font(measure_context_, *font);
        cairo_font_extents_t font_extents{};
        cairo_font_extents(measure_context_, &font_extents);
        cairo_text_extents_t x_extents{};
        cairo_text_extents(measure_context_, "x", &x_extents);
        cairo_restore(measure_context_);
        require_context(measure_context_, "failed to measure mail HTML font");

        // The frozen renderer leaves the auxiliary CSS-relative metrics at
        // their litehtml defaults. Keep those values explicit so master CSS
        // em/ch spacing remains byte-for-byte compatible with the oracle.
        metrics->font_size = 0.0F;
        metrics->height = std::max(1, static_cast<int>(font_extents.height + 0.5));
        metrics->ascent = std::max(1, static_cast<int>(font_extents.ascent + 0.5));
        metrics->descent = std::max(0, static_cast<int>(font_extents.descent + 0.5));
        metrics->x_height = std::max(1, static_cast<int>(-x_extents.y_bearing + 0.5));
        metrics->ch_width = 0.0F;
        metrics->draw_spaces = font->decoration != litehtml::text_decoration_line_none;
        metrics->sub_shift = 0.0F;
        metrics->super_shift = 0.0F;
        font->metrics = *metrics;
        checkpoint();
        return reinterpret_cast<litehtml::uint_ptr>(font.release());
    }

    void delete_font(litehtml::uint_ptr font) override {
        delete reinterpret_cast<FontHandle*>(font);
    }

    litehtml::pixel_t text_width(const char* text, litehtml::uint_ptr font) override {
        checkpoint();
        if (text == nullptr || *text == '\0') {
            return 0.0F;
        }
        const auto* handle = reinterpret_cast<const FontHandle*>(font);
        if (handle == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "litehtml requested a null font");
        }
        cairo_save(measure_context_);
        apply_font(measure_context_, *handle);
        cairo_text_extents_t extents{};
        cairo_text_extents(measure_context_, text, &extents);
        cairo_restore(measure_context_);
        require_context(measure_context_, "failed to measure mail HTML text");
        checkpoint();
        if (!std::isfinite(extents.x_advance) || extents.x_advance < 0.0 ||
            extents.x_advance > kMaxCoordinate) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "invalid mail HTML text extent");
        }
        return static_cast<litehtml::pixel_t>(extents.x_advance);
    }

    void draw_text(litehtml::uint_ptr hdc, const char* text, litehtml::uint_ptr font,
                   litehtml::web_color color, const litehtml::position& position) override {
        checkpoint();
        if (hdc == 0U || text == nullptr || *text == '\0' ||
            !valid_position(position, false)) {
            return;
        }
        const auto* handle = reinterpret_cast<const FontHandle*>(font);
        if (handle == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "litehtml requested a null drawing font");
        }
        auto* context = reinterpret_cast<cairo_t*>(hdc);
        cairo_save(context);
        apply_clip(context);
        apply_font(context, *handle);
        apply_compat_color(context, color);
        const double baseline = position.y + handle->metrics.ascent;
        cairo_move_to(context, position.x, baseline);
        cairo_show_text(context, text);

        cairo_text_extents_t extents{};
        cairo_text_extents(context, text, &extents);
        if (handle->decoration != litehtml::text_decoration_line_none &&
            std::isfinite(extents.x_advance) && extents.x_advance > 0.0) {
            cairo_set_line_width(context, 1.0);
            if ((handle->decoration & litehtml::text_decoration_line_underline) != 0) {
                cairo_move_to(context, position.x, baseline + 2.0);
                cairo_line_to(context, position.x + extents.x_advance, baseline + 2.0);
                cairo_stroke(context);
            }
            if ((handle->decoration & litehtml::text_decoration_line_line_through) != 0) {
                const double y = position.y + handle->metrics.height * 0.45;
                cairo_move_to(context, position.x, y);
                cairo_line_to(context, position.x + extents.x_advance, y);
                cairo_stroke(context);
            }
            if ((handle->decoration & litehtml::text_decoration_line_overline) != 0) {
                cairo_move_to(context, position.x, position.y);
                cairo_line_to(context, position.x + extents.x_advance, position.y);
                cairo_stroke(context);
            }
        }
        cairo_restore(context);
        require_context(context, "failed to draw mail HTML text");
        checkpoint();
    }

    void load_image(const char* source, const char* base_url, bool) override {
        checkpoint();
        litehtml::string url;
        make_url(source, base_url, url);
        cairo_surface_t* surface = get_image(url);
        if (surface != nullptr) {
            cairo_surface_destroy(surface);
        }
        checkpoint();
    }

    void get_image_size(const char* source, const char* base_url,
                        litehtml::size& size) override {
        checkpoint();
        container_cairo::get_image_size(source, base_url, size);
        checkpoint();
    }

    void draw_image(litehtml::uint_ptr hdc, const litehtml::background_layer& layer,
                    const std::string& url, const std::string& base_url) override {
        checkpoint();
        if (hdc == 0U || !valid_position(layer.origin_box, true) ||
            !valid_position(layer.clip_box, false) ||
            !valid_position(layer.border_box, false)) {
            return;
        }
        litehtml::string resolved;
        make_url(url.c_str(), base_url.c_str(), resolved);
        UniqueSurface image(get_image(resolved));
        if (!image) {
            return;
        }
        const int image_width = cairo_image_surface_get_width(image.get());
        const int image_height = cairo_image_surface_get_height(image.get());
        if (image_width <= 0 || image_height <= 0) {
            return;
        }
        const litehtml::position& destination =
            layer.origin_box.width > 0.0F ? layer.origin_box : layer.border_box;
        if (!valid_position(destination, true)) {
            return;
        }
        auto* context = reinterpret_cast<cairo_t*>(hdc);
        cairo_save(context);
        apply_clip(context);
        cairo_rectangle(context, layer.clip_box.x, layer.clip_box.y,
                        layer.clip_box.width, layer.clip_box.height);
        cairo_clip(context);
        cairo_translate(context, destination.x, destination.y);
        cairo_scale(context, destination.width / image_width,
                    destination.height / image_height);
        cairo_set_source_surface(context, image.get(), 0.0, 0.0);
        cairo_paint(context);
        cairo_restore(context);
        require_context(context, "failed to draw mail HTML image");
        checkpoint();
    }

    void draw_solid_fill(litehtml::uint_ptr hdc, const litehtml::background_layer& layer,
                         const litehtml::web_color& color) override {
        checkpoint();
        if (hdc == 0U || !valid_position(layer.clip_box, false) ||
            !valid_position(layer.border_box, false)) {
            return;
        }
        auto* context = reinterpret_cast<cairo_t*>(hdc);
        cairo_save(context);
        apply_clip(context);
        cairo_rectangle(context, layer.clip_box.x, layer.clip_box.y,
                        layer.clip_box.width, layer.clip_box.height);
        cairo_clip(context);
        apply_compat_color(context, color);
        cairo_rectangle(context, layer.border_box.x, layer.border_box.y,
                        layer.border_box.width, layer.border_box.height);
        cairo_fill(context);
        cairo_restore(context);
        require_context(context, "failed to draw mail HTML background");
        checkpoint();
    }

    void draw_linear_gradient(
        litehtml::uint_ptr hdc, const litehtml::background_layer& layer,
        const litehtml::background_layer::linear_gradient& gradient) override {
        checkpoint();
        if (hdc == 0U || !valid_position(layer.origin_box, true) ||
            !valid_position(layer.clip_box, false) ||
            !valid_coordinate(gradient.start.x) || !valid_coordinate(gradient.start.y) ||
            !valid_coordinate(gradient.end.x) || !valid_coordinate(gradient.end.y)) {
            return;
        }
        container_cairo::draw_linear_gradient(hdc, layer, gradient);
        checkpoint();
    }

    void draw_radial_gradient(
        litehtml::uint_ptr hdc, const litehtml::background_layer& layer,
        const litehtml::background_layer::radial_gradient& gradient) override {
        checkpoint();
        if (hdc == 0U || !valid_position(layer.origin_box, true) ||
            !valid_position(layer.clip_box, false) ||
            !valid_coordinate(gradient.position.x) ||
            !valid_coordinate(gradient.position.y) ||
            !valid_coordinate(gradient.radius.x) ||
            !valid_coordinate(gradient.radius.y) || gradient.radius.x <= 0.0F ||
            gradient.radius.y <= 0.0F) {
            return;
        }
        container_cairo::draw_radial_gradient(hdc, layer, gradient);
        checkpoint();
    }

    void draw_conic_gradient(
        litehtml::uint_ptr hdc, const litehtml::background_layer& layer,
        const litehtml::background_layer::conic_gradient& gradient) override {
        checkpoint();
        if (hdc == 0U || !valid_position(layer.origin_box, true) ||
            !valid_position(layer.clip_box, false) ||
            !valid_coordinate(gradient.position.x) ||
            !valid_coordinate(gradient.position.y) ||
            !valid_coordinate(gradient.angle) || !valid_coordinate(gradient.radius) ||
            gradient.radius <= 0.0F) {
            return;
        }
        container_cairo::draw_conic_gradient(hdc, layer, gradient);
        checkpoint();
    }

    void draw_borders(litehtml::uint_ptr hdc, const litehtml::borders& borders,
                      const litehtml::position& position, bool root) override {
        checkpoint();
        if (hdc == 0U || !valid_position(position, false)) {
            return;
        }
        (void)root;
        auto* context = reinterpret_cast<cairo_t*>(hdc);
        cairo_save(context);
        apply_clip(context);
        const auto draw_edge = [&](const litehtml::border& border,
                                   double x, double y, double width, double height) {
            if (border.width <= 0.0F || border.style <= litehtml::border_style_hidden ||
                width <= 0.0 || height <= 0.0) {
                return;
            }
            apply_compat_color(context, border.color);
            cairo_rectangle(context, x, y, width, height);
            cairo_fill(context);
        };
        const double top = borders.top.width;
        const double bottom = borders.bottom.width;
        const double left = borders.left.width;
        const double right = borders.right.width;
        draw_edge(borders.top, position.x, position.y, position.width, top);
        draw_edge(borders.bottom, position.x, position.y + position.height - bottom,
                  position.width, bottom);
        draw_edge(borders.left, position.x, position.y, left, position.height);
        draw_edge(borders.right, position.x + position.width - right, position.y,
                  right, position.height);
        cairo_restore(context);
        require_context(context, "failed to draw mail HTML borders");
        checkpoint();
    }

    void draw_list_marker(litehtml::uint_ptr hdc,
                          const litehtml::list_marker& marker) override {
        checkpoint();
        if (hdc == 0U || !valid_position(marker.pos, true)) {
            return;
        }
        container_cairo::draw_list_marker(hdc, marker);
        checkpoint();
    }

    void set_clip(const litehtml::position& position,
                  const litehtml::border_radiuses& radii) override {
        checkpoint();
        if (valid_position(position, false)) {
            container_cairo::set_clip(position, radii);
        } else {
            container_cairo::set_clip(litehtml::position(0, 0, 0, 0), {});
        }
    }

    void del_clip() override {
        checkpoint();
        container_cairo::del_clip();
    }

    void make_url(const char* url, const char*, litehtml::string& output) override {
        checkpoint();
        output.clear();
        if (url != nullptr && std::strncmp(url, "cid:", 4U) == 0 && url[4] != '\0') {
            output.assign(url);
        }
    }

    cairo_surface_t* get_image(const std::string& url) override {
        checkpoint();
        if (url.size() <= 4U || url.compare(0U, 4U, "cid:") != 0) {
            return nullptr;
        }
        const std::string cid = url.substr(4U);
        const auto resource = resources_.find(cid);
        if (resource == resources_.end()) {
            return nullptr;
        }
        auto cached = image_cache_.find(cid);
        if (cached == image_cache_.end()) {
            UniqueSurface surface = make_image_surface(resource->second);
            cached = image_cache_.emplace(cid, std::move(surface)).first;
        }
        checkpoint();
        return cairo_surface_reference(cached->second.get());
    }

    double get_screen_dpi() const override { return 96.0; }
    int get_screen_width() const override {
        return static_cast<int>(config_.viewport_width);
    }
    int get_screen_height() const override {
        return static_cast<int>(config_.max_document_height);
    }

    litehtml::pixel_t get_default_font_size() const override {
        checkpoint();
        return std::max(1, static_cast<int>(config_.base_font_size + 0.5F));
    }

    const char* get_default_font_name() const override {
        checkpoint();
        return "sans-serif";
    }

    void set_caption(const char*) override { checkpoint(); }
    void set_base_url(const char*) override { checkpoint(); }
    void on_anchor_click(const char*, const litehtml::element::ptr&) override {
        checkpoint();
    }
    void on_mouse_event(const litehtml::element::ptr&, litehtml::mouse_event) override {
        checkpoint();
    }
    void set_cursor(const char*) override { checkpoint(); }

    void import_css(litehtml::string& text, const litehtml::string&,
                    litehtml::string& base_url) override {
        checkpoint();
        text.clear();
        base_url.clear();
    }

    void get_viewport(litehtml::position& viewport) const override {
        checkpoint();
        viewport.x = 0.0F;
        viewport.y = 0.0F;
        viewport.width = static_cast<litehtml::pixel_t>(config_.viewport_width);
        viewport.height = static_cast<litehtml::pixel_t>(config_.max_document_height);
    }

private:
    struct FontHandle {
        cairo_font_face_t* face = nullptr;
        int size = 1;
        bool italic = false;
        int decoration = litehtml::text_decoration_line_none;
        litehtml::font_metrics metrics{};
    };

    enum FontIndex : size_t {
        SansRegular = 0U,
        SansBold = 1U,
        MonoRegular = 2U,
        MonoBold = 3U,
    };

    void initialize_fonts() {
        checkpoint();
        if (FT_Init_FreeType(&freetype_) != 0) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "failed to initialize FreeType");
        }
        const std::array<const char*, 4U> paths = {
            kSansRegular,
            kSansBold,
            kMonoRegular,
            kMonoBold,
        };
        for (size_t index = 0U; index < paths.size(); ++index) {
            checkpoint();
            if (FT_New_Face(freetype_, paths[index], 0, &freetype_faces_[index]) != 0 ||
                freetype_faces_[index] == nullptr) {
                fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR,
                     std::string("failed to load fixed font: ") + paths[index]);
            }
            if (FT_Select_Charmap(freetype_faces_[index], FT_ENCODING_UNICODE) != 0) {
                fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR,
                     std::string("fixed font has no Unicode charmap: ") + paths[index]);
            }
            cairo_faces_[index] =
                cairo_ft_font_face_create_for_ft_face(freetype_faces_[index], 0);
            const cairo_status_t status = cairo_font_face_status(cairo_faces_[index]);
            if (status != CAIRO_STATUS_SUCCESS) {
                fail(status == CAIRO_STATUS_NO_MEMORY ? LMYZMAIL_MAIL_HTML_OUT_OF_MEMORY
                                                      : LMYZMAIL_MAIL_HTML_RENDER_ERROR,
                     std::string("failed to create Cairo font face: ") +
                         cairo_status_to_string(status));
            }
        }
        checkpoint();
    }

    void cleanup() noexcept {
        if (measure_context_ != nullptr) {
            cairo_destroy(measure_context_);
            measure_context_ = nullptr;
        }
        if (measure_surface_ != nullptr) {
            cairo_surface_destroy(measure_surface_);
            measure_surface_ = nullptr;
        }
        for (cairo_font_face_t*& face : cairo_faces_) {
            if (face != nullptr) {
                cairo_font_face_destroy(face);
                face = nullptr;
            }
        }
        for (FT_Face& face : freetype_faces_) {
            if (face != nullptr) {
                FT_Done_Face(face);
                face = nullptr;
            }
        }
        if (freetype_ != nullptr) {
            FT_Done_FreeType(freetype_);
            freetype_ = nullptr;
        }
    }

    cairo_font_face_t* select_face(const std::string& family, bool bold) const {
        std::string lower = family;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char character) {
            if (character >= 'A' && character <= 'Z') {
                return static_cast<char>(character - 'A' + 'a');
            }
            return static_cast<char>(character);
        });
        const bool monospace = lower.find("mono") != std::string::npos ||
                               lower.find("courier") != std::string::npos ||
                               lower.find("consolas") != std::string::npos;
        const size_t index = monospace ? (bold ? MonoBold : MonoRegular)
                                       : (bold ? SansBold : SansRegular);
        return cairo_faces_[index];
    }

    static void apply_font(cairo_t* context, const FontHandle& font) {
        cairo_set_font_face(context, font.face);
        cairo_matrix_t matrix;
        cairo_matrix_init_scale(&matrix, font.size, font.size);
        if (font.italic) {
            matrix.xy = -0.2 * font.size;
        }
        cairo_set_font_matrix(context, &matrix);
    }

    static void apply_compat_color(cairo_t* context, litehtml::web_color color) {
        const uint8_t alpha = color.alpha == 0U ? 255U : color.alpha;
        cairo_set_source_rgba(context, color.red / 255.0, color.green / 255.0,
                              color.blue / 255.0, alpha / 255.0);
    }

    UniqueSurface make_image_surface(const ResourceView& resource) const {
        checkpoint();
        UniqueSurface surface(cairo_image_surface_create(
            CAIRO_FORMAT_ARGB32, static_cast<int>(resource.width),
            static_cast<int>(resource.height)));
        require_surface(surface.get(), "failed to create CID image surface");
        cairo_surface_flush(surface.get());
        uint8_t* destination = cairo_image_surface_get_data(surface.get());
        const int destination_stride = cairo_image_surface_get_stride(surface.get());
        if (destination == nullptr || destination_stride < 0 ||
            static_cast<size_t>(destination_stride) <
                static_cast<size_t>(resource.width) * 4U) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "invalid Cairo CID image buffer");
        }

        for (uint32_t y = 0U; y < resource.height; ++y) {
            if ((y & 63U) == 0U) {
                checkpoint();
            }
            const uint8_t* source_row =
                resource.rgba + static_cast<size_t>(y) * resource.stride;
            auto* destination_row = reinterpret_cast<uint32_t*>(
                destination + static_cast<size_t>(y) * destination_stride);
            for (uint32_t x = 0U; x < resource.width; ++x) {
                const uint8_t* pixel = source_row + static_cast<size_t>(x) * 4U;
                const uint32_t alpha = pixel[3];
                const uint32_t red = static_cast<uint32_t>(pixel[0]) * alpha / 255U;
                const uint32_t green = static_cast<uint32_t>(pixel[1]) * alpha / 255U;
                const uint32_t blue = static_cast<uint32_t>(pixel[2]) * alpha / 255U;
                destination_row[x] = (alpha << 24U) | (red << 16U) | (green << 8U) | blue;
            }
        }
        cairo_surface_mark_dirty(surface.get());
        require_surface(surface.get(), "failed to populate CID image surface");
        checkpoint();
        return surface;
    }

    lmyzmail_mail_html_config config_{};
    std::map<std::string, ResourceView> resources_;
    std::map<std::string, UniqueSurface> image_cache_;
    cairo_surface_t* measure_surface_ = nullptr;
    cairo_t* measure_context_ = nullptr;
    FT_Library freetype_ = nullptr;
    std::array<FT_Face, 4U> freetype_faces_{};
    std::array<cairo_font_face_t*, 4U> cairo_faces_{};
};

class NativeContext final {
public:
    NativeContext(const lmyzmail_mail_html_config& config,
                  const uint8_t* html,
                  size_t html_len,
                  std::vector<ResourceView> resources)
        : config_(config),
          container_(config, std::move(resources)) {
        container_.checkpoint();
        const std::string html_storage =
            html_len == 0U
                ? std::string()
                : std::string(reinterpret_cast<const char*>(html), html_len);
        const std::string user_css =
            "img { max-width: " + std::to_string(config_.viewport_width) +
            "px !important; height: auto !important; }";
        document_ = litehtml::document::createFromString(
            html_storage, &container_, litehtml::master_css, user_css);
        container_.checkpoint();
        if (!document_) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR,
                 "litehtml returned a null document while parsing mail HTML");
        }
        document_->render(static_cast<litehtml::pixel_t>(config_.viewport_width));
        container_.checkpoint();

        const float raw_width = document_->width();
        const float raw_height = document_->height();
        if (!std::isfinite(raw_width) || !std::isfinite(raw_height) ||
            raw_width > kMaxCoordinate || raw_height > kMaxCoordinate) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "litehtml produced invalid document dimensions");
        }
        content_width_ = raw_width > 0.0F ? static_cast<uint32_t>(raw_width)
                                          : config_.viewport_width;
        content_height_ = raw_height > 0.0F ? static_cast<uint32_t>(raw_height) : 128U;
        content_width_ = std::max(1U, std::min(content_width_, config_.viewport_width));
        content_height_ =
            std::max(1U, std::min(content_height_, config_.max_document_height));
    }

    NativeContext(const NativeContext&) = delete;
    NativeContext& operator=(const NativeContext&) = delete;

    void checkpoint() const { container_.checkpoint(); }
    uint32_t content_width() const noexcept { return content_width_; }
    uint32_t content_height() const noexcept { return content_height_; }

    void render(uint32_t y_start,
                uint32_t output_width,
                uint32_t output_height,
                uint8_t* output_rgb,
                size_t output_len,
                size_t output_stride) {
        checkpoint();
        if (output_rgb == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGB output pointer is null");
        }
        if (output_width == 0U || output_width > kMaxViewportWidth ||
            output_height == 0U || output_height > kMaxDocumentHeight) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
                 "mail HTML RGB output dimensions are out of range");
        }
        const uint64_t pixels = static_cast<uint64_t>(output_width) * output_height;
        if (pixels > kMaxRenderPixels) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED,
                 "mail HTML RGB output exceeds pixel budget");
        }
        if (y_start > config_.max_document_height) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML render offset is out of range");
        }
        const uint64_t range_end = static_cast<uint64_t>(y_start) + output_height;
        if (range_end > static_cast<uint64_t>(config_.max_document_height) + 127U) {
            fail(LMYZMAIL_MAIL_HTML_LIMIT_EXCEEDED, "mail HTML render range is out of bounds");
        }

        const size_t row_bytes =
            checked_multiply(static_cast<size_t>(output_width), 3U,
                             "mail HTML RGB row size overflow");
        if (output_stride < row_bytes) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGB stride is too small");
        }
        const size_t required = checked_multiply(
            output_stride, static_cast<size_t>(output_height),
            "mail HTML RGB output size overflow");
        if (output_len < required) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML RGB output buffer is too short");
        }

        UniqueSurface surface(cairo_image_surface_create(
            CAIRO_FORMAT_ARGB32, static_cast<int>(output_width),
            static_cast<int>(output_height)));
        require_surface(surface.get(), "failed to create mail HTML output surface");
        UniqueCairo cairo(cairo_create(surface.get()));
        require_context(cairo.get(), "failed to create mail HTML output context");

        const double red = ((config_.background_rgb >> 16U) & 0xFFU) / 255.0;
        const double green = ((config_.background_rgb >> 8U) & 0xFFU) / 255.0;
        const double blue = (config_.background_rgb & 0xFFU) / 255.0;
        cairo_set_source_rgb(cairo.get(), red, green, blue);
        cairo_paint(cairo.get());

        if (y_start < content_height_) {
            const uint32_t draw_height =
                std::min(output_height, content_height_ - y_start);
            cairo_save(cairo.get());
            cairo_translate(cairo.get(), 0.0, -static_cast<double>(y_start));
            cairo_rectangle(cairo.get(), 0.0, static_cast<double>(y_start),
                            static_cast<double>(output_width),
                            static_cast<double>(draw_height));
            cairo_clip(cairo.get());
            litehtml::position clip(
                0.0F, static_cast<litehtml::pixel_t>(y_start),
                static_cast<litehtml::pixel_t>(output_width),
                static_cast<litehtml::pixel_t>(draw_height));
            document_->draw(reinterpret_cast<litehtml::uint_ptr>(cairo.get()), 0.0F, 0.0F,
                            &clip);
            cairo_restore(cairo.get());
        }
        require_context(cairo.get(), "failed to render mail HTML document");
        checkpoint();

        cairo_surface_flush(surface.get());
        require_surface(surface.get(), "failed to flush mail HTML output surface");
        const uint8_t* source = cairo_image_surface_get_data(surface.get());
        const int source_stride = cairo_image_surface_get_stride(surface.get());
        if (source == nullptr || source_stride < 0 ||
            static_cast<size_t>(source_stride) < static_cast<size_t>(output_width) * 4U) {
            fail(LMYZMAIL_MAIL_HTML_RENDER_ERROR, "invalid Cairo mail HTML output buffer");
        }
        for (uint32_t y = 0U; y < output_height; ++y) {
            if ((y & 63U) == 0U) {
                checkpoint();
            }
            const uint8_t* source_row =
                source + static_cast<size_t>(y) * static_cast<size_t>(source_stride);
            uint8_t* destination_row = output_rgb + static_cast<size_t>(y) * output_stride;
            for (uint32_t x = 0U; x < output_width; ++x) {
                const uint8_t* pixel = source_row + static_cast<size_t>(x) * 4U;
                uint8_t* destination = destination_row + static_cast<size_t>(x) * 3U;
                destination[0] = pixel[2];
                destination[1] = pixel[1];
                destination[2] = pixel[0];
            }
        }
        checkpoint();
    }

private:
    lmyzmail_mail_html_config config_{};
    MailContainer container_;
    litehtml::document::ptr document_;
    uint32_t content_width_ = 1U;
    uint32_t content_height_ = 1U;
};

}  // namespace

struct lmyzmail_mail_html_context {
    explicit lmyzmail_mail_html_context(
        const lmyzmail_mail_html_config& config,
        const uint8_t* html,
        size_t html_len,
        std::vector<ResourceView> resources)
        : implementation(config, html, html_len, std::move(resources)) {}

    NativeContext implementation;
};

extern "C" {

uint32_t lmyzmail_mail_html_abi_version(void) {
    return LMYZMAIL_MAIL_HTML_ABI_VERSION;
}

int32_t lmyzmail_mail_html_create(
    const lmyzmail_mail_html_config* config,
    const uint8_t* html,
    size_t html_len,
    const lmyzmail_mail_html_resource* resources,
    size_t resource_count,
    lmyzmail_mail_html_context** out_context,
    char* error,
    size_t error_capacity) {
    return ffi_boundary(error, error_capacity, [&] {
        if (config == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML config pointer is null");
        }
        if (out_context == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT,
                 "mail HTML output context pointer is null");
        }
        *out_context = nullptr;
        std::vector<ResourceView> validated =
            validate_inputs(*config, html, html_len, resources, resource_count);
        auto context = std::make_unique<lmyzmail_mail_html_context>(
            *config, html, html_len, std::move(validated));
        context->implementation.checkpoint();
        *out_context = context.release();
    });
}

int32_t lmyzmail_mail_html_query_size(
    const lmyzmail_mail_html_context* context,
    uint32_t* out_width,
    uint32_t* out_height,
    char* error,
    size_t error_capacity) {
    return ffi_boundary(error, error_capacity, [&] {
        if (context == nullptr || out_width == nullptr || out_height == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT,
                 "mail HTML size query received a null pointer");
        }
        context->implementation.checkpoint();
        *out_width = context->implementation.content_width();
        *out_height = context->implementation.content_height();
    });
}

int32_t lmyzmail_mail_html_render_range(
    lmyzmail_mail_html_context* context,
    uint32_t y_start,
    uint32_t output_width,
    uint32_t output_height,
    uint8_t* output_rgb,
    size_t output_len,
    size_t output_stride,
    char* error,
    size_t error_capacity) {
    return ffi_boundary(error, error_capacity, [&] {
        if (context == nullptr) {
            fail(LMYZMAIL_MAIL_HTML_INVALID_ARGUMENT, "mail HTML context pointer is null");
        }
        context->implementation.render(y_start, output_width, output_height, output_rgb,
                                       output_len, output_stride);
    });
}

int32_t lmyzmail_mail_html_destroy(
    lmyzmail_mail_html_context* context,
    char* error,
    size_t error_capacity) {
    return ffi_boundary(error, error_capacity, [&] { delete context; });
}

}  // extern "C"

#if defined(LMYZMAIL_MAIL_HTML_STANDALONE_SMOKE)

namespace {

int32_t smoke_cancel(void*) {
    return 1;
}

}  // namespace

int main() {
    if (lmyzmail_mail_html_abi_version() != LMYZMAIL_MAIL_HTML_ABI_VERSION) {
        return 10;
    }

    lmyzmail_mail_html_config config{};
    config.struct_size = sizeof(config);
    config.viewport_width = 128U;
    config.max_document_height = 512U;
    config.base_font_size = 16.0F;
    config.background_rgb = 0x00FFFFFFU;

    constexpr char html[] =
        "<html><head><style>@import url(file:///etc/passwd);</style></head>"
        "<body style=\"margin:0;background:#00ff00\">"
        "<img src=\"cid:smoke\" width=\"2\" height=\"1\">smoke"
        "<img src=\"/etc/passwd\"><img src=\"file:///etc/passwd\">"
        "<img src=\"/tmp/lmyzmail-mail-html-smoke-fifo\">"
        "<img src=\"file:///tmp/lmyzmail-mail-html-smoke-fifo\">"
        "<img src=\"http://127.0.0.1:18099/trap\">"
        "<img src=\"data:image/png;base64,AAAA\">"
        "</body></html>";
    constexpr std::array<uint8_t, 8U> rgba = {
        255U, 0U, 0U, 255U,
        0U, 0U, 255U, 255U,
    };
    constexpr std::array<uint8_t, 8U> duplicate_rgba = {
        0U, 255U, 0U, 255U,
        0U, 255U, 0U, 255U,
    };
    constexpr char cid[] = "smoke";
    std::array<lmyzmail_mail_html_resource, 2U> resources{};
    resources[0].cid = reinterpret_cast<const uint8_t*>(cid);
    resources[0].cid_len = sizeof(cid) - 1U;
    resources[0].rgba = rgba.data();
    resources[0].rgba_len = rgba.size();
    resources[0].width = 2U;
    resources[0].height = 1U;
    resources[0].stride = 8U;
    resources[1] = resources[0];
    resources[1].rgba = duplicate_rgba.data();
    resources[1].rgba_len = duplicate_rgba.size();

    std::array<char, 256U> error{};
    lmyzmail_mail_html_context* context = nullptr;
    int32_t status = lmyzmail_mail_html_create(
        &config, reinterpret_cast<const uint8_t*>(html), sizeof(html) - 1U,
        resources.data(), resources.size(), &context, error.data(), error.size());
    if (status != LMYZMAIL_MAIL_HTML_OK || context == nullptr) {
        return 20;
    }

    uint32_t width = 0U;
    uint32_t height = 0U;
    status = lmyzmail_mail_html_query_size(
        context, &width, &height, error.data(), error.size());
    if (status != LMYZMAIL_MAIL_HTML_OK || width == 0U || height == 0U ||
        width > config.viewport_width || height > config.max_document_height) {
        lmyzmail_mail_html_destroy(context, error.data(), error.size());
        return 30;
    }

    constexpr uint32_t output_width = 128U;
    constexpr uint32_t output_height = 128U;
    constexpr size_t output_stride = output_width * 3U;
    std::vector<uint8_t> rgb(output_stride * output_height, 0U);
    status = lmyzmail_mail_html_render_range(
        context, 0U, output_width, output_height, rgb.data(), rgb.size(),
        output_stride, error.data(), error.size());
    if (status != LMYZMAIL_MAIL_HTML_OK) {
        lmyzmail_mail_html_destroy(context, error.data(), error.size());
        return 40;
    }
    const bool has_non_background_pixel =
        std::any_of(rgb.begin(), rgb.end(), [](uint8_t channel) { return channel != 255U; });
    if (!has_non_background_pixel) {
        lmyzmail_mail_html_destroy(context, error.data(), error.size());
        return 41;
    }
    bool has_first_resource_pixel = false;
    for (size_t offset = 0U; offset < rgb.size(); offset += 3U) {
        if (rgb[offset] == 255U && rgb[offset + 1U] == 0U &&
            rgb[offset + 2U] == 0U) {
            has_first_resource_pixel = true;
            break;
        }
    }
    if (!has_first_resource_pixel) {
        lmyzmail_mail_html_destroy(context, error.data(), error.size());
        return 42;
    }
    if (lmyzmail_mail_html_destroy(context, error.data(), error.size()) !=
        LMYZMAIL_MAIL_HTML_OK) {
        return 50;
    }

    config.cancel = smoke_cancel;
    context = nullptr;
    status = lmyzmail_mail_html_create(
        &config, reinterpret_cast<const uint8_t*>(html), sizeof(html) - 1U,
        nullptr, 0U, &context, error.data(), error.size());
    if (status != LMYZMAIL_MAIL_HTML_CANCELLED || context != nullptr) {
        lmyzmail_mail_html_destroy(context, error.data(), error.size());
        return 60;
    }
    return 0;
}

#endif
