/* Authored memory I/O boundary. No effect, palette or audio-processing code. */
#include <stdint.h>
_Static_assert(sizeof(void *) == 4, "Compile this boundary for 32-bit Xtensa");
typedef struct {
    void *vtable;
    uint16_t reserved, start, length, padding;
    uint8_t *pixels;
} VirtualBus;

uint16_t virtual_length(VirtualBus *bus) { return bus->length; }

void virtual_set(VirtualBus *bus, uint16_t index, uint32_t color) {
    if (index >= bus->length) return;
    uint8_t *pixel = bus->pixels + 3 * index;
    pixel[0] = color >> 16;
    pixel[1] = color >> 8;
    pixel[2] = color;
}

uint32_t virtual_get(VirtualBus *bus, uint16_t index) {
    if (index >= bus->length) return 0;
    const uint8_t *pixel = bus->pixels + 3 * index;
    return ((uint32_t)pixel[0] << 16) | ((uint32_t)pixel[1] << 8) | pixel[2];
}

/* The WLED scheduler normally updates strip.now before calling an effect. */
void set_frame_time(uint32_t *clock, uint32_t milliseconds) { *clock = milliseconds; }

typedef struct {
    void *vtable;
    void *data;
    uint32_t reads;
} VirtualAudio;

uint16_t virtual_audio_id(VirtualAudio *audio) { (void)audio; return 32; }
uint8_t virtual_audio_data(VirtualAudio *audio, void **output) {
    *output = audio->data;
    ++audio->reads;
    return 1;
}

void snapshot(uint32_t *calls, const uint16_t *mapping, const uint8_t *physical,
              uint8_t *logical, uint32_t count) {
    ++*calls;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t index = mapping[i];
        for (uint32_t channel = 0; channel < 3; ++channel)
            logical[3*i+channel] = index < count ? physical[3*index+channel] : 0;
    }
}
