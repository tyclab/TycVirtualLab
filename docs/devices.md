# Device profiles and execution boundaries

TycVirtualLab includes three runnable **synthetic demonstrations**. They test
trace handling, state, pixel streams and viewing. They do not execute vendor
firmware or reproduce any vendor effect. Every demo capture declares this in
its manifest.

| Profile | Streams | Illustrative geometry |
| --- | --- | --- |
| `hypercube-demo` | Two logical streams of 144 RGB pixels | Cube, 12 edges × 24 points; synthetic bus and edge order |
| `exoy-one-demo` | One logical stream of 480 RGB pixels | Dodecahedron, 30 edges × 16 points; synthetic edge order |
| `glorb-demo` | One logical stream of 120 RGB slots | 20 × 6 raster; 80 visible cells on six spherical rings, 40 holes |

The profiles contain mathematical geometry rather than private room models,
factory LED maps or calibrated wiring. Dimensions are arbitrary display units.
Pixel counts, raster sizes and ring arrangements in this table are illustrative
fixture choices, not statements about a manufacturer's internal layout.
Mirror reflections, diffuser shape and optical brightness are not modeled.
Firmware, recovered palettes, device addresses and measurements belong in an
external private workspace.

## Adding geometry

`geometry.points` is an array of `{bus, index, x, y, z}` objects. Each point
references a pixel in a declared bus. Coordinates can describe a strip, matrix,
polyhedron or another shape. Version 1 allows one point per pixel. A
`geometry.description` states how the coordinates were obtained and whether
the mapping is calibrated. A strip view remains available even with points.

`geometry.mask` maps bus IDs to boolean arrays of exactly the bus length.
False entries are crossed out in strip view and omitted in point view. This
display projection does not prove that the backend discarded writes or returned
black on reads. A renderer with feedback must implement its own pixel-access
semantics. The synthetic GLORB demo explicitly requests
`settings.pixel_access = "masked-black"`; a real adapter must independently
reproduce its device's access behavior.

`buses[].stage` distinguishes `logical` from `driver` bytes. The GLORB demo's
120-slot raster is a logical space, not an assertion that 120 physical face
LEDs exist. Logical-to-physical mapping, skipped indices, byte order, gamma,
brightness and limiting are adapter responsibilities. Compare like stages.

## Private device adapters

| Family | Private configuration needed | First execution boundary |
| --- | --- | --- |
| HyperCube | A compatible ELF/ROM, initialization recipe and verified function boundaries | Run original code with explicit clock, input, state and output regions; distinguish it from a recovered port |
| Exoy ONE | An image loader, matching CPU/ABI model and verified input/output boundaries | Establish a small independently checked routine before claiming a complete renderer |
| GLORB | Matching CPU/ABI support, input state and logical-to-physical pixel mapping | Identify the renderer's dependencies and preserve any masked pixel semantics during computation |

An original-machine-code backend must support the actual instruction set and
ABI. ESP8266 call0 code, classic ESP32 register-window code and ESP32-S3 code
are separate execution targets. Merely parsing their image headers does not
establish an executable reference. Each adapter declares supported inputs,
clock/RNG/state logs, unsupported calls and limitations in its capture manifest.

Recovered effects may depend on segment buffers, time, palette helpers and
audio data. A usermod source file is therefore not necessarily a standalone host
renderer. A host adapter must supply these dependencies explicitly. Captured liveview
pixels also need a stage label: they may precede gamma and power limiting.

A local control-protocol fixture can test serialization without opening a
socket. The framework does not send packets or provision devices. An app's scene
labels or command registry alone do not establish its rendering algorithms.

## Viewing evidence

Open a capture in the packaged viewer or export self-contained HTML. The file
is read locally in the browser; there are no uploads, CDN assets or network
requests. Exported HTML includes the capture's full manifest, frame state and
events, so keep it with the private run results.

Playback uses recorded timestamps. The inspector displays both stored byte
order and decoded RGB, along with the bus stage. Execution labels and capability
flags are declarations from the capture, not attestations from the viewer.
The viewer warns when a display-masked pixel contains nonzero stored bytes.
Crossed cells remain inspectable in Strips view, and byte comparison includes
masked pixels regardless of whether the preview draws their color.
Use stored original outputs, held-out fixtures and deliberately corrupted data
to test the execution backend and comparator separately from visual appeal.

## Inspecting image files

`tycvl inspect-image` reads a local file without running code. The Python API is
`vfl.firmware.inspect_image(path, format="auto")`. It returns metadata including
the file hash, architecture identifier, entry point and segment bounds; it does
not emit payloads or recovered strings. Invalid or unsupported layouts raise
`LabError`. Inputs must be regular files no larger than 256 MiB.

Supported Espressif inputs are standalone E9 application images with an 8-byte
ESP8266 header or a 24-byte ESP32-family header. The inspector checks each segment,
the padded XOR checksum, and the optional appended SHA256. Automatic selection
accepts validated ESP32-family layouts; ESP8266 requires explicit format selection
because E9 alone does not identify a chip. An image valid under both layouts also
requires explicit selection. ESP32 chip IDs 0 and 9 identify ESP32 and ESP32-S3;
unknown IDs remain unknown. Signed-image trailers, merged flash images, encrypted
images, filesystem images and ESP8266 EA containers are unsupported.

For ELF32/ELF64, either byte order is supported. Header tables, section and segment
file bounds, load sizes and alignment are checked. An ELF Xtensa machine ID does
not distinguish an Espressif chip, register-window ABI or particular CPU core.
ELF structure checks provide no embedded checksum or signature verification.

`valid: true` means that the supported layout and reported checks passed. It does
not establish instruction validity, vendor authenticity, board compatibility,
peripheral emulation or successful execution. The appended Espressif SHA256 is
an integrity check, not a secure-boot signature.

Format references: Espressif's [ESP32 image format](https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/firmware-image-format.html)
and [ESP8266 image format](https://docs.espressif.com/projects/esptool/en/latest/esp8266/advanced-topics/firmware-image-format.html),
the generic ABI's [ELF header](https://gabi.xinuos.com/elf/02-eheader.html) and
[program header](https://gabi.xinuos.com/elf/07-pheader.html), and Espressif's
[ESP32](https://github.com/espressif/esptool/blob/master/esptool/targets/esp32.py)
and [ESP32-S3](https://github.com/espressif/esptool/blob/master/esptool/targets/esp32s3.py)
chip-ID definitions.
