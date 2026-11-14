# Device profiles and execution boundaries

Alongside its executable device adapters, TycVirtualLab includes three runnable **synthetic demonstrations**. They test
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
Firmware, recovered palettes and measurements remain external inputs. Reusable
address maps and device setup are included in the shareable source.

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

Detailed workflows: [HyperCube](hypercube.md), [Exoy ONE](exoy.md), [GLORB](glorb.md),
and [audio calibration](calibration.md).

## Executable device setup

The public `vfl.devices` package contains reusable device maps and builders. The
CLI exposes them through `device list`, `device effects`, `device prepare` and
`device coverage`. Firmware and output files are supplied in external directories.

| Device | Execution boundary | Captured output |
| --- | --- | --- |
| HyperCube hs-2.2 | Original static constructors, application setup, boot configuration, audio analysis and effect engine; SDK/peripheral boundaries declared | Two 144-pixel GRB driver buffers and firmware state |
| Exoy ONE v2.1 | Original Xtensa windowed routines; supported selectors and runtime hooks declared by the profile | 480 RGB pixels and renderer state |
| GLORB | Supplied recovered renderer compiled with the public WLED host boundary | 120 logical cells, a bus sized from factory configuration, segment state and actual processed-audio reads |

An adapter's inventory is not proof that every effect ran. Coverage reports keep
requested selectors, executed entry points, nonblack frames, changes and failures
separate. Original instruction execution and recovered C++ execution have distinct
manifest labels. Neither label claims reset-ROM boot or a physical microphone.

GLORB uses externally supplied factory presets, palettes and mapping. It drops
writes and returns black at holes during rendering, preserving feedback behavior.
The capture has both logical and mapped pre-output stages. Audio input is the
processed `volumeSmth` value, not raw PCM. Changes of effect reset segment state;
changing a palette requires its actual table. Its host is an independent comparison
target for original-machine-code captures, not a certificate of equivalence.

Xtensa call0, classic ESP32 register windows and ESP32-S3 code remain distinct
targets. The pinned Ghidra adapter includes regression fixtures for register-window
rotation, locals, nested and indirect calls, and hardware loops. Missing instructions
and undefined memory fail explicitly; any runtime substitutions are named and logged.

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
