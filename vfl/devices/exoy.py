"""Exoy ONE v2.1 original-code scene setup. User-supplied image required.

Address metadata and initialization recipes are shared; no firmware, palettes,
reconstructed effects, device state or observed RGB are bundled.
"""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import struct
import shutil
import sys

from .. import device_inputs
from ..firmware import inspect_image
from ..model import LabError, compatible_input, file_digest, integer, private_path, require, validate_profile, validate_trace

APP_SHA256 = "976a7381601509547055dc434c7e954ad7fda70226f16b34cf4acb648cd0ac1a"
SOURCE = "https://github.com/the-skips/Exoy-bin-files/tree/91c28be5cbb90765e97cba3ae7f135d5cc1ad237"
SEGMENTS = (
 (0x3f400020,211592,"75326061588a75ec6dede7f54159db9ce0becc3512df40d7b72590d7da283b56"),
 (0x3ffbdb60,30464,"447075fea829003fda5e32fa16e0cfc886a84f227888c45661653cc88c5052c2"),
 (0x40080000,20064,"c829d2b1587273db3ac3ba19c1f51a17d30e57b689000933ec3b745f31678206"),
 (0x400d0020,850828,"e2f71037135fe9b5f66a2da65184c2e0a5cfc41ea56152f6c97e97377dd0d49c"),
 (0x40084e60,62664,"90a78b14d993f23d9640d2c791ea69f651f737f6172c048708e6e8e5d21fbd2b"),
)
PACKS = (('Rave', ('Beats Burst', 'Laser Lash', 'Electric Ave', 'Hypnosis', 'Glow Groove', 'Whirling Spectrum', 'Rainbow Rumble')), ('Party', ('Dance Floor', 'Rhythm Run', 'Pop Party', 'Funky Flash', 'Jubulo', 'Gloze', 'Color Rush', 'Confetti', 'Rising Rhythm', 'Pulse Peaks', 'Beat Orbit')), ('Chill', ('Soothing Sound', 'Euphoria', 'Dreamscape', 'Serene Symphony', 'Svelte', 'Tranquilo')), ('Mood', ('Mood Swing', 'Emotional Express', 'Feeling Flow', 'Zenith', 'Nimbus')), ('Genre', ('Rockin’ Rhythms', 'Jazz Live', 'Hip Hop Hues', 'Country Crescendo', 'EDM Flow', 'Hardstyle Beats')), ('Themes', ('Cosmic Carnival', 'Summer Breeze', 'Desert Miracle', 'Winter Wonderland', 'Underwater Oasis', 'Rainbow Ripple', 'Error', 'Matrix', 'Beating Heart')), ('Nature', ('Wildfire', 'Thunderstorm', 'Aurora', 'Rainbow Reflection', 'Bloom', 'Celestial', 'Ebb & Flow', 'Majestic', 'Whirlwind', 'Lightning', 'Snowstorm')), ('Cosmic', ('Galaxy', 'Cosmic Dust', 'Solar Flare', 'Sabre Fight', 'Black Hole', 'Meteor', 'Astro', 'Super Nova')), ('Background', ('Ambient Aura', 'Twilight', 'Dawn', 'Custom Hue', 'Color Carousel', 'Shimmer', 'Whisper')))
ROM_SHA256 = "bef39889393de40d7ae8dcf1cfe0bba32435a96a0b6ec35839724a9fddd6049f"
# Original Espressif ROM instructions and constants, supplied separately.
ROM_SECTIONS = ((0x40000560, 2016, 53516), (0x40010000, 55540, 347890),
                (0x3ff96000, 403432, 36888))
# Synthetic stack/heap lie outside application data/BSS and the supplied ROM's
# reserved RAM (including its PRO/APP stacks). They are not physical boot state.
STACK_START, STACK_SIZE = 0x3ffd8000, 0x7000
HEAP_START, HEAP_SIZE = 0x3fff0000, 0x10000
SELECTORS = (0x400da404,0x400da4f0,0x40194038,0x401940e4,0x400da668,0x4019419c,0x401942e4,0x400da768,0x400da890)
ADC_INPUT = {"kind":"scalar","channels":64,"minimum":0,"maximum":4095,"units":"esp32-adc-chronological-read-counts"}
INPUT = {"kind":"bands","channels":2,"minimum":0,"maximum":255,"units":"exoy-renderer-audio-counts"}
DEFAULTS = {"pack":1,"effect":4,"brightness":255,"speed":None,"hue":None,"saturation":None,
            "sound_reactive":True,"strip_order":None,"strip_reverse":None}
LIMITATIONS = [
 "Original scene dispatcher, selectors, renderer and pixel helpers execute; board boot and physical LED output are excluded.",
 "ESP32 floating division helper is replaced by finite IEEE754 binary32 division; this is a runtime substitution, not original instruction execution of that helper.",
 "The image entrypoint's BSS span is explicitly zero-initialized and strip objects are declared. This is an isolated application-state boundary, not a captured factory boot state.",
 "Original strip mapping/reversal initialization executes from image data; optional overrides are explicit. No measured three-dimensional optical placement is supplied.",
 "Original microphone routine consumes up to 64 chronological ADC return values per frame, including original max aggregation, baseline and envelope processing. ADC hardware, acquisition timing and microphone transfer function are excluded; samples are not calibrated sound pressure.",
 "A bounded 64 KiB first-fit arena replaces SDK malloc/realloc/free; original vector/effect code executes. Allocation addresses, ownership checks and lifetime are modeled; the ESP-IDF heap algorithm and RTOS are excluded.",
 "RGB is captured before the hardware-show boundary, so physical timing, final driver brightness/current limiting and dithering are not modeled.",
]
RENDERER_INPUT_LIMITATION = "Optional two-byte renderer inputs replace the microphone-processing routine at two internal globals; original microphone acquisition/DSP are excluded at this narrower boundary, not calibrated PCM or sound pressure."

def effect_inventory():
    return [{"pack":pi,"pack_name":name,"effect":ei,"name":effect,
             "status":"original-selector-present; runtime coverage must be checked"}
            for pi,(name,effects) in enumerate(PACKS) for ei,effect in enumerate(effects)]

def device_info():
    return {"id":"exoy-one","name":"Exoy ONE","revision":"v2.1",
            "execution_kind":"original-firmware","execution_scope":"routine-diagnostic","backend":"ghidra-pcode, logical Xtensa windows",
            "image_sha256":APP_SHA256,"source":SOURCE,"effects":effect_inventory(),
            "input":copy.deepcopy(ADC_INPUT),"renderer_input":copy.deepcopy(INPUT),
            "renderer_input_limitations":[RENDERER_INPUT_LIMITATION],"rom_sha256":ROM_SHA256,"limitations":list(LIMITATIONS)}

def settings(values=None):
    values={} if values is None else values
    require(isinstance(values,dict) and set(values)<=set(DEFAULTS),"unknown Exoy setting")
    result=copy.deepcopy(DEFAULTS);result.update(values)
    integer(result["pack"],"pack",0,len(PACKS)-1)
    integer(result["effect"],"effect",0,len(PACKS[result["pack"]][1])-1)
    integer(result["brightness"],"brightness",0,255)
    for key in ("speed","hue","saturation"):
        if result[key] is not None: integer(result[key],key,0,255)
    require(type(result["sound_reactive"]) is bool,"sound_reactive must be boolean")
    require(result["strip_order"] is None or (isinstance(result["strip_order"],list) and all(type(i) is int for i in result["strip_order"])
            and sorted(result["strip_order"])==list(range(30))),"strip_order must be null or permute thirty strips")
    require(result["strip_reverse"] is None or (isinstance(result["strip_reverse"],list) and len(result["strip_reverse"])==30
            and all(type(i) is bool for i in result["strip_reverse"])),"strip_reverse must be null or thirty booleans")
    return result

def _verify_elf(elf):
    path=Path(elf).expanduser().resolve(strict=True); info=inspect_image(path,"elf");data=path.read_bytes()
    require(info["machine_id"]==94 and info["elf_class"]==32 and info["byte_order"]=="little","expected Xtensa ELF32")
    loaded=[s for s in info["segments"] if s["type"]==1]
    require(len(loaded)==len(SEGMENTS),"unexpected Exoy ELF load segments")
    for address,size,sha in SEGMENTS:
        found=[s for s in loaded if s["virtual_address"]==address and s["physical_address"]==address
               and s["file_size"]==size and s["memory_size"]==size]
        require(len(found)==1,"unexpected Exoy segment address or size")
        s=found[0];require(hashlib.sha256(data[s["file_offset"]:s["file_offset"]+size]).hexdigest()==sha,"Exoy segment digest mismatch")
    for section in info["sections"]:
        if not section["flags"]&2 or not section["has_file_data"] or not section["size"]:continue
        a,n=section["address"],section["size"]
        matches=[s for s in loaded if s["virtual_address"]<=a and a+n<=s["virtual_address"]+s["file_size"]]
        require(len(matches)==1,"unexpected allocated Exoy ELF section")
        expected=matches[0]["file_offset"]+a-matches[0]["virtual_address"]
        require(data[section["file_offset"]:section["file_offset"]+n]==data[expected:expected+n],"ELF section differs from load segment")
    _verify_control_defaults(data, loaded)
    return path,info["sha256"]


def _verify_control_defaults(data, loaded):
    """Null controls restore the identified image's actual -1 initializer."""
    address,size=0x3ffbdbb0,9*30*3*4
    matches=[s for s in loaded if s["virtual_address"]<=address and
             address+size<=s["virtual_address"]+s["file_size"]]
    require(len(matches)==1,"Exoy control defaults are outside loaded data")
    offset=matches[0]["file_offset"]+address-matches[0]["virtual_address"]
    require(data[offset:offset+size]==b"\xff"*size,"Exoy image control defaults are not the expected -1 sentinel")

def prepare_image(app_image,output_elf):
    source=Path(app_image).expanduser().resolve(strict=True);info=inspect_image(source,"esp32")
    require(info["sha256"]==APP_SHA256,"only the identified Exoy v2.1 application is supported")
    data=source.read_bytes();segments=info["segments"]
    names=b"\0";sections=[];programs=[];result=bytearray(52+32*len(segments))
    for i,seg in enumerate(segments):
        a,n,o=seg["load_address"],seg["file_size"],seg["file_offset"]
        result.extend(bytes(-len(result)%4));start=len(result);result.extend(data[o:o+n])
        executable=0x40000000<=a<0x40400000;name_offset=len(names);names+=f".segment{i}".encode()+b"\0"
        programs.append(struct.pack("<IIIIIIII",1,start,a,a,n,n,5 if executable else 6,4))
        sections.append(struct.pack("<IIIIIIIIII",name_offset,1,6 if executable else 3,a,start,n,0,0,4,0))
    name_offset=len(names);names+=b".shstrtab\0";start=len(result);result+=names
    sections.append(struct.pack("<IIIIIIIIII",name_offset,3,0,0,start,len(names),0,0,1,0))
    result.extend(bytes(-len(result)%4));section_offset=len(result);result+=bytes(40)+b"".join(sections)
    result[:52]=struct.pack("<16sHHIIIIIHHHHHH",b"\x7fELF\x01\x01\x01"+bytes(9),2,94,1,info["entry_point"],52,section_offset,0x300,52,32,len(programs),40,len(sections)+1,len(sections))
    result[52:52+32*len(programs)]=b"".join(programs)
    target=private_path(output_elf);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as f:f.write(result)
    _verify_elf(target)
    return target

def _write(address,value,width=4):
    return {"op":"write","address":address,"hex":int(value).to_bytes(width,"little").hex()}

def _controls(options, changed=None):
    """Write selected controls, preserving render and strip state during frames."""
    initial = changed is None
    changed = set(DEFAULTS) if initial else set(changed)
    result = []
    locations = {"brightness":(0x3ffc53cc,1), "sound_reactive":(0x3ffc53d4,1),
                 "pack":(0x3ffc53d8,4), "effect":(0x3ffc53dc,1)}
    for key,(address,width) in locations.items():
        if key in changed: result.append(_write(address,int(options[key]),width))
    if initial: result.append(_write(0x3ffc53d5,1,1))
    table=0x3ffbdbb0+options["pack"]*360+options["effect"]*12
    for i,key in enumerate(("speed","hue","saturation")):
        if key in changed or changed & {"pack","effect"}:
            result.append(_write(table+i*4,0xffffffff if options[key] is None else options[key]))
    return result


def _geometry(options):
    """Boot-only strip objects and original constructor; never a live control."""
    result = [_write(0x3ffc5d80+i*20,0x3ffc548c+i*48) for i in range(30)]
    result.append({"op":"call","address":0x400d6874,"arguments":[0x3ffc5d80]})
    if options["strip_order"] is not None:
        for logical,physical in enumerate(options["strip_order"]):
            result.extend([_write(0x3ffc5d80+600+logical*4,physical),
                           _write(0x3ffc5d80+physical*20+8,logical)])
    if options["strip_reverse"] is not None:
        for physical,reverse in enumerate(options["strip_reverse"]):
            result.append(_write(0x3ffc5d84+physical*20,int(reverse),1))
    return result


def _input_matches(actual, expected):
    if not isinstance(actual,dict): return False
    try:
        compatible_input({"input":expected},{"input":actual})
        return True
    except (LabError,TypeError,KeyError):
        return False


def build_profile(elf,*,rom=None,settings=None,trace=None,headless=None,limiter=None,hold_files=None,
                  timeout_s=900,state_encoding="sha256"):
    options=globals()["settings"](settings);program,sha=_verify_elf(elf)
    require(hold_files is None or (isinstance(hold_files,(list,tuple)) and all(isinstance(path,(str,Path)) and str(path) for path in hold_files)), "hold_files must be path strings")
    require(state_encoding in {"bytes","sha256"},"unsupported state encoding")
    require(type(timeout_s) in (int,float) and 10<=timeout_s<=86400,"invalid timeout")
    adc_mode = trace is None or _input_matches(trace.get("input"), ADC_INPUT)
    input_spec = ADC_INPUT if adc_mode else INPUT
    limitations = list(LIMITATIONS)
    if not adc_mode:
        limitations[4] = RENDERER_INPUT_LIMITATION
    initialization=[_write(0x3ffbe864,80)]+_controls(options)+_geometry(options)
    config={"elf_role":"elf","abi":{"kind":"xtensa-windowed","stack_pointer":STACK_START+STACK_SIZE,"return_sentinel":0x4fff0000},
        "heap":{"address":HEAP_START,"size":HEAP_SIZE},
        "memory_regions":[{"address":STACK_START,"size":STACK_SIZE},{"address":0x3ffc5260,"size":0x11020}],
        "hooks":[{"address":0x40092af0,"kind":"malloc"},{"address":0x40092afc,"kind":"realloc"},
                 {"address":0x40092b10,"kind":"free"},{"address":0x400ddbe0,"kind":"noop"},{"address":0x400d2fcc,"kind":"noop"},{"address":0x400f000c,"kind":"micros"},
                 {"address":0x400f0018,"kind":"millis"},{"address":0x401976f4,"kind":"f32_div"},
                 {"address":0x400ee974,"kind":"rng","mode":"bounded"},
                 {"address":0x4011c0f0,"kind":"guard_acquire"},{"address":0x4011c234,"kind":"guard_release"}],
        "initialization":initialization,"frame_calls":[{"op":"call","address":0x400d999c}],
        "input_writes":[{"channel":0,"address":0x3ffd0490,"width":1},{"channel":1,"address":0x3ffd048e,"width":1}],
        "outputs":[{"id":"leds","address":0x3ffc548c,"size":1440}],
        "state":[{"id":"scene-state","address":0x3ffc6530,"size":80}, {"id":"selector-state","address":0x3ffc53cc,"size":32}],
        "observations":[{"id":f"pack-{i}","address":a} for i,a in enumerate(SELECTORS)],
        "state_encoding":state_encoding,"instruction_limit":1000000,"output_limit":64*1024*1024,"max_frames":500,
        "settings_acknowledgements":copy.deepcopy(options),"hold_files":[str(Path(path).expanduser().absolute()) for path in (hold_files or [])],
        "timeout_s":float(timeout_s)*0.9}
    if adc_mode:
        config["observations"].append({"id":"audio-dsp","address":0x400ddbe0})
        config["hooks"] = [hook for hook in config["hooks"] if hook["address"] != 0x400ddbe0]
        config["hooks"].append({"address":0x400efcf0,"kind":"adc"})
        config.pop("input_writes")
        config["input_read_policy"] = "exoy-adc"
        config["state"].append({"id":"audio-state","address":0x3ffd0400,"size":256})
    else:
        config["input_read_policy"] = "exoy-renderer"
    assets=[{"role":"elf","format":"elf","path":str(program),"sha256":sha}]
    if rom is not None:
        path = Path(rom).expanduser().resolve(strict=True)
        info = inspect_image(path, "elf")
        require(info["sha256"] == ROM_SHA256, "only the identified ESP32 rev0 ROM ELF is supported")
        assets.append({"role":"rom","format":"elf","path":str(path),"sha256":info["sha256"]})
        config["binary_mappings"] = [{"role":"rom","address":a,"offset":o,"length":n} for a,o,n in ROM_SECTIONS]
    else:
        limitations.append("No ROM image supplied: scenes reaching original ESP32 ROM routines fail closed; supply the compatible ROM ELF for broader execution.")
    if headless is not None:config["headless"]=str(Path(headless).resolve(strict=True))
    if limiter is not None:
        path=Path(limiter).resolve(strict=True);assets.append({"role":"limiter","path":str(path),"sha256":file_digest(path)})
        config.update(launcher_role="limiter",post_launcher_hold_check=True,launcher_environment={"EMU_SLOTS":"1","EMU_CPUS":"1","EMU_MEM":"3072M","EMU_NO_LIMIT":"0"})
    if trace is not None:
        trace=validate_trace(trace);compatible_input({"input":input_spec},trace)
        if adc_mode:
            require(all(type(value) is int for frame in trace["frames"] for value in frame["values"]), "ADC samples must be integers")
        current=copy.deepcopy(options);recipes=[]
        for frame in trace["frames"]:
            controls=frame.get("controls",{})
            if controls:
                require(not set(controls) & {"strip_order","strip_reverse"}, "strip geometry controls are boot-only")
                updated=globals()["settings"]({**current,**controls})
                changed={key for key in controls if updated[key] != current[key]}
                recipes.append({"index":frame["index"],"controls":controls,"operations":_controls(updated,changed)})
                current=updated
        if recipes:config["frame_operations"]=recipes
    profile={"schema":"vfl.profile.v1","id":"exoy-one-v2-1","description":"Original scene dispatcher with declared runtime boundaries; see metadata limitations.",
        "input":copy.deepcopy(input_spec),"target":{"chip":"esp32","isa":"xtensa-lx6","abi":"xtensa-windowed"},
        "buses":[{"id":"leds","pixels":480,"order":"RGB","stage":"logical"}],"geometry":{"kind":"strips"},
        "settings":options,"firmware":assets,"backend":{"kind":"external","execution_kind":"original-firmware",
            "command":[sys.executable,"-m","vfl.ghidra","{request}","{capture}"],"timeout_s":timeout_s,
            "options":{"ghidra":config}},"metadata":{"device":"exoy-one","revision":"v2.1","limitations":limitations}}
    command = shutil.which("tycvl-ghidra")
    if command:
        profile["backend"]["command"] = [command, "{request}", "{capture}"]
    else:
        profile["backend"]["env"] = {"PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    return validate_profile(profile)


def coverage_plan():
    return [{"id": f"p{item['pack']}-e{item['effect']}", "effect": item,
             "settings": {"pack":item['pack'], "effect":item['effect'], "sound_reactive":True}}
            for item in effect_inventory()]


def smoke_trace(frames=4, *, frame_ms=20, seed=17):
    """Authored 64-read ADC packets; no measured acquisition cadence implied."""
    integer(frames, "frames", 1, 500); integer(frame_ms,"frame_ms",1,1000)
    return validate_trace({"schema":"vfl.trace.v1","input":copy.deepcopy(ADC_INPUT),
        "seed":seed,"clock_policy":"frame", "provenance":{"kind":"synthetic",
        "description":"Chronological ADC packets with declared frame timing; uncalibrated amplitude and acquisition timing"},
        "frames":[{"index":i,"time_us":i*frame_ms*1000,"values":[2048+((i*53+j*17)%600) for j in range(64)],"controls":{}}
                  for i in range(frames)]})

def _collect_coverage_case(profile, trace, commands, output, output_tags, state_tags, nonce, provenance):
    """Validate real protocol evidence; deliberately not a completed-run import."""
    from ..hsemu import capture_from_output
    from ..model import digest, experiment_digest, load_json, validate_capture
    execution = load_json(str(output) + ".execution.json", maximum_bytes=1024 * 1024)
    require(execution.get("schema") == "tycvl.ghidra-execution.v1"
            and execution.get("request_id") == nonce
            and execution.get("commands_sha256") == hashlib.sha256(commands.encode()).hexdigest(),
            "coverage execution binding differs")
    require(execution.get("uninitialized_policy") == "strict"
            and execution.get("read_enforcement") == "execute-read-fault"
            and execution.get("uninitialized_reads") == 0, "coverage requires strict defined-memory execution")
    require(execution.get("fused_float_policy") == "finite-nearest-even-no-status-flags", "coverage requires corrected fused-float semantics")
    integer(execution.get("fused_float_instructions"), "fused instruction count", 0)
    config = profile["backend"]["options"]["ghidra"]
    require(output.is_file() and not output.is_symlink()
            and output.stat().st_size <= config["output_limit"], "missing or oversized coverage output")
    capture = capture_from_output(profile, trace, commands, output.read_text(), output_tags,
        state_tag_map=state_tags, request_id=nonce, execution_kind="original-firmware", backend="ghidra-pcode",
        limitations=profile["metadata"]["limitations"] + [
            "Campaign cases have protocol/nonce/asset/source validation, not the outer runner's completed-run status envelope.",
            "Each case starts a fresh emulator and declared isolated scene state within a shared imported Ghidra Program."])
    engine = capture["manifest"].get("engine", {})
    require(engine.get("name") == "ghidra-pcode" and engine.get("abi") == "xtensa-windowed"
            and engine.get("version") == "12.0.4" and engine.get("language", "").startswith("Xtensa:"), "coverage engine identity differs")
    require(len(capture["events"]) == capture["manifest"]["completion"]["stubs"], "coverage instrumentation is incomplete")
    read_counts = {kind: 0 for kind in ("adc", "clock", "rng")}
    for event in capture["events"]:
        kind = event["kind"]
        if kind in read_counts: read_counts[kind] += 1
        if kind == "adc":
            require(event["frame"] >= 0, "ADC read before frame input")
            values = trace["frames"][event["frame"]]["values"]
            channel = integer(event.get("channel"), "ADC channel", 0, len(values)-1)
            require(event["value"] == values[channel], "observed ADC value differs from stimulus")
        if kind == "clock":
            require(event.get("units") in {"ms", "us"}, "unknown clock units")
            expected = event["time_us"] // 1000 if event["units"] == "ms" else event["time_us"]
            require(event["value"] == expected & 0xffffffff, "observed clock differs from frozen schedule")
    hooks = {hook["kind"] for hook in config["hooks"]}
    expected = {"adc_log": "adc" in hooks, "clock_log": bool(hooks & {"millis","micros"}), "rng_log": "rng" in hooks, "state": True}
    require(all(capture["manifest"]["capabilities"].get(key) == value for key,value in expected.items()), "coverage instrumentation capabilities differ")
    observers = {item["id"]: item["address"] for item in config["observations"]}
    for event in capture["events"]:
        if event.get("operation") == "observe-entry":
            require(event.get("value") == observers.get(event.get("observer_id")) and event.get("source") == "executed-instruction-observer", "unexpected observer event")
    expected_settings = copy.deepcopy(profile["settings"])
    for frame, input_frame in zip(capture["frames"], trace["frames"]):
        expected_settings.update(input_frame.get("controls", {}))
        selector = bytes.fromhex(frame["state"]["selector-state"])
        require(int.from_bytes(selector[12:16], "little") == expected_settings["pack"]
                and selector[16] == expected_settings["effect"], "captured scene selection differs from requested controls")
    device_inputs.record_input_evidence(profile, trace, capture)
    encoding = config["state_encoding"]
    if encoding == "sha256":
        for frame in capture["frames"]:
            frame["state"] = {tag: hashlib.sha256(bytes.fromhex(raw)).hexdigest() for tag, raw in frame["state"].items()}
    capture["manifest"].update(execution_scope="routine-diagnostic", request_id=nonce, input_sha256=digest(trace), profile_sha256=digest(profile),
        experiment_sha256=experiment_digest(profile, trace), state_encoding=encoding,
        adapter_provenance={**provenance, "execution_metadata": execution, "read_counts": read_counts,
                            "commands_sha256": hashlib.sha256(commands.encode()).hexdigest(), "output_sha256": file_digest(output),
                            "validation_scope": "campaign-protocol-and-assets; no completed-run envelope"})
    validate_capture(capture, profile, trace)
    return capture

def run_coverage(elf, rom, output_dir, *, case_ids=None, trace=None, frames=4, batch_size=8,
                 settings=None, progress=None, script_path=None, **profile_options):
    """Execute independent-reset original cases, with at most eight per JVM.

    The fresh external directory retains requests, exact executed commands, raw
    dumps, execution metadata and normalized captures. A failing case remains a
    failure; later cases are still examined. This campaign is protocol verified,
    not falsely presented as an outer-runner completed-run directory.
    """
    import os
    import json
    import secrets
    import shutil
    import time
    from .. import ghidra, hsemu, model
    from ..ghidra import _asset_paths, compile_commands
    from ..model import digest, experiment_digest, private_path, write_json
    from ..runner import run_process
    integer(batch_size, "batch_size", 1, 8)
    out = private_path(output_dir)
    require(not out.exists(), "coverage output directory must be new")
    cases = coverage_plan()
    if case_ids is not None:
        require(isinstance(case_ids, (list, tuple)) and len(case_ids) == len(set(case_ids)) and case_ids,
                "case_ids must be a nonempty list of unique coverage IDs")
        selected = {case["id"]: case for case in cases}
        require(all(name in selected for name in case_ids), "unknown coverage case ID")
        cases = [selected[name] for name in case_ids]
    trace = validate_trace(copy.deepcopy(trace) if trace is not None else smoke_trace(frames))
    require(any(_input_matches(trace["input"], spec) for spec in (INPUT, ADC_INPUT)), "Exoy coverage trace has unsupported input boundary")
    require(not any(frame.get("controls", {}).keys() & {"pack", "effect"} for frame in trace["frames"]), "coverage trace cannot override case pack or effect")
    # Preflight all cases before allocating the output directory or starting Java.
    compiled = []
    for case in cases:
        options = {**case["settings"], **(settings or {}),
                   "pack": case["settings"]["pack"], "effect": case["settings"]["effect"]}
        profile = build_profile(elf, rom=rom, settings=options, trace=trace, **profile_options)
        assets = _asset_paths(profile)
        commands, output_tags, state_tags = compile_commands(profile, trace, assets)
        compiled.append((case, profile, assets, commands, output_tags, state_tags))
    config = compiled[0][1]["backend"]["options"]["ghidra"]
    executable = config.get("headless") or os.environ.get("GHIDRA_HEADLESS") or shutil.which("ghidra-analyzeHeadless")
    require(isinstance(executable, str) and Path(executable).is_file(), "configure Ghidra headless")
    for path in config["hold_files"]:
        require(not os.path.lexists(path), "emulator HOLD is active")
    out.mkdir(parents=True)
    runtime = out / "runtime"; runtime.mkdir()
    script = (Path(script_path).expanduser().resolve(strict=True) if script_path is not None else
              Path(ghidra.__file__).with_name("ghidra") / "TycEmu.java")
    require(script.name == "TycEmu.java" and script.is_file(), "campaign script must be a declared TycEmu.java file")
    for source in (Path(__file__), Path(ghidra.__file__), Path(hsemu.__file__), Path(model.__file__), Path(device_inputs.__file__), script):
        shutil.copyfile(source, runtime / source.name)
    # The limiter can wait before acquiring its lock. Check HOLD again after
    # that wait, immediately before replacing this tiny process with Ghidra.
    guard = runtime / "launch_guard.py"
    guard.write_text("import json, os, sys\n"
                     "assert sys.argv[2] == '--'\n"
                     "if any(os.path.lexists(p) for p in json.loads(sys.argv[1])):\n"
                     "    raise SystemExit('emulator HOLD became active while waiting for the shared slot')\n"
                     "os.execvpe(sys.argv[3], sys.argv[3:], os.environ)\n")
    source_pins = {path.name: file_digest(path) for path in runtime.iterdir()}
    pinned_headless = file_digest(executable)
    summary = {"schema": "tycvl.device-coverage.v1", "device": "exoy-one", "revision": "v2.1",
               "status": "running", "validation_scope": "original execution with protocol/nonce/asset/source validation",
               "completed_run_envelope": False, "fidelity": "not-evaluated", "input_sha256": digest(trace), "frames_per_case": len(trace["frames"]),
               "runtime_sha256": source_pins, "cases": [], "limitations": compiled[0][1]["metadata"]["limitations"]}
    write_json(out / "campaign.json", summary)
    for group_start in range(0, len(compiled), batch_size):
        group = compiled[group_start:group_start + batch_size]
        batch = out / f"batch-{group_start // batch_size:03d}"; batch.mkdir()
        project = batch / "project"; project.mkdir()
        argv = [executable, str(project), "coverage", "-import", str(group[0][2]["elf"]["path"]),
                "-processor", "Xtensa:LE:32:default", "-noanalysis", "-deleteProject", "-scriptPath", str(runtime)]
        prepared = []
        for case, profile, assets, commands, output_tags, state_tags in group:
            directory = out / case["id"]; directory.mkdir()
            nonce = secrets.token_hex(16); command_path = directory / "commands.txt"; output_path = directory / "output.txt"
            command_path.write_text(commands)
            write_json(directory / "profile.json", profile); write_json(directory / "input.json", trace)
            write_json(directory / "request.json", {"schema": "vfl.request.v1", "request_id": nonce,
                "profile": profile, "trace": trace, "workdir": str(directory),
                "identities": {"input_sha256": digest(trace), "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}})
            argv.extend(["-postScript", script.name, str(command_path), str(output_path), nonce, "strict"])
            prepared.append((case, profile, assets, commands, output_tags, state_tags, directory, nonce))
        env = os.environ.copy(); env.update(config.get("launcher_environment", {}))
        properties = []
        for name in ("settings", "cache", "temp"):
            directory = batch / name; directory.mkdir(); properties.append(f'-Dapplication.{name}dir="{directory}"')
        env["JAVA_TOOL_OPTIONS"] = " ".join([env.get("JAVA_TOOL_OPTIONS", "")] + properties).strip()
        argv = [sys.executable, str(guard), json.dumps(config["hold_files"]), "--", *argv]
        if config.get("launcher_role"):
            argv.insert(0, str(group[0][2][config["launcher_role"]]["path"]))
        for path in config["hold_files"]:
            require(not os.path.lexists(path), "emulator HOLD became active before batch")
        # Recheck assets before every launch, and after completion before accepting results.
        require(all(assets == _asset_paths(profile) for _, profile, assets, *_ in group), "coverage asset changed")
        started = time.monotonic(); process_error = None
        try:
            run_process(argv, batch, batch / "stdout.log", batch / "stderr.log", config["timeout_s"], env,
                        output_limit=64 * 1024 * 1024, termination_grace_s=0.0)
        except (LabError, OSError) as error:
            if isinstance(error, LabError) and str(error).startswith("runner interrupted by "):
                summary.update(status="interrupted", interruption=str(error))
                write_json(out / "campaign.json", summary)
                raise
            process_error = str(error)
        except KeyboardInterrupt:
            summary.update(status="interrupted", interruption="KeyboardInterrupt")
            write_json(out / "campaign.json", summary)
            raise
        require(file_digest(executable) == pinned_headless and
                all(file_digest(runtime / name) == sha for name, sha in source_pins.items()), "pinned campaign runtime changed")
        require(all(assets == _asset_paths(profile) for _, profile, assets, *_ in group), "coverage asset changed during execution")
        elapsed = time.monotonic() - started
        for case, profile, assets, commands, output_tags, state_tags, directory, nonce in prepared:
            result = {"id": case["id"], "effect": case["effect"], "status": "failed", "fidelity": "not-evaluated", "batch_seconds": round(elapsed, 3)}
            if process_error: result["batch_error"] = process_error
            try:
                capture = _collect_coverage_case(profile, trace, commands, directory / "output.txt", output_tags, state_tags, nonce,
                    {"runtime_sha256": source_pins, "headless_sha256": pinned_headless,
                     "firmware_sha256": {name: value["sha256"] for name, value in assets.items()}})
                # A process timeout/error is never hidden behind a valid partial case.
                require(process_error is None, "batch process did not complete: " + str(process_error))
                write_json(directory / "capture.json", capture)
                rgb = ["".join(frame["buses"].values()) for frame in capture["frames"]]
                result.update(status="executed", frames=len(rgb), nonblack_frames=sum(any(bytes.fromhex(raw)) for raw in rgb),
                              distinct_frames=len(set(rgb)), events=len(capture["events"]),
                              read_counts=capture["manifest"]["adapter_provenance"]["read_counts"],
                              capture_sha256=file_digest(directory / "capture.json"),
                              capture=str(directory / "capture.json"))
                entries = [event["observer_id"] for event in capture["events"]
                           if event.get("operation") == "observe-entry" and event["frame"] >= 0]
                result["observed_entries"] = sorted(set(entries))
                result["selector_entry_count"] = sum(entry.startswith("pack-") for entry in entries)
                result["audio_dsp_entry_count"] = entries.count("audio-dsp")
                result["requested_pack_entry_observed"] = f"pack-{case['effect']['pack']}" in entries
                result["execution_completed"] = True
                if not result["requested_pack_entry_observed"]:
                    result.update(status="failed", failure_kind="entry-not-reached",
                                  error="Original execution completed, but the requested pack selector entry was not observed; use a longer or differently timed scenario")
            except (LabError, OSError, ValueError, KeyError, TypeError) as error:
                result["error"] = str(error)
                raw = directory / "output.txt"
                if raw.exists():
                    with raw.open("rb") as f:
                        f.seek(max(0, raw.stat().st_size-2048)); tail = f.read().decode("utf-8", errors="replace")
                    faults = [line for line in tail.splitlines() if line.startswith("X ")]
                    if faults: result["execution_error"] = faults[-1]
            summary["cases"].append(result)
            write_json(out / "campaign.json", summary)
            if progress is not None: progress(copy.deepcopy(result))
        # The optional shared limiter polls at two-second intervals. Yield after
        # every batch so a fresh process cannot repeatedly steal its next slot.
        time.sleep(3)
    executed = sum(case["status"] == "executed" for case in summary["cases"])
    summary.update(status="completed", executed=executed, passed=executed,
                   passed_semantics="Compatibility count of executed cases with observed requested pack selectors; fidelity is not evaluated",
                   failed=sum(case["status"] == "failed" for case in summary["cases"]))
    write_json(out / "campaign.json", summary)
    return summary
