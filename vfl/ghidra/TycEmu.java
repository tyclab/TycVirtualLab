// TycVirtualLab: a generic, bounded Xtensa call0 execution boundary.
// @category TycVirtualLab
// Usage: -postScript TycEmu.java COMMANDS OUTPUT REQUEST_NONCE strict|allow
// All addresses, memory contents, ABI setup and hooks come from COMMANDS.
// No device firmware, rendering algorithms or device address defaults live here.
//
// Commands (decimal or 0x integers; # starts a comment):
//   abi pc a1 a0 a2,a3,a4,a5,a6,a7 a2 <stack-address> <sentinel-address>
//   zero <address> <size> | wbytes <address> <even-hex>
//   w8|w16|w32 <address> <value> | reg <name> <u32>
//   hook <entry> millis|micros|adc|noop|guard_acquire|guard_release
//   hook <entry> rng [raw|bounded]
//   hook <entry> return <u32>
//   hook <entry> write <target-address> <width:1|2|4> <value>
//   seed <u32> (zero maps to one) | adc_policy strict|cycle
//   frame <index:-1-or-sequential> <time_us> [ADC values...]
//   time <milliseconds> (must agree exactly with the current frame clock)
//   limit <steps-per-call:1..10000000> | output_limit <bytes:1024..536870912>
//   call|callq <entry> [up to six u32 arguments] | dump <tag> <address> <size>
//
// Imported initialized blocks are copied; uninitialized blocks are NOT filled.
// Declare scratch/BSS with zero explicitly. Unknown instructions/userops fail.
// Synchronization userops are explicit no-ops in this single-threaded boundary;
// no interrupt, bus, peripheral or multi-core timing semantics are asserted.
// Boundary stubs emit one event each; only a sentinel return completes a call.

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class TycEmu extends GhidraScript {
    static final long U32 = 0xffffffffL;
    static final int MAX_TRANSFER = 16 * 1024 * 1024;
    static final long MAX_INITIALIZED = 256L * 1024 * 1024;
    static final long MAX_COMMAND_BYTES = 64L * 1024 * 1024;
    static final long MAX_STEPS = 10_000_000L;
    static final long MAX_EVENTS = 1_000_000L;
    static final long MAX_OUTPUT = 512L * 1024 * 1024;
    static final Set<String> WINDOWED = Set.of(
        "call4", "call8", "call12", "callx4", "callx8", "callx12",
        "entry", "retw", "retw.n", "rotw", "movsp", "rfwo", "rfwu");

    public static class BoundaryOps extends AnnotatedPcodeUseropLibrary<byte[]> {
        @PcodeUserop public void memw() {}
        @PcodeUserop public void isync() {}
        @PcodeUserop public void extw() {}
        @PcodeUserop public void dsync() {}
        @PcodeUserop public void esync() {}
        @PcodeUserop public void rsync() {}
    }

    static class Hook {
        String kind;
        boolean bounded;
        long value, target;
        int width;
        Hook(String kind) { this.kind = kind; }
    }

    PcodeEmulator emu;
    PcodeThread<byte[]> thread;
    PcodeArithmetic<byte[]> arithmetic;
    Language language;
    AddressSpace ram;
    PrintWriter output;
    final Gson json = new Gson();
    final Map<Long, Hook> hooks = new HashMap<>();
    final List<long[]> importedRanges = new ArrayList<>();
    long initializedBytes, outputBytes;
    long outputLimit = 64L * 1024 * 1024;
    long stepLimit = 1_000_000, steps, maxSteps, stubHits;
    long frameIndex = -1, timeUs, rng = 1, adcPosition;
    long[] adc = new long[0];
    String adcPolicy = "strict";
    String pcRegister, stackRegister, returnRegister, resultRegister;
    String[] argumentRegisters;
    long stackAddress, sentinel;
    boolean abiReady, sawFrame, seedReady;
    boolean allowUninitialized = false;
    long uninitializedReadCount = 0;
    final Set<String> uninitializedReadRegions = new LinkedHashSet<>();
    boolean uninitializedRegionsTruncated = false;

    void recordUninitializedRead(AddressSetView ranges) {
        uninitializedReadCount++;
        String detail = ranges.toString();
        if (detail.length() > 512) detail = detail.substring(0, 512) + "...";
        if (uninitializedReadRegions.size() < 256) uninitializedReadRegions.add(detail);
        else if (!uninitializedReadRegions.contains(detail)) uninitializedRegionsTruncated = true;
        if (!allowUninitialized) throw new AccessPcodeExecutionException("Uninitialized emulation read: " + detail);
    }

    class GuardedStatePiece extends BytesPcodeExecutorStatePiece {
        GuardedStatePiece(Language language, PcodeStateCallbacks callbacks) {
            super(language, callbacks);
        }

        @Override protected BytesPcodeExecutorStateSpace getForSpace(AddressSpace space, boolean toWrite) {
            // First reads must visit the same checked space as later reads;
            // the base null-space path otherwise supplies zero without warning.
            return super.getForSpace(space, true);
        }

        @Override protected BytesPcodeExecutorStateSpace newSpace(AddressSpace space) {
            return new BytesPcodeExecutorStateSpace(language, space, this) {
                @Override protected void warnUninit(AddressSetView ranges) {
                    // Ghidra 12.0.4 calls this only for EXECUTE_READ. Decoder
                    // lookahead and initial register RE_INIT keep their normal
                    // semantics; missing instruction bytes still fail decode.
                    recordUninitializedRead(ranges);
                }
            };
        }
    }

    static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }

    static long number(String value, long maximum) {
        require(value.length() <= 20 && value.matches("(?:0[xX][0-9a-fA-F]+|[0-9]+)"), "invalid unsigned integer");
        long result;
        try {
            result = value.startsWith("0x") || value.startsWith("0X")
                ? Long.parseLong(value.substring(2), 16) : Long.parseLong(value);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("integer exceeds supported range");
        }
        require(result <= maximum, "integer exceeds supported range");
        return result;
    }

    static long u32(String value) { return number(value, U32); }
    static void arity(String[] words, int count) { require(words.length == count, "wrong command argument count"); }
    static String hex(long value) { return "0x" + Long.toHexString(value); }

    void range(long address, long size) {
        require(address >= 0 && address <= U32 && size > 0 && size <= U32 + 1 - address,
            "invalid or wrapping memory range");
    }

    Address address(long value) { return ram.getAddress(value); }

    Register register(String name) {
        require(name.matches("[A-Za-z][A-Za-z0-9_]*"), "invalid register name");
        Register register = language.getRegister(name);
        require(register != null && register.getBitLength() == 32, "unknown or non-32-bit register");
        return register;
    }

    long readRegister(String name) {
        return arithmetic.toLong(thread.getState().getVar(register(name),
            PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & U32;
    }

    void writeRegister(String name, long value) {
        thread.getState().setVar(register(name), arithmetic.fromConst(value, 4));
    }

    byte[] read(long start, int size) {
        range(start, size);
        // Treat dumps and hook reads as real reads too: INSPECT would silently
        // supply zero for an uninitialized byte, hiding a missing declaration.
        return emu.getSharedState().getVar(address(start), size, false,
            PcodeExecutorStatePiece.Reason.EXECUTE_READ);
    }

    void write(long start, byte[] bytes) {
        range(start, bytes.length);
        initializedBytes += bytes.length;
        require(initializedBytes <= MAX_INITIALIZED, "memory initialization budget exceeded");
        emu.getSharedState().setConcrete(address(start), bytes);
    }

    void writeValue(long start, long value, int width) {
        range(start, width);
        byte[] bytes = new byte[width];
        for (int index = 0; index < width; index++) {
            int shift = language.isBigEndian() ? 8 * (width - index - 1) : 8 * index;
            bytes[index] = (byte) (value >>> shift);
        }
        // Runtime hook writes do not consume the setup allocation budget.
        emu.getSharedState().setConcrete(address(start), bytes);
    }

    void emit(String line) {
        long size = line.getBytes(StandardCharsets.UTF_8).length + 1L;
        require(size <= outputLimit - outputBytes, "protocol output limit exceeded");
        output.println(line);
        outputBytes += size;
        require(!output.checkError(), "protocol output write failed");
    }

    long nextRandom() {
        long value = rng;
        value ^= (value << 13) & U32;
        value ^= value >>> 17;
        value ^= (value << 5) & U32;
        rng = value & U32;
        return rng;
    }

    boolean handleHook(long pc) {
        Hook hook = hooks.get(pc);
        if (hook == null) return false;
        require(stubHits < MAX_EVENTS, "boundary event limit exceeded");
        long caller = readRegister(returnRegister);
        long argument = readRegister(argumentRegisters[0]);
        long rngBefore = rng, adcBefore = adcPosition;
        switch (hook.kind) {
            case "millis": writeRegister(resultRegister, (timeUs / 1000) & U32); break;
            case "micros": writeRegister(resultRegister, timeUs & U32); break;
            case "adc":
                require(sawFrame && adc.length > 0, "ADC hook reached without a declared input queue");
                require(adcPolicy.equals("cycle") || adcPosition < adc.length, "ADC input queue exhausted");
                writeRegister(resultRegister, adc[(int) (adcPosition++ % adc.length)]);
                break;
            case "rng":
                require(seedReady, "RNG hook reached without an explicit seed");
                writeRegister(resultRegister, hook.bounded
                    ? (argument == 0 ? 0 : nextRandom() % argument) : nextRandom());
                break;
            case "return": writeRegister(resultRegister, hook.value); break;
            case "write": writeValue(hook.target, hook.value, hook.width); break;
            case "guard_acquire": writeRegister(resultRegister, read(argument, 1)[0] == 0 ? 1 : 0); break;
            case "guard_release": writeValue(argument, 1, 1); break;
            case "noop": break;
            default: throw new IllegalStateException("unsupported hook");
        }
        String kind = hook.kind.equals("adc") ? "adc" : hook.kind.equals("rng") ? "rng"
            : hook.kind.equals("millis") || hook.kind.equals("micros") ? "clock" : "stub";
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("sequence", stubHits);
        event.put("kind", kind);
        event.put("frame", frameIndex);
        event.put("phase", frameIndex < 0 ? "initialization" : "frame");
        event.put("time_us", timeUs);
        event.put("call_site", "return-address:" + hex(caller));
        event.put("return_address", hex(caller));
        event.put("entrypoint", hex(pc));
        event.put("operation", hook.kind);
        event.put("argument_a2", argument);
        event.put("value", readRegister(resultRegister));
        event.put("value_register", resultRegister);
        if (kind.equals("adc")) {
            event.put("source", "scheduled-adc-queue");
            event.put("queue_length", adc.length);
            event.put("policy", adcPolicy);
            event.put("read_index", adcBefore);
            event.put("channel", adcBefore % adc.length);
        } else if (kind.equals("clock")) {
            event.put("source", "frozen-frame-clock");
            event.put("units", hook.kind.equals("millis") ? "ms" : "us");
        } else if (kind.equals("rng")) {
            event.put("source", "xorshift32-boundary-substitute");
            event.put("mode", hook.bounded ? "bounded" : "raw");
            if (hook.bounded) event.put("bound", argument);
            event.put("state_before", rngBefore);
            event.put("state_after", rng);
        } else {
            event.put("source", "boundary-stub");
            if (hook.kind.equals("write")) {
                event.put("write_address", hex(hook.target));
                event.put("write_width", hook.width);
                event.put("write_value", hook.value);
            }
        }
        emit("E event " + json.toJson(event));
        stubHits++;
        thread.overrideCounter(address(caller));
        return true;
    }

    void call(long entry, long[] arguments, boolean printResult) {
        require(abiReady, "call requires an explicit ABI");
        require(entry != sentinel, "call entry cannot be the return sentinel");
        for (int index = 0; index < arguments.length; index++) writeRegister(argumentRegisters[index], arguments[index]);
        writeRegister(returnRegister, sentinel);
        writeRegister(stackRegister, stackAddress);
        thread.overrideCounter(address(entry));
        thread.overrideContextWithDefault();
        steps = 0;
        // P-code breakpoints are not visited before the first instruction of a
        // newly entered call. A configured entry hook must still replace that
        // boundary, just as it does when reached by an instruction-level call.
        if (hooks.containsKey(entry)) {
            require(handleHook(entry), "configured entry hook was not handled");
            if (printResult) emit("R " + Long.toHexString(readRegister(resultRegister))
                + " " + Long.toHexString(readRegister(argumentRegisters[1])));
            return;
        }
        while (true) {
            try {
                thread.run();
                throw new IllegalStateException("emulator returned without sentinel breakpoint");
            } catch (InterruptPcodeExecutionException error) {
                long pc = thread.getCounter().getOffset();
                if (pc == sentinel) break;
                require(handleHook(pc), "unexpected breakpoint at " + hex(pc));
                // A tail jump into a hook preserves the harness return address.
                // Do not attempt to decode the sentinel after that hook returns.
                if (thread.getCounter().getOffset() == sentinel) break;
            }
        }
        maxSteps = Math.max(maxSteps, steps);
        if (printResult) emit("R " + Long.toHexString(readRegister(resultRegister))
            + " " + Long.toHexString(readRegister(argumentRegisters[1])));
    }

    void configureAbi(String[] words) {
        arity(words, 8);
        require(!abiReady, "ABI may only be declared once");
        require(words[1].equalsIgnoreCase("pc") && words[2].equalsIgnoreCase("a1")
            && words[3].equalsIgnoreCase("a0") && words[4].equalsIgnoreCase("a2,a3,a4,a5,a6,a7")
            && words[5].equalsIgnoreCase("a2"), "only the Xtensa call0 register ABI is supported");
        pcRegister = words[1]; stackRegister = words[2]; returnRegister = words[3];
        argumentRegisters = words[4].split(","); resultRegister = words[5];
        require(register(pcRegister).equals(language.getProgramCounter()), "ABI PC does not match language PC");
        register(stackRegister); register(returnRegister); register(resultRegister);
        for (String name : argumentRegisters) register(name);
        stackAddress = u32(words[6]); sentinel = u32(words[7]);
        require(stackAddress % 16 == 0, "call0 stack must be 16-byte aligned");
        require(!hooks.containsKey(sentinel), "return sentinel conflicts with a hook");
        emu.addBreakpoint(address(sentinel), "1:1");
        abiReady = true;
    }

    void configureHook(String[] words) {
        require(words.length >= 3, "hook requires an address and kind");
        long entry = u32(words[1]);
        require(!hooks.containsKey(entry) && (!abiReady || entry != sentinel), "duplicate hook or sentinel conflict");
        Hook hook = new Hook(words[2]);
        switch (hook.kind) {
            case "millis": case "micros": case "adc": case "noop": case "guard_acquire": case "guard_release":
                arity(words, 3); break;
            case "rng":
                require(words.length == 3 || words.length == 4, "rng hook expects an optional mode");
                if (words.length == 4) {
                    require(words[3].equals("raw") || words[3].equals("bounded"), "unsupported RNG mode");
                    hook.bounded = words[3].equals("bounded");
                }
                break;
            case "return": arity(words, 4); hook.value = u32(words[3]); break;
            case "write":
                arity(words, 6); hook.target = u32(words[3]); hook.width = (int) number(words[4], 4);
                require(hook.width == 1 || hook.width == 2 || hook.width == 4, "write hook width must be 1, 2 or 4");
                hook.value = number(words[5], hook.width == 4 ? U32 : (1L << (8 * hook.width)) - 1);
                range(hook.target, hook.width);
                break;
            default: throw new IllegalArgumentException("unknown hook kind");
        }
        hooks.put(entry, hook);
        emu.addBreakpoint(address(entry), "1:1");
    }

    void command(String[] words) {
        switch (words[0]) {
            case "abi": configureAbi(words); break;
            case "hook": configureHook(words); break;
            case "seed":
                arity(words, 2); rng = u32(words[1]); if (rng == 0) rng = 1; seedReady = true; break;
            case "adc_policy":
                arity(words, 2); require(words[1].equals("strict") || words[1].equals("cycle"), "unknown ADC policy");
                adcPolicy = words[1]; break;
            case "frame": {
                require(words.length >= 3 && words.length <= 4099, "invalid frame input count");
                long index = words[1].equals("-1") ? -1 : number(words[1], Integer.MAX_VALUE);
                require(index == frameIndex + 1 || (!sawFrame && index == -1), "frame indices must be sequential from zero, optionally preceded by -1");
                long nextTime = number(words[2], U32 * 1000);
                require(nextTime >= timeUs && (index <= 0 || nextTime > timeUs), "frame clock must increase");
                frameIndex = index; timeUs = nextTime; sawFrame = true; adcPosition = 0;
                adc = new long[words.length - 3];
                for (int indexValue = 3; indexValue < words.length; indexValue++) adc[indexValue - 3] = u32(words[indexValue]);
                break;
            }
            case "time":
                arity(words, 2); require(sawFrame && u32(words[1]) * 1000 == timeUs, "time must agree exactly with the frame clock"); break;
            case "reg": {
                arity(words, 3); long value = u32(words[2]);
                String name = words[1].toLowerCase(Locale.ROOT);
                require(!name.contains("window") && (!name.equals("ps") || value == 0), "windowed register state is unsupported");
                writeRegister(words[1], value); break;
            }
            case "zero": {
                arity(words, 3); int size = (int) number(words[2], MAX_TRANSFER);
                require(size > 0, "zero region must be nonempty");
                long start = u32(words[1]); range(start, size);
                for (long[] imported : importedRanges) {
                    require(start + size <= imported[0] || start >= imported[1],
                        "zero region overlaps initialized ELF memory; use an explicitly acknowledged byte-write recipe");
                }
                write(start, new byte[size]); break;
            }
            case "wbytes": {
                arity(words, 3); String text = words[2];
                require(text.length() > 0 && text.length() % 2 == 0 && text.length() <= MAX_TRANSFER * 2
                    && text.matches("[0-9a-fA-F]+"), "invalid hex byte sequence");
                byte[] bytes = new byte[text.length() / 2];
                for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) Integer.parseInt(text.substring(index * 2, index * 2 + 2), 16);
                write(u32(words[1]), bytes); break;
            }
            case "w8": case "w16": case "w32": {
                arity(words, 3); int width = Integer.parseInt(words[0].substring(1)) / 8;
                long value = number(words[2], width == 4 ? U32 : (1L << (width * 8)) - 1);
                writeValue(u32(words[1]), value, width); break;
            }
            case "limit":
                arity(words, 2); stepLimit = number(words[1], MAX_STEPS); require(stepLimit > 0, "step limit must be positive"); break;
            case "output_limit":
                arity(words, 2); outputLimit = number(words[1], MAX_OUTPUT);
                require(outputLimit >= 1024 && outputLimit >= outputBytes, "invalid output limit"); break;
            case "call": case "callq": {
                require(words.length >= 2 && words.length <= 8, "call supports at most six arguments");
                long[] arguments = new long[words.length - 2];
                for (int index = 2; index < words.length; index++) arguments[index - 2] = u32(words[index]);
                call(u32(words[1]), arguments, words[0].equals("call")); break;
            }
            case "dump": {
                arity(words, 4); require(words[1].matches("[A-Za-z0-9_.-]{1,96}"), "invalid dump tag");
                int size = (int) number(words[3], MAX_TRANSFER); require(size > 0, "dump must be nonempty");
                require(size * 2L + words[1].length() + 4 <= outputLimit - outputBytes, "dump would exceed output limit");
                byte[] bytes = read(u32(words[2]), size);
                StringBuilder line = new StringBuilder("D " + words[1] + " ");
                char[] digits = "0123456789abcdef".toCharArray();
                for (byte value : bytes) { line.append(digits[(value & 255) >>> 4]); line.append(digits[value & 15]); }
                emit(line.toString()); break;
            }
            default: throw new IllegalArgumentException("unknown command");
        }
    }

    void initialize() throws Exception {
        require(currentProgram != null, "a program must be imported first");
        language = currentProgram.getLanguage();
        require(language.getLanguageID().getIdAsString().startsWith("Xtensa:"), "only Xtensa languages are supported");
        require(!currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase(Locale.ROOT).contains("window"), "windowed compiler ABI is unsupported");
        ram = language.getAddressFactory().getDefaultAddressSpace();
        require(ram.getSize() == 32 && ram.getAddressableUnitSize() == 1, "only byte-addressed 32-bit memory is supported");
        emu = new PcodeEmulator(language) {
            @Override protected PcodeExecutorState<byte[]> createSharedState() {
                return new DefaultPcodeExecutorState<>(new GuardedStatePiece(language, cb.wrapFor(null)));
            }
            @Override protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
                return new DefaultPcodeExecutorState<>(new GuardedStatePiece(language, cb.wrapFor(thread)));
            }
            @Override protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
                return super.createUseropLibrary().compose(new BoundaryOps());
            }
            @Override protected BytesPcodeThread createThread(String name) {
                return new BytesPcodeThread(name, this) {
                    @Override public void stepInstruction() {
                        require(!monitor.isCancelled(), "execution cancelled");
                        require(++steps <= stepLimit, "per-call instruction/step limit exceeded");
                        super.stepInstruction();
                    }
                    @Override protected void preExecuteInstruction() {
                        String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
                        String display = instruction.toString().toLowerCase(Locale.ROOT);
                        require(!WINDOWED.contains(mnemonic) && !display.contains("windowbase") && !display.contains("windowstart"),
                            "windowed instruction unsupported at " + instruction.getAddress());
                        super.preExecuteInstruction();
                    }
                };
            }
        };
        arithmetic = emu.getArithmetic();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            AddressSpace sourceSpace = block.getStart().getAddressSpace();
            // ELF loader metadata in OTHER space is not guest memory.
            if (!sourceSpace.isLoadedMemorySpace()) continue;
            require(!sourceSpace.isOverlaySpace() && sourceSpace.getName().equals(ram.getName())
                && sourceSpace.getSize() == ram.getSize() && sourceSpace.getAddressableUnitSize() == 1,
                "unsupported imported memory block " + block.getName() + " in space " + sourceSpace.getName());
            require(block.getSize() > 0 && block.getSize() <= MAX_INITIALIZED - initializedBytes, "imported memory budget exceeded");
            byte[] bytes = new byte[(int) block.getSize()];
            require(block.getBytes(block.getStart(), bytes) == bytes.length, "incomplete imported memory block");
            write(block.getStart().getOffset(), bytes);
            importedRanges.add(new long[] {block.getStart().getOffset(), block.getStart().getOffset() + bytes.length});
        }
        thread = emu.newThread();
        for (int index = 0; index < 16; index++) writeRegister("a" + index, 0);
        writeRegister("PS", 0);
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 4 && args[2].matches("[0-9a-f]{32}")
            && (args[3].equals("strict") || args[3].equals("allow")),
            "expected command-file, fresh output-file, request nonce and uninitialized-read policy");
        allowUninitialized = args[3].equals("allow");
        Path commands = Paths.get(args[0]);
        require(Files.isRegularFile(commands) && Files.size(commands) <= MAX_COMMAND_BYTES, "invalid or oversized command file");
        byte[] commandBytes = Files.readAllBytes(commands);
        require(commandBytes.length <= MAX_COMMAND_BYTES, "command file grew past limit");
        String commandHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(commandBytes));
        Set<String> declaredHooks = new HashSet<>();
        for (String line : new String(commandBytes, StandardCharsets.UTF_8).split("\\R")) {
            String[] words = line.split("#", 2)[0].trim().split("\\s+");
            if (words.length >= 3 && words[0].equals("hook")) declaredHooks.add(words[2]);
        }
        Path executionPath = Paths.get(args[1] + ".execution.json");
        require(!Files.exists(executionPath), "execution metadata already exists");
        long started = System.nanoTime();
        int lineNumber = 0;
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(args[1]), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
            output = writer;
            try {
                emit("E binding " + json.toJson(Map.of("schema", "tycvl.execution-binding.v1",
                    "request_id", args[2], "commands_sha256", commandHash)));
                initialize();
                emit("E instrumentation " + json.toJson(Map.of("schema", "vfl.boundary-log.v1",
                    "adc_log", declaredHooks.contains("adc"),
                    "clock_log", declaredHooks.contains("millis") || declaredHooks.contains("micros"),
                    "rng_log", declaredHooks.contains("rng"),
                    "engine", Map.of("name", "ghidra-pcode", "version", Application.getApplicationVersion(),
                        "language", language.getLanguageID().getIdAsString(), "abi", "xtensa-call0"))));
                try (BufferedReader reader = new BufferedReader(new StringReader(new String(commandBytes, StandardCharsets.UTF_8)))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        require(++lineNumber <= 1_000_000, "command count limit exceeded");
                        int comment = line.indexOf('#');
                        if (comment >= 0) line = line.substring(0, comment);
                        line = line.trim();
                        if (!line.isEmpty()) command(line.split("\\s+"));
                    }
                }
                require(abiReady, "missing ABI declaration");
                Map<String, Object> execution = new LinkedHashMap<>();
                execution.put("schema", "tycvl.ghidra-execution.v1");
                execution.put("request_id", args[2]);
                execution.put("commands_sha256", commandHash);
                execution.put("read_enforcement", "execute-read-fault");
                execution.put("uninitialized_policy", args[3]);
                execution.put("uninitialized_reads", uninitializedReadCount);
                execution.put("uninitialized_regions", uninitializedReadRegions);
                execution.put("uninitialized_regions_truncated", uninitializedRegionsTruncated);
                try (Writer metadata = Files.newBufferedWriter(executionPath, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                    json.toJson(execution, metadata);
                }
                emit("E done stubs=" + stubHits + " ms=" + ((System.nanoTime() - started) / 1_000_000)
                    + " maxsteps=" + maxSteps);
            } catch (Exception error) {
                // Do not echo command text or payloads. A bounded failure marker
                // is attempted; missing completion also makes a truncated run fail.
                String message = String.valueOf(error.getMessage()).replaceAll("[\\r\\n]", " ");
                if (message.length() > 300) message = message.substring(0, 300);
                String failure = "X line " + lineNumber + ": " + error.getClass().getSimpleName() + " " + message;
                if (outputBytes + failure.getBytes(StandardCharsets.UTF_8).length + 1 <= outputLimit) output.println(failure);
                output.flush();
                throw error;
            }
        }
    }
}
