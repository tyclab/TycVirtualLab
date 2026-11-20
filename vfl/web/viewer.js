"use strict";

function executionScope(manifest) {
  if (manifest.backend === "ghidra-pcode") return "routine-diagnostic";
  if (manifest.backend === "qemu-esp32-board") return "board-diagnostic";
  if (manifest.backend === "glorb-host-v1") return "host-renderer";
  return ["synthetic", "replay"].includes(manifest.execution_kind) ? manifest.execution_kind : "unspecified";
}

function validateCapture(value) {
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const integer = (v) => Number.isSafeInteger(v) && v >= 0;
  const fail = (message) => { throw new Error(message); };
  if (!object(value) || value.schema !== "vfl.capture.v1") fail("Expected a vfl.capture.v1 JSON capture.");
  if (!object(value.manifest)) fail("The capture has no run manifest.");
  for (const key of ["profile_id", "execution_kind", "backend"]) {
    if (typeof value.manifest[key] !== "string" || !value.manifest[key]) fail(`Manifest ${key} must be a nonempty string.`);
  }
  if (value.manifest.execution_scope !== undefined && value.manifest.execution_scope !== executionScope(value.manifest)) fail("Execution scope differs from backend.");
  if (!Array.isArray(value.manifest.limitations) || value.manifest.limitations.some((v) => typeof v !== "string")) fail("Manifest limitations must be an array of strings.");
  if (!["synthetic", "original-firmware", "recovered-code", "replay"].includes(value.manifest.execution_kind)) fail("Unsupported execution kind.");
  if (!object(value.manifest.capabilities) || ["adc_log", "clock_log", "rng_log", "state"].some((key) => typeof value.manifest.capabilities[key] !== "boolean")) fail("Manifest capabilities must explicitly declare ADC, clock, RNG and state booleans.");
  if (!Array.isArray(value.buses) || !value.buses.length || value.buses.length > 64) fail("One to 64 output buses are required.");
  const buses = new Map();
  let totalPixels = 0;
  for (const bus of value.buses) {
    if (!object(bus) || typeof bus.id !== "string" || !bus.id || buses.has(bus.id)) fail("Bus IDs must be nonempty and unique.");
    if (!integer(bus.pixels) || bus.pixels < 1 || bus.pixels > 65536) fail(`Invalid pixel count for bus ${bus.id}.`);
    totalPixels += bus.pixels;
    if (totalPixels > 65536) fail("Capture exceeds the total pixel limit.");
    if (typeof bus.order !== "string" || !/^(RGB|RBG|GRB|GBR|BRG|BGR)$/.test(bus.order)) fail(`Unsupported byte order for bus ${bus.id}; expected an RGB permutation.`);
    if (bus.stage !== undefined && !["logical", "driver"].includes(bus.stage)) fail(`Unknown stage for bus ${bus.id}.`);
    buses.set(bus.id, bus);
  }
  if (!Array.isArray(value.frames) || !value.frames.length || value.frames.length > 100000) fail("Capture must contain one to 100000 frames.");
  let previous = -1;
  for (let index = 0; index < value.frames.length; index++) {
    const frame = value.frames[index];
    if (!object(frame) || frame.index !== index || !integer(frame.time_us) || frame.time_us <= previous) fail(`Frame ${index} has an invalid index or timestamp.`);
    if (!object(frame.buses) || Object.keys(frame.buses).length !== buses.size) fail(`Frame ${index} has the wrong bus set.`);
    for (const [id, bus] of buses) {
      const bytes = frame.buses[id];
      if (!Object.hasOwn(frame.buses, id) || typeof bytes !== "string" || bytes.length !== bus.pixels * 6 || !/^[0-9a-fA-F]+$/.test(bytes)) fail(`Frame ${index}, bus ${id}: expected ${bus.pixels * 3} hexadecimal bytes.`);
    }
    previous = frame.time_us;
  }
  const geometry = value.geometry ?? {kind: "strips"};
  if (!object(geometry)) fail("Geometry must be an object.");
  if (!["strips", "points"].includes(geometry.kind ?? "strips")) fail("Unsupported geometry kind.");
  if (geometry.points !== undefined) {
    if (!Array.isArray(geometry.points) || geometry.points.length > 65536) fail("Geometry points must be a bounded array.");
    const seen = new Set();
    for (const point of geometry.points) {
      if (!object(point) || !buses.has(point.bus) || !integer(point.index) || point.index >= buses.get(point.bus).pixels) fail("A geometry point references an unknown pixel.");
      const key = JSON.stringify([point.bus, point.index]);
      if (seen.has(key)) fail("A pixel has duplicate geometry points.");
      seen.add(key);
      if (![point.x, point.y, point.z].every((v) => typeof v === "number" && Number.isFinite(v))) fail("Geometry point coordinates must be finite numbers.");
    }
  }
  if (geometry.mask !== undefined) {
    if (!object(geometry.mask)) fail("Geometry mask must be a bus-to-boolean-array mapping.");
    for (const [id, mask] of Object.entries(geometry.mask)) {
      if (!buses.has(id) || !Array.isArray(mask) || mask.length !== buses.get(id).pixels || mask.some((v) => typeof v !== "boolean")) fail(`Invalid display mask for bus ${id}.`);
    }
  }
  if (!Array.isArray(value.events)) fail("Recorded events must be an array.");
  return value;
}

function maskedNonzeroCount(capture, frame) {
  let count = 0;
  for (const [bus, mask] of Object.entries(capture.geometry?.mask ?? {})) {
    for (let index = 0; index < mask.length; index++) {
      if (mask[index] === false && frame.buses[bus].slice(index * 6, index * 6 + 6) !== "000000") count++;
    }
  }
  return count;
}

function decodePixel(hex, order, index) {
  const channels = [0, 1, 2].map((offset) => parseInt(hex.slice(index * 6 + offset * 2, index * 6 + offset * 2 + 2), 16));
  return ["R", "G", "B"].map((channel) => channels[order.indexOf(channel)]);
}

function frameAtTime(frames, timeUs) {
  let low = 0, high = frames.length - 1;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (frames[middle].time_us <= timeUs) low = middle;
    else high = middle - 1;
  }
  return low;
}

if (typeof module !== "undefined" && module.exports) module.exports = {validateCapture, decodePixel, frameAtTime, maskedNonzeroCount};

if (typeof document !== "undefined") (() => {
  const byId = (id) => document.getElementById(id);
  const canvas = byId("canvas"), ctx = canvas.getContext("2d");
  let capture = null, current = 0, playing = false, anchor = 0, anchorUs = 0, animation = null;
  let selected = null, hitTargets = [], width = 1000, height = 450, loadSerial = 0;
  const text = (id, value) => { byId(id).textContent = value; };
  const rgbCSS = (rgb) => `rgb(${rgb.join(",")})`;
  const masked = (bus, index) => capture.geometry?.mask?.[bus]?.[index] === false;

  function pause() {
    playing = false;
    if (animation !== null) cancelAnimationFrame(animation);
    animation = null;
    text("play", "Play");
  }

  function reset() {
    pause(); capture = null; current = 0; selected = null;
    for (const id of ["previous", "play", "next", "timeline"]) byId(id).disabled = true;
    byId("timeline").max = "0"; byId("timeline").value = "0";
    byId("view").value = "strips"; byId("view").options[1].disabled = true;
    byId("yaw-label").hidden = true; byId("pitch-label").hidden = true;
    text("profile", "No capture loaded"); text("execution", "—"); text("backend", "—"); text("count", "0");
    text("position", "Frame — · — ms"); text("pixel", "Click a pixel in the preview.");
    byId("swatch").style.backgroundColor = "#000";
    byId("capabilities").replaceChildren(); byId("limits").replaceChildren();
    for (const id of ["manifest-detail", "frame-detail", "events-detail"]) text(id, "No capture loaded.");
    text("geometry-note", ""); text("canvas-note", "Open a vfl.capture.v1 file, or export a run as HTML.");
    draw();
  }

  function showError(error) {
    reset();
    text("error", `Could not load capture: ${error.message || String(error)}`);
    byId("error").hidden = false;
  }

  function load(value) {
    validateCapture(value);
    reset(); capture = value;
    byId("error").hidden = true;
    const manifest = capture.manifest;
    text("profile", manifest.profile_id); text("execution", executionScope(manifest) === manifest.execution_kind ? manifest.execution_kind : `${executionScope(manifest)} (${manifest.execution_kind})`); text("backend", manifest.backend);
    text("count", String(capture.frames.length));
    for (const limit of manifest.limitations.length ? manifest.limitations : ["No limitations declared by this capture."]) {
      const item = document.createElement("li"); item.textContent = limit; byId("limits").append(item);
    }
    for (const [name, available] of Object.entries(manifest.capabilities)) {
      const term = document.createElement("dt"), definition = document.createElement("dd");
      term.textContent = name; definition.textContent = available ? "Recorded" : "Unavailable";
      byId("capabilities").append(term, definition);
    }
    const maskNote = capture.geometry?.mask ? " Display masks control visibility only; read/write behavior belongs to the execution backend." : "";
    text("geometry-note", String(capture.geometry?.description ?? "Geometry has no calibration declaration.") + maskNote);
    const hasPoints = Boolean(capture.geometry?.points?.length);
    byId("view").options[1].disabled = !hasPoints;
    text("manifest-detail", JSON.stringify(manifest, null, 2));
    const events = capture.events ?? [];
    text("events-detail", JSON.stringify(events.slice(0, 500), null, 2) + (events.length > 500 ? `\nShowing 500 of ${events.length} events.` : ""));
    byId("timeline").max = String(capture.frames.length - 1);
    for (const id of ["previous", "play", "next", "timeline"]) byId(id).disabled = false;
    update();
  }

  function inspect() {
    if (!capture || !selected) return;
    const bus = capture.buses.find((v) => v.id === selected.bus);
    const frame = capture.frames[current], bytes = frame.buses[bus.id];
    const rgb = decodePixel(bytes, bus.order, selected.index);
    text("pixel", `${bus.id} [${selected.index}] · ${bus.stage ?? "driver"}\nRGB ${rgb.join(", ")}\nStored ${bus.order}: ${bytes.slice(selected.index * 6, selected.index * 6 + 6)}${masked(bus.id, selected.index) ? "\nDisplay-masked pixel" : ""}`);
    byId("swatch").style.backgroundColor = rgbCSS(rgb);
  }

  function drawStrips(frame) {
    const columns = Math.max(8, Math.floor((width - 40) / 15));
    const gap = 3, left = 18;
    const rows = capture.buses.reduce((sum, bus) => sum + Math.ceil(bus.pixels / columns), 0);
    const cell = Math.max(2, Math.min(18, (width - 40) / columns - gap, (height - 45 * capture.buses.length - 14) / Math.max(1, rows) - gap));
    let top = 15;
    for (const bus of capture.buses) {
      ctx.fillStyle = "#adbdcf"; ctx.font = "12px system-ui";
      ctx.fillText(`${bus.id} · ${bus.pixels} ${bus.stage ?? "driver"} pixels · ${bus.order}`, left, top + 12);
      top += 25;
      for (let index = 0; index < bus.pixels; index++) {
        const x = left + (index % columns) * (cell + gap), y = top + Math.floor(index / columns) * (cell + gap);
        const hidden = masked(bus.id, index);
        ctx.fillStyle = hidden ? "#121922" : rgbCSS(decodePixel(frame.buses[bus.id], bus.order, index));
        ctx.fillRect(x, y, cell, cell);
        ctx.strokeStyle = hidden ? "#405063" : "#25303c"; ctx.lineWidth = 0.5; ctx.strokeRect(x, y, cell, cell);
        if (hidden) { ctx.beginPath(); ctx.moveTo(x, y + cell); ctx.lineTo(x + cell, y); ctx.stroke(); }
        if (selected?.bus === bus.id && selected.index === index) { ctx.strokeStyle = "white"; ctx.lineWidth = 2; ctx.strokeRect(x - 2, y - 2, cell + 4, cell + 4); }
        hitTargets.push({bus: bus.id, index, x, y, w: cell, h: cell});
      }
      top += Math.ceil(bus.pixels / columns) * (cell + gap) + 15;
    }
  }

  function drawPoints(frame) {
    const points = capture.geometry.points.filter((p) => !masked(p.bus, p.index));
    if (!points.length) { ctx.fillStyle = "#adbdcf"; ctx.fillText("All geometry points are display-masked.", 24, 40); return; }
    const axes = ["x", "y", "z"];
    const min = axes.map((axis) => points.reduce((v, p) => Math.min(v, p[axis]), Infinity));
    const max = axes.map((axis) => points.reduce((v, p) => Math.max(v, p[axis]), -Infinity));
    const centre = min.map((v, index) => v / 2 + max[index] / 2);
    const extent = Math.max(...max.map((v, index) => v - min[index]), 1e-9);
    const yaw = Number(byId("yaw").value) * Math.PI / 180, pitch = Number(byId("pitch").value) * Math.PI / 180;
    const projected = points.map((p) => {
      const x = (p.x - centre[0]) / extent * 2, y = (p.y - centre[1]) / extent * 2, z = (p.z - centre[2]) / extent * 2;
      const rx = x * Math.cos(yaw) - z * Math.sin(yaw), rz = x * Math.sin(yaw) + z * Math.cos(yaw);
      const ry = y * Math.cos(pitch) - rz * Math.sin(pitch), depth = y * Math.sin(pitch) + rz * Math.cos(pitch);
      const zoom = Math.min(width, height) * 0.36 * 4 / (4 - depth);
      return {...p, px: width / 2 + rx * zoom, py: height / 2 - ry * zoom, depth};
    }).sort((a, b) => a.depth - b.depth);
    const buses = new Map(capture.buses.map((bus) => [bus.id, bus]));
    const radius = Math.max(2, Math.min(7, 70 / Math.sqrt(points.length)));
    for (const point of projected) {
      const bus = buses.get(point.bus), rgb = decodePixel(frame.buses[point.bus], bus.order, point.index);
      ctx.fillStyle = rgbCSS(rgb); ctx.beginPath(); ctx.arc(point.px, point.py, radius, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = selected?.bus === point.bus && selected.index === point.index ? "white" : "#384859";
      ctx.lineWidth = selected?.bus === point.bus && selected.index === point.index ? 2 : 0.6; ctx.stroke();
      hitTargets.push({bus: point.bus, index: point.index, x: point.px - radius - 3, y: point.py - radius - 3, w: radius * 2 + 6, h: radius * 2 + 6});
    }
  }

  function draw() {
    const rect = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
    width = Math.max(1, rect.width); height = Math.max(1, rect.height);
    canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0); ctx.clearRect(0, 0, width, height); hitTargets = [];
    if (!capture) { ctx.fillStyle = "#8799ae"; ctx.font = "15px system-ui"; ctx.fillText("Your capture will appear here.", 24, 42); return; }
    const frame = capture.frames[current];
    if (byId("view").value === "points") drawPoints(frame); else drawStrips(frame);
  }

  function update() {
    if (!capture) return;
    const frame = capture.frames[current];
    byId("timeline").value = String(current);
    text("position", `Frame ${current + 1}/${capture.frames.length} · ${(frame.time_us / 1000).toFixed(3)} ms`);
    const {buses, ...metadata} = frame;
    text("frame-detail", JSON.stringify(metadata, null, 2));
    const total = capture.buses.reduce((sum, bus) => sum + bus.pixels, 0);
    const hiddenNonzero = maskedNonzeroCount(capture, frame);
    const maskWarning = hiddenNonzero ? ` Warning: ${hiddenNonzero} display-masked pixel${hiddenNonzero === 1 ? " has" : "s have"} nonzero stored bytes. Inspect crossed cells in Strips view; comparison still includes these values.` : "";
    text("canvas-note", `${total} indexed pixels across ${capture.buses.length} bus${capture.buses.length === 1 ? "" : "es"}. Click a pixel for stored bytes.${byId("view").value === "points" ? " Rotate and tilt to inspect the supplied geometry." : " Crossed cells are display-masked."}${maskWarning}`);
    inspect(); draw();
  }

  function tick(now) {
    if (!playing || !capture) return;
    const time = anchorUs + (now - anchor) * Number(byId("speed").value) * 1000;
    const next = frameAtTime(capture.frames, time);
    if (next !== current) { current = next; update(); }
    if (time >= capture.frames[capture.frames.length - 1].time_us) { pause(); return; }
    animation = requestAnimationFrame(tick);
  }

  byId("file").addEventListener("change", async (event) => {
    const file = event.target.files[0], serial = ++loadSerial;
    if (!file) return;
    try {
      if (file.size > 128 * 1024 * 1024) throw new Error("This viewer accepts JSON files up to 128 MiB; export a smaller time window.");
      const value = JSON.parse(await file.text());
      if (serial === loadSerial) load(value);
    } catch (error) { if (serial === loadSerial) showError(error); }
  });
  byId("play").addEventListener("click", () => {
    if (!capture) return;
    if (playing) { pause(); return; }
    if (current === capture.frames.length - 1) { current = 0; update(); }
    anchor = performance.now(); anchorUs = capture.frames[current].time_us; playing = true; text("play", "Pause");
    animation = requestAnimationFrame(tick);
  });
  byId("speed").addEventListener("change", () => { if (playing) { anchor = performance.now(); anchorUs = capture.frames[current].time_us; } });
  byId("timeline").addEventListener("input", () => { pause(); current = Number(byId("timeline").value); update(); });
  byId("previous").addEventListener("click", () => { pause(); current = Math.max(0, current - 1); update(); });
  byId("next").addEventListener("click", () => { pause(); current = Math.min(capture.frames.length - 1, current + 1); update(); });
  byId("view").addEventListener("change", () => { byId("yaw-label").hidden = byId("pitch-label").hidden = byId("view").value !== "points"; update(); });
  for (const id of ["yaw", "pitch"]) byId(id).addEventListener("input", draw);
  canvas.addEventListener("click", (event) => {
    const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
    const hit = [...hitTargets].reverse().find((p) => x >= p.x && x <= p.x + p.w && y >= p.y && y <= p.y + p.h);
    if (hit) { selected = {bus: hit.bus, index: hit.index}; inspect(); draw(); }
  });
  canvas.addEventListener("keydown", (event) => {
    if (!capture || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    event.preventDefault(); pause(); current = Math.max(0, Math.min(capture.frames.length - 1, current + (event.key === "ArrowRight" ? 1 : -1))); update();
  });
  window.addEventListener("resize", draw);
  reset();
  const embedded = byId("vfl-capture");
  if (embedded) {
    try { const value = JSON.parse(embedded.textContent); if (value !== null) load(value); }
    catch (error) { showError(error); }
  }
})();
