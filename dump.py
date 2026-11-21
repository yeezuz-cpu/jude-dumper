"""Dump the CS2 offsets and signatures used by Jude."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pefile


DEFAULT_GAME = Path(
    r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game"
)


@dataclass(frozen=True)
class Target:
    module: str
    pattern: str
    operand: int
    instruction_end: int
    section: str


TARGETS = {
    "dwCSGOInput": Target("client.dll", "48 89 05 ? ? ? ? 0F 57 C0 0F 11 05", 3, 7, ".data"),
    "dwEntityList": Target("client.dll", "48 89 0D ? ? ? ? E9 ? ? ? ? CC", 3, 7, ".data"),
    "dwGameEntitySystem": Target("client.dll", "48 8B 1D ? ? ? ? 48 89 1D ? ? ? ? 4C 63 B3", 3, 7, ".data"),
    "dwGameRules": Target("client.dll", "F6 C1 01 0F 85 ? ? ? ? 4C 8B 05 ? ? ? ? 4D 85", 12, 16, ".data"),
    "dwGlobalVars": Target("client.dll", "48 89 15 ? ? ? ? 48 89 42", 3, 7, ".data"),
    "dwGlowManager": Target("client.dll", "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 41", 3, 7, ".data"),
    "dwLocalPlayerController": Target("client.dll", "48 8B 05 ? ? ? ? 41 89 BE", 3, 7, ".data"),
    "dwPlantedC4": Target("client.dll", "48 39 2D ? ? ? ? 75 ? 49 89 AE 78 12 00 00 49 89 AE 80 12 00 00 4C 89 35 ? ? ? ?", 3, 7, ".data"),
    "dwPrediction": Target("client.dll", "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54", 3, 7, ".data"),
    "dwSensitivity": Target("client.dll", "48 8D 0D ? ? ? ? 0F 57 C9 0F 28 F0 F3 0F 2A D7", 3, 7, ".data"),
    "dwViewMatrix": Target("client.dll", "48 8D 0D ? ? ? ? 48 C1 E0 06", 3, 7, ".data"),
    "dwViewRender": Target("client.dll", "48 89 05 ? ? ? ? 48 8B C8 48 85 C0", 3, 7, ".data"),
    "inventoryManager": Target("client.dll", "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 0F B6 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 83 B9", 3, 7, ".data"),
    "particleManager": Target("client.dll", "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 5C 24 ? 57 B8 40 12 00 00", 3, 7, ".data"),
    "inventoryUiEngine": Target("client.dll", "48 8B 3D ? ? ? ? 48 C1 E3 20", 3, 7, ".data"),
    "inventoryUiEventType": Target("client.dll", "0F B7 0D ? ? ? ? 66 89 48 ? 48 B9 00 00 00 00 FF FF FF FF 48 89 48 ? 48 8D 0D ? ? ? ? 48 89 08 48 89 58", 3, 7, ".data"),
    "inventoryUiEventVtable": Target("client.dll", "48 8D 0D ? ? ? ? 48 89 08 48 89 58 ? 48 8D 54 24", 3, 7, ".rdata"),
    "sceneLightQueue": Target("scenesystem.dll", "4C 8B 35 ? ? ? ? C1 E0 05 48 63 D0 49 03 56 ? 49 3B 56 ? 76 ? 49 8B CE FF 15 ? ? ? ? 84 C0 75 ? 49 8B F4", 3, 7, ".data"),
    "dwBuildNumber": Target("engine2.dll", "89 05 ? ? ? ? 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 0D", 2, 6, ".data"),
    "dwNetworkGameClient": Target("engine2.dll", "48 89 3D ? ? ? ? FF 87", 3, 7, ".data"),
    "dwWindowHeight": Target("engine2.dll", "8B 05 ? ? ? ? 89 03", 2, 6, ".data"),
    "dwWindowWidth": Target("engine2.dll", "8B 05 ? ? ? ? 89 07", 2, 6, ".data"),
}

# Anchored to the C_EconItemView primary vtable assignment in the constructor.
FUNCTION_TARGETS = {
    "econ_item_view_constructor": ("client.dll", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8D 05 ? ? ? ? 48 8B F9 48 89 01 45 33 C9"),
    "inventory_metadata_bind": ("client.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 4C 24 ? 56 57 41 56 48 83 EC 60"),
    "econ_item_view_init": ("client.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 8B D9 45 8B F1"),
    "weapon_composite_data": ("client.dll", "40 53 48 83 EC 20 48 8B 41 ? 4C 8B 00 4D 85 C0 74 ? 48 8B 40 ? 33 DB 48 63 15 ? ? ? ? 48 8B 88 ? ? ? ? 0F B7 04 51 B9 FF FF 00 00 66 3B C1 74 ? 4A 8B 0C 00 EB ? 48 8B CB 48 85 C9 74 ? 48 8B 49 ? 48 8B 01 FF 50 ? 48 85 C0 74 ? 48 8B 80"),
    "particle_create": ("client.dll", "40 57 48 83 EC 20 49 8B 00"),
    "particle_control": ("client.dll", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 50 F3 0F 10 1D"),
    "particle_destroy": ("client.dll", "83 FA FF 0F 84 ? ? ? ? 41 54"),
    "inventory_item_added": ("client.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 30 44 8B A4 24"),
    "resource_path_init": ("client.dll", "48 89 5C 24 ? 57 48 83 EC 30 8B 41 ? 48 8D 79"),
    "scene_parameter_set": ("client.dll", "48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 66 0F 6E CA 49 8B F0 66 0F 70 C9 00 8B EA 48 8B F9 45 33 C9 48 8B C1 66 66 0F 1F 84 00 ? ? ? ? 66 0F 6F C1 4C 8D 15 ? ? ? ? 66 0F 76 00 0F 50 C8 85 C9 75 ? 41 FF C1 48 83 C0 10 41 83 F9 02 72 ? 48 8B 87 ? ? ? ? 48 85 C0 74 ? 90 48 8D 48 ? 33 D2 66 66 0F 1F 84 00 ? ? ? ? 66 0F 6F C1 66 0F 76 01 44 0F 50 C0 45 85 C0 75 ? FF C2 48 83 C1 10 83 FA 01"),
    "scene_light_update": ("scenesystem.dll", "48 89 54 24 ? 55 57 41 56"),
    "scene_sky_draw": ("scenesystem.dll", "45 85 C9 0F 8E ? ? ? ? 4C 8B DC"),
}


def module_path(game: Path, name: str) -> Path:
    candidates = [
        game / "csgo" / "bin" / "win64" / name,
        game / "bin" / "win64" / name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"cannot find {name} under {game}")


def compile_pattern(text: str) -> tuple[bytes, bytes]:
    values = bytearray()
    masks = bytearray()
    for token in text.split():
        if token in {"?", "??"}:
            values.append(0)
            masks.append(0)
        else:
            values.append(int(token, 16))
            masks.append(0xFF)
    if not values:
        raise ValueError("empty pattern")
    return bytes(values), bytes(masks)


class Image:
    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        self.pe = pefile.PE(data=self.raw, fast_load=False)
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.fingerprint = hashlib.sha256(self.raw).hexdigest()

    def sections(self, executable_only: bool = False):
        for section in self.pe.sections:
            if executable_only and not section.Characteristics & 0x20000000:
                continue
            name = section.Name.rstrip(b"\0").decode("ascii", "replace")
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            yield name, section.VirtualAddress, self.pe.get_data(section.VirtualAddress, size)

    def scan(self, pattern: str) -> list[int]:
        values, masks = compile_pattern(pattern)
        if not any(masks):
            return []
        expression = b"".join(
            re.escape(bytes([value])) if mask else b"."
            for value, mask in zip(values, masks)
        )
        matcher = re.compile(expression, re.DOTALL)
        hits: list[int] = []
        for _name, section_rva, data in self.sections(executable_only=True):
            hits.extend(section_rva + match.start() for match in matcher.finditer(data))
        return hits

    def resolve_rel32(self, hit: int, operand: int, instruction_end: int) -> int:
        displacement = struct.unpack("<i", self.pe.get_data(hit + operand, 4))[0]
        return hit + instruction_end + displacement

    def read_u32(self, rva: int) -> int:
        return struct.unpack("<I", self.pe.get_data(rva, 4))[0]

    def read_cstring(self, rva: int, limit: int = 128) -> str | None:
        data = self.pe.get_data(rva, limit)
        end = data.find(b"\0")
        if end <= 0:
            return None
        try:
            value = data[:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        return value if all(32 <= ord(char) < 127 for char in value) else None

    def section_name(self, rva: int) -> str | None:
        section = self.pe.get_section_by_rva(rva)
        return section.Name.rstrip(b"\0").decode("ascii", "replace") if section else None


SOURCE_PATTERN = re.compile(
    r"scan::(find|findAll)\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\""
)
SCHEMA_PATTERN = re.compile(r"schema::offset\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"\s*\)")
RTTI_PATTERN = re.compile(r'scan::vtableOf\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
WRAPPER_PATTERN = re.compile(r'\b(findUnique|unique|resolveCall)\(\s*"([0-9A-Fa-f? ]+)"\s*\)')
RVA_PATTERN = re.compile(
    r"(?:constexpr\s+std::uintptr_t\s+|\b)([A-Za-z_]\w*(?:Rva|RVA|Global|Function|Vtable))\s*=\s*(0x[0-9A-Fa-f]+)"
)


def source_inventory(source: Path) -> tuple[list[dict], list[dict], list[dict]]:
    signatures: list[dict] = []
    schemas: dict[tuple[str, str], dict] = {}
    hardcoded: list[dict] = []
    for path in sorted(source.rglob("*")):
        if path.suffix not in {".cpp", ".h"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(source.parent).as_posix()
        for match in SOURCE_PATTERN.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            assignment = re.search(r"([A-Za-z_]\w*)\s*=\s*$", text[line_start:match.start()])
            label = assignment.group(1) if assignment else str(line_number)
            signatures.append({
                "file": relative,
                "line": line_number,
                "name": f"sig_{path.stem}_{label}",
                "api": match.group(1),
                "module": match.group(2),
                "pattern": match.group(3),
            })
        for match in WRAPPER_PATTERN.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            assignment = re.search(r"([A-Za-z_]\w*)\s*=.*$", text[line_start:match.start()])
            label = assignment.group(1) if assignment else str(line_number)
            signatures.append({"file": relative, "line": line_number, "name": f"sig_{path.stem}_{label}",
                               "api": match.group(1), "module": "client.dll", "pattern": match.group(2)})
        for match in SCHEMA_PATTERN.finditer(text):
            key = (match.group(1), match.group(2))
            schemas.setdefault(key, {"class": key[0], "field": key[1], "used_by": []})["used_by"].append(relative)
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in RVA_PATTERN.finditer(line):
                hardcoded.append({
                    "file": relative,
                    "line": line_number,
                    "name": match.group(1),
                    "value": int(match.group(2), 16),
                })
    return signatures, list(schemas.values()), hardcoded


def audit_signatures(signatures: list[dict], images: dict[str, Image]) -> list[dict]:
    results = []
    cache: dict[tuple[str, str], list[int]] = {}
    for item in signatures:
        key = (item["module"].lower(), item["pattern"])
        image = images.get(key[0])
        row = dict(item)
        if not image:
            row.update(status="module-missing", matches=[])
        else:
            try:
                if key not in cache:
                    cache[key] = image.scan(item["pattern"])
                matches = cache[key]
                if len(matches) == 1:
                    status = "ok"
                elif not matches:
                    status = "missing"
                elif item["api"] == "findAll":
                    status = "candidate-set"
                else:
                    status = "ambiguous"
                row.update(status=status, matches=matches)
            except ValueError as error:
                row.update(status="invalid-pattern", matches=[], error=str(error))
        results.append(row)
    return results


def derive_immediate(image: Image, pattern: str, operand: int) -> tuple[int | None, list[int]]:
    hits = image.scan(pattern)
    if len(hits) != 1:
        return None, hits
    return image.read_u32(hits[0] + operand), hits


def add_derived_offsets(offsets: dict[str, dict], images: dict[str, Image]) -> None:
    client = images.get("client.dll")
    if not client:
        return
    definitions = [
        ("dwGameEntitySystem_highestEntityIndex", "FF 81 ? ? ? ? 48 85 D2", 2, None),
        ("dwViewAngles", "F2 42 0F 10 84 28 ? ? ? ?", 6, "dwCSGOInput"),
        ("dwLocalPlayerPawn", "4C 39 B6 ? ? ? ? 74 ? 44 88 BE", 3, "dwPrediction"),
    ]
    for name, pattern, operand, base_name in definitions:
        immediate, hits = derive_immediate(client, pattern, operand)
        result = {"module": "client.dll", "pattern": pattern, "matches": hits}
        if immediate is None:
            result["status"] = "missing" if not hits else "ambiguous"
        elif base_name and offsets.get(base_name, {}).get("status") == "ok":
            result.update(status="ok", rva=offsets[base_name]["rva"] + immediate, derived_from=base_name, field_offset=immediate)
        elif base_name:
            result.update(status="dependency-failed", field_offset=immediate, derived_from=base_name)
        else:
            result.update(status="ok", rva=immediate, immediate=True)
        offsets[name] = result
    # The sensitivity getter dereferences the convar pointer at +8, then reads
    # its float value. Resolve the call before extracting the value offset.
    pattern = "E8 ? ? ? ? F3 0F 59 C6 F3 0F 11 86"
    hits = client.scan(pattern)
    sensitivity = {"module": "client.dll", "pattern": pattern, "matches": hits,
                   "relative_to": "dwSensitivity", "status": "missing" if not hits else "ambiguous"}
    if len(hits) == 1:
        getter = client.resolve_rel32(hits[0], 1, 5)
        code = client.pe.get_data(getter, 10)
        if code[:8] == bytes.fromhex("48 8B 41 08 F3 0F 10 40") and code[9:10] == b"\xC3":
            sensitivity.update(status="ok", rva=code[8], getter=getter, pointer_offset=8)
        else:
            sensitivity.update(status="unexpected-getter", getter=getter)
    offsets["dwSensitivity_sensitivity"] = sensitivity


def dump_buttons(client: Image) -> list[dict]:
    pattern = "45 33 C0 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8"
    wanted = {
        "attack", "attack2", "back", "duck", "forward", "jump", "left",
        "lookatweapon", "reload", "right", "score", "speed", "turnleft",
        "turnright", "use", "zoom",
    }
    found: dict[str, dict] = {}
    for hit in client.scan(pattern):
        name_rva = client.resolve_rel32(hit, 6, 10)
        button_rva = client.resolve_rel32(hit, 13, 17)
        name = client.read_cstring(name_rva)
        if name in wanted and name not in found:
            found[name] = {"name": name, "rva": button_rva + 0x28, "initializer": hit}
    return [found[name] for name in sorted(found)]


def dump_interfaces(images: dict[str, Image]) -> list[dict]:
    expression = re.compile(rb"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]{3,48}(?:_\d{3}|\d{3}))\x00")
    prefixes = ("V", "Source", "Schema", "Game", "Engine", "Input", "Material", "Scene", "Resource", "Network", "Panorama")
    results: list[dict] = []
    for module, image in sorted(images.items()):
        seen = set()
        for _section, section_rva, data in image.sections():
            for match in expression.finditer(data):
                name = match.group(1).decode("ascii")
                if name.startswith(prefixes) and name not in seen:
                    seen.add(name)
                    results.append({"module": module, "name": name, "string_rva": section_rva + match.start(1)})
    return results


def dump_rtti_vtables(source: Path, images: dict[str, Image]) -> list[dict]:
    requests = set()
    for path in source.rglob("*"):
        if path.suffix in {".cpp", ".h"}:
            requests.update(RTTI_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace")))
    results = []
    for module, name in sorted(requests):
        row = {"module": module.lower(), "type": name, "status": "missing", "matches": []}
        image = images.get(module.lower())
        if not image:
            row["status"] = "module-missing"
            results.append(row)
            continue
        sections = list(image.sections())
        needle = name.encode("ascii") + b"\0"
        names = [(rva + m.start()) for _, rva, data in sections for m in re.finditer(re.escape(needle), data)]
        if len(names) != 1 or names[0] < 16:
            row["status"] = "missing" if not names else "ambiguous-type"
            results.append(row)
            continue
        descriptor = names[0] - 16
        imagebase = image.pe.OPTIONAL_HEADER.ImageBase
        locators = []
        for _, section_rva, data in sections:
            for match in re.finditer(re.escape(struct.pack("<I", descriptor)), data):
                pos = match.start() - 12
                if pos < 0 or pos + 24 > len(data):
                    continue
                sig, offset, _, type_rva, _, self_rva = struct.unpack_from("<6I", data, pos)
                locator = section_rva + pos
                if sig == 1 and offset == 0 and type_rva == descriptor and self_rva == locator:
                    locators.append(locator)
        for locator in locators:
            ptr = struct.pack("<Q", imagebase + locator)
            for _, section_rva, data in sections:
                for match in re.finditer(re.escape(ptr), data):
                    table = section_rva + match.start() + 8
                    if image.section_name(table) == ".rdata":
                        results_row = image.pe.get_data(table, 8)
                        if len(results_row) == 8:
                            entry = struct.unpack("<Q", results_row)[0] - imagebase
                            if image.section_name(entry) == ".text":
                                row["matches"].append(table)
        row["matches"] = sorted(set(row["matches"]))
        row["status"] = "ok" if len(row["matches"]) == 1 else ("ambiguous" if row["matches"] else "missing")
        if row["status"] == "ok":
            row["rva"] = row["matches"][0]
            known_slots = {".?AVClientModeCSNormal@@": {"override_view": 15},
                           ".?AVC_EnvSky@@": {"rebuild_sky": 13},
                           ".?AVCAnimatableSceneObjectDesc@@": {"generate_primitives": 4},
                           ".?AVCAggregateSceneObjectDesc@@": {"draw": 7},
                           ".?AVCSceneObjectDesc@@": {"draw": 1}}
            row["slots"] = {}
            for label, slot in known_slots.get(name, {}).items():
                pointer = image.pe.get_data(row["rva"] + 8 * slot, 8)
                if len(pointer) != 8:
                    continue
                function = struct.unpack("<Q", pointer)[0] - imagebase
                if image.section_name(function) == ".text":
                    row["slots"][label] = {"slot": slot, "rva": function}
        results.append(row)
    return results


def read_schema_log(path: Path | None, client: Image | None) -> dict:
    result = {"path": str(path) if path else None, "status": "missing", "values": []}
    if not path or not path.is_file():
        return result
    # A newer log is not proof that it came from this exact binary.
    result["status"] = "unverified" if client and path.stat().st_mtime >= client.path.stat().st_mtime else "stale"
    expression = re.compile(r"schema ok\s+([^\s]+)->([^\s]+) = 0x([0-9A-Fa-f]+)")
    for match in expression.finditer(path.read_text(encoding="utf-8", errors="replace")):
        result["values"].append({"class": match.group(1), "field": match.group(2), "offset": int(match.group(3), 16)})
    return result


def compare_offsets(previous: dict | None, offsets: dict[str, dict]) -> list[dict]:
    if not previous:
        return []

    old_offsets = previous.get("generated_offsets", {})
    changes = []
    for name in sorted(set(old_offsets) | set(offsets)):
        old = old_offsets.get(name, {})
        new = offsets.get(name, {})
        old_value = old.get("rva") if old.get("status") == "ok" else None
        new_value = new.get("rva") if new.get("status") == "ok" else None
        if old_value != new_value or old.get("status") != new.get("status"):
            changes.append({
                "name": name,
                "old_status": old.get("status", "absent"),
                "old_value": old_value,
                "new_status": new.get("status", "absent"),
                "new_value": new_value,
            })
    return changes


def describe_offset(status: str, value: int | None) -> str:
    return f"0x{value:X}" if value is not None else status


def render_header(offsets: dict[str, dict], fingerprints: dict[str, str]) -> str:
    lines = [
        "#pragma once",
        "",
        "// dumped by Michel",
        "namespace generated_offsets {",
    ]
    for module, digest in sorted(fingerprints.items()):
        identifier = module.replace(".", "_")
        lines.append(f'inline constexpr char {identifier}_sha256[] = "{digest}";')
    lines.append("")
    for name, result in offsets.items():
        if result["status"] == "ok":
            lines.append(f"inline constexpr unsigned long long {name} = 0x{result['rva']:X}ull;")
    lines.extend(["}", ""])
    return "\n".join(lines)


def render_offset_text(
    offsets: dict[str, dict],
    created: datetime,
    buttons: list[dict],
    schema_log: dict,
    rtti_vtables: list[dict],
    function_targets: dict[str, dict],
) -> str:
    lines = [
        "// dumped by Michel",
        f"// {created.astimezone().strftime('%Y-%m-%d %H:%M:%S %z')}",
        "",
    ]
    modules = list(dict.fromkeys(result["module"] for result in offsets.values()))
    for module_index, module in enumerate(modules):
        if module_index:
            lines.append("")
        lines.append(f"// {module}")
        for name, result in offsets.items():
            if result["status"] == "ok" and result["module"] == module:
                lines.append(f"{name} = 0x{result['rva']:X}")
    lines.extend(["", "// buttons"])
    for button in buttons:
        lines.append(f"button_{button['name']} = 0x{button['rva']:X}")
    lines.extend(["", "// vtables"])
    for table in rtti_vtables:
        if table["status"] == "ok":
            type_name = table['type']
            if type_name.startswith('.?AV') and type_name.endswith('@@'):
                type_name = '::'.join(reversed(type_name[4:-2].split('@')))
            lines.append(f"{type_name} = 0x{table['rva']:X}")
            for label, entry in table.get("slots", {}).items():
                lines.append(f"{type_name}::{label} = 0x{entry['rva']:X}")
    lines.extend(["", "// functions"])
    for name, target in function_targets.items():
        if target["status"] == "ok":
            lines.append(f"{name} = 0x{target['rva']:X}")
    if schema_log["status"] == "current" and schema_log["values"]:
        lines.extend(["", "// schema"])
        for field in schema_log["values"]:
            lines.append(f"{field['class']}::{field['field']} = 0x{field['offset']:X}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and audit Jude offsets from installed CS2 PE files")
    parser.add_argument("--game", type=Path, default=DEFAULT_GAME)
    script_dir = Path(__file__).resolve().parent
    default_root = script_dir.parent.parent if script_dir.parent.name == "tools" else script_dir
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--write-header", action="store_true")
    parser.add_argument("--schema-log", type=Path)
    args = parser.parse_args()

    output = args.output or args.root / "build" / "offsets"
    output.mkdir(parents=True, exist_ok=True)
    previous_path = output / "jude-offset-report.json"
    previous = None
    if previous_path.is_file():
        try:
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    signatures, schemas, hardcoded = source_inventory(args.root / "src")
    modules = sorted(
        {target.module.lower() for target in TARGETS.values()}
        | {item["module"].lower() for item in signatures}
        | {"scenesystem.dll"}
    )
    images: dict[str, Image] = {}
    load_errors: dict[str, str] = {}
    for module in modules:
        try:
            images[module] = Image(module_path(args.game, module))
        except (FileNotFoundError, pefile.PEFormatError) as error:
            load_errors[module] = str(error)

    offsets: dict[str, dict] = {}
    for name, target in TARGETS.items():
        image = images.get(target.module.lower())
        if not image:
            offsets[name] = {"module": target.module, "status": "module-missing"}
            continue
        hits = image.scan(target.pattern)
        result = {"module": target.module, "pattern": target.pattern, "matches": hits}
        if len(hits) != 1:
            result["status"] = "missing" if not hits else "ambiguous"
        else:
            rva = image.resolve_rel32(hits[0], target.operand, target.instruction_end)
            section = image.section_name(rva)
            result.update(rva=rva, section=section, expected_section=target.section)
            result["status"] = "ok" if section == target.section else "wrong-section"
        offsets[name] = result

    add_derived_offsets(offsets, images)

    function_targets = {}
    for name, (module, pattern) in FUNCTION_TARGETS.items():
        image = images.get(module)
        hits = image.scan(pattern) if image else []
        status = "module-missing" if not image else ("ok" if len(hits) == 1 else ("missing" if not hits else "ambiguous"))
        function_targets[name] = {"module": module, "pattern": pattern, "status": status, "matches": hits}
        if status == "ok":
            function_targets[name]["rva"] = hits[0]

    signature_results = audit_signatures(signatures, images)
    for item in hardcoded:
        module = "scenesystem.dll" if "world.cpp" in item["file"] and item["value"] < 0x1000000 else "client.dll"
        image = images.get(module)
        item["module"] = module
        item["section"] = image.section_name(item["value"]) if image else None
        item["status"] = "inside-image" if image and item["section"] else "outside-image"

    buttons = dump_buttons(images["client.dll"]) if "client.dll" in images else []
    interfaces = dump_interfaces(images)
    rtti_vtables = dump_rtti_vtables(args.root / "src", images)
    schema_path = args.schema_log or args.root / "build" / "Release" / "jude.log"
    schema_log = read_schema_log(schema_path, images.get("client.dll"))

    fingerprints = {name: image.fingerprint for name, image in images.items()}
    created = datetime.now(timezone.utc)
    report = {
        "format": 1,
        "created_utc": created.isoformat(),
        "game_root": str(args.game),
        "modules": {
            name: {"path": str(image.path), "sha256": image.fingerprint, "size_of_image": image.image_size}
            for name, image in images.items()
        },
        "module_errors": load_errors,
        "generated_offsets": offsets,
        "function_targets": function_targets,
        "runtime_signatures": signature_results,
        "schema_requests": schemas,
        "hardcoded_rvas": hardcoded,
        "buttons": buttons,
        "interfaces": interfaces,
        "rtti_vtables": rtti_vtables,
        "schema_log": schema_log,
    }
    changes = compare_offsets(previous, offsets)
    report["changes_since_previous_run"] = changes
    report_path = output / "jude-offset-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    offsets_path = output / "offsets.txt"
    offsets_path.write_text(
        render_offset_text(offsets, created, buttons, schema_log, rtti_vtables, function_targets),
        encoding="utf-8",
    )

    unique = sum(value["status"] == "ok" for value in offsets.values())
    signature_ok = sum(value["status"] in {"ok", "candidate-set"} for value in signature_results)
    summary = [
        f"Jude offset report for {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Generated globals: {unique}/{len(offsets)} validated",
        f"Runtime signatures: {signature_ok}/{len(signature_results)} usable",
        f"Schema requests inventoried: {len(schemas)} (resolved by Jude at runtime)",
        f"Hardcoded RVAs inventoried: {len(hardcoded)}",
        f"Function targets resolved: {sum(v['status'] == 'ok' for v in function_targets.values())}/{len(function_targets)}",
        f"Buttons dumped: {len(buttons)}",
        f"Interface names found: {len(interfaces)}",
        f"RTTI tables resolved: {sum(x['status'] == 'ok' for x in rtti_vtables)}/{len(rtti_vtables)}",
        f"Changes since previous report: {len(changes)}" if previous else "Changes since previous report: unavailable",
        "",
    ]
    for row in rtti_vtables:
        result = f"0x{row['rva']:X}" if row["status"] == "ok" else row["status"]
        summary.append(f"  {row['module']} {row['type']}: {result}")
    summary.append("")
    if changes:
        for change in changes:
            old = describe_offset(change["old_status"], change["old_value"])
            new = describe_offset(change["new_status"], change["new_value"])
            summary.append(f"  {change['name']}: {old} -> {new}")
        summary.append("")
    for name, value in offsets.items():
        suffix = f"0x{value['rva']:X}" if value["status"] == "ok" else value["status"]
        summary.append(f"{name:30} {suffix}")
    summary_path = output / "jude-offset-report.txt"
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")

    if args.write_header:
        required = {"dwViewMatrix", "dwGlobalVars"}
        failed = [name for name in required if offsets.get(name, {}).get("status") != "ok"]
        if failed:
            print("Refusing to write header. Required targets failed: " + ", ".join(failed), file=sys.stderr)
            return 2
        header = args.root / "src" / "generated" / "offsets.h"
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(render_header(offsets, fingerprints), encoding="utf-8")
        print(f"Wrote {header}")

    print(summary_path.read_text(encoding="utf-8"), end="")
    print(f"Offsets: {offsets_path}")
    print(f"JSON: {report_path}")
    return 0 if unique else 1


if __name__ == "__main__":
    raise SystemExit(main())
