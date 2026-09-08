"""General-purpose ELF binary analyzer — no crypto domain knowledge."""

from __future__ import annotations

import mmap
import re
import struct
from dataclasses import dataclass
from pathlib import Path

_PT_LOAD = 1
_PT_DYNAMIC = 2
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10

_MACHINE_NAMES: dict[int, str] = {
    3: "i386",
    62: "x86_64",
    40: "arm",
    183: "aarch64",
    243: "riscv64",
    8: "mips",
    10: "mips64",
}


@dataclass
class ElfMetadata:
    arch: str
    elf_class: int
    endian: str


@dataclass
class StringMatch:
    pattern_id: str
    matched: str
    offset: int


@dataclass
class LinkedLibrary:
    name: str


class ElfAnalyzer:
    """Parse ELF headers and dynamic sections without external tools."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._data: bytes | None = None

    def _load(self) -> bytes:
        if self._data is None:
            self._data = self.path.read_bytes()
        return self._data

    def _parse_header(self, data: bytes) -> tuple[int, str, int, int] | None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None
        ei_class = data[4]
        if data[5] == 1:
            endian = "<"
        elif data[5] == 2:
            endian = ">"
        else:
            return None
        if ei_class == 2 or ei_class == 1:
            e_machine = struct.unpack_from(endian + "H", data, 18)[0]
        else:
            return None
        return ei_class, endian, e_machine, ei_class

    def metadata(self) -> ElfMetadata | None:
        data = self._load()
        parsed = self._parse_header(data)
        if parsed is None:
            return None
        ei_class, endian, e_machine, _ = parsed
        arch = _MACHINE_NAMES.get(e_machine, f"unknown({e_machine})")
        return ElfMetadata(
            arch=arch,
            elf_class=32 if ei_class == 1 else 64,
            endian="little" if endian == "<" else "big",
        )

    def _load_segments(self, data: bytes) -> tuple[list[tuple[int, int, int]], int, int]:
        """Return (PT_LOAD segments, dynamic_offset, dynamic_size)."""
        parsed = self._parse_header(data)
        if parsed is None:
            return [], 0, 0
        ei_class, endian, _, _ = parsed
        load_segments: list[tuple[int, int, int]] = []
        dynamic_offset = 0
        dynamic_size = 0

        try:
            if ei_class == 2:
                e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
                for i in range(e_phnum):
                    off = e_phoff + i * e_phentsize
                    if off + 56 > len(data):
                        break
                    p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = (
                        struct.unpack_from(endian + "IIQQQQQQ", data, off)
                    )
                    if p_type == _PT_LOAD:
                        load_segments.append((p_offset, p_vaddr, p_filesz))
                    elif p_type == _PT_DYNAMIC:
                        dynamic_offset = p_offset
                        dynamic_size = p_filesz
            elif ei_class == 1:
                e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
                for i in range(e_phnum):
                    off = e_phoff + i * e_phentsize
                    if off + 32 > len(data):
                        break
                    p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = (
                        struct.unpack_from(endian + "IIIIIIII", data, off)
                    )
                    if p_type == _PT_LOAD:
                        load_segments.append((p_offset, p_vaddr, p_filesz))
                    elif p_type == _PT_DYNAMIC:
                        dynamic_offset = p_offset
                        dynamic_size = p_filesz
        except struct.error:
            return [], 0, 0
        return load_segments, dynamic_offset, dynamic_size

    @staticmethod
    def _vaddr_to_offset(
        vaddr: int,
        segments: list[tuple[int, int, int]],
    ) -> int | None:
        for p_offset, seg_vaddr, p_filesz in segments:
            if seg_vaddr <= vaddr < seg_vaddr + p_filesz:
                return p_offset + (vaddr - seg_vaddr)
        return None

    def linked_libraries(self) -> list[LinkedLibrary]:
        data = self._load()
        parsed = self._parse_header(data)
        if parsed is None:
            return []
        ei_class, endian, _, _ = parsed
        load_segments, dynamic_offset, dynamic_size = self._load_segments(data)

        if not dynamic_offset or dynamic_offset + dynamic_size > len(data):
            return []

        strtab_vaddr = 0
        strtab_size = 0
        needed_indices: list[int] = []
        entry_size = 16 if ei_class == 2 else 8

        pos = dynamic_offset
        end = dynamic_offset + dynamic_size
        while pos + entry_size <= end:
            try:
                if ei_class == 2:
                    d_tag, d_val = struct.unpack_from(endian + "QQ", data, pos)
                else:
                    d_tag, d_val = struct.unpack_from(endian + "II", data, pos)
            except struct.error:
                break
            pos += entry_size
            if d_tag == _DT_NULL:
                break
            if d_tag == _DT_STRTAB:
                strtab_vaddr = d_val
            elif d_tag == _DT_STRSZ:
                strtab_size = d_val
            elif d_tag == _DT_NEEDED:
                needed_indices.append(d_val)

        if not strtab_vaddr or not needed_indices:
            return []

        strtab_off = self._vaddr_to_offset(strtab_vaddr, load_segments)
        if strtab_off is None:
            return []

        limit = strtab_size or (len(data) - strtab_off)
        libs: list[LinkedLibrary] = []
        for idx in needed_indices:
            start = strtab_off + idx
            if start >= len(data):
                continue
            end_idx = data.find(b"\x00", start, min(start + 256, strtab_off + limit))
            if end_idx == -1:
                continue
            name = data[start:end_idx].decode("ascii", errors="replace")
            if name:
                libs.append(LinkedLibrary(name=name))
        return libs

    @classmethod
    def linked_libraries_from_bytes(cls, data: bytes) -> list[LinkedLibrary]:
        """Parse DT_NEEDED from raw ELF bytes (no file required)."""
        analyzer = cls.__new__(cls)
        analyzer.path = Path()
        analyzer._data = data
        return analyzer.linked_libraries()

    def scan_strings(
        self,
        patterns: list[tuple[str, re.Pattern[bytes]]],
        *,
        max_scan: int = 32_000_000,
    ) -> list[StringMatch]:
        matches: list[StringMatch] = []
        with self.path.open("rb") as fh:
            try:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    scan_data = mm[: min(len(mm), max_scan)]
                    for pattern_id, regex in patterns:
                        for m in regex.finditer(scan_data):
                            matched = m.group(0).decode("ascii", errors="replace")
                            matches.append(
                                StringMatch(
                                    pattern_id=pattern_id,
                                    matched=matched,
                                    offset=m.start(),
                                )
                            )
            except (ValueError, OSError):
                data = self._load()[:max_scan]
                for pattern_id, regex in patterns:
                    for m in regex.finditer(data):
                        matched = m.group(0).decode("ascii", errors="replace")
                        matches.append(
                            StringMatch(
                                pattern_id=pattern_id,
                                matched=matched,
                                offset=m.start(),
                            )
                        )
        return matches

    @classmethod
    def scan_bytes(
        cls,
        data: bytes,
        patterns: list[tuple[str, re.Pattern[bytes]]],
        *,
        max_scan: int = 32_000_000,
    ) -> list[StringMatch]:
        """Scan raw bytes without a file on disk."""
        matches: list[StringMatch] = []
        scan_data = data[: min(len(data), max_scan)]
        for pattern_id, regex in patterns:
            for m in regex.finditer(scan_data):
                matched = m.group(0).decode("ascii", errors="replace")
                matches.append(
                    StringMatch(
                        pattern_id=pattern_id,
                        matched=matched,
                        offset=m.start(),
                    )
                )
        return matches

    @classmethod
    def is_elf(cls, data: bytes) -> bool:
        return len(data) >= 4 and data[:4] == b"\x7fELF"
