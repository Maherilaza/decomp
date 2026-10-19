"""Windows PC programs (Portable Executable: .exe, .dll) and the compiler that built them.

A PE file opens with an `MZ` DOS stub and, at the offset stored at 0x3C, a `PE\\0\\0` signature
followed by the COFF and Optional headers. We read enough to describe the program and to guess
its compiler:

* MSVC writes a "Rich header" between the DOS stub and the PE signature: a XOR-masked list of
  `@comp.id` records, one per tool (compiler, assembler, linker) that touched the binary. Its
  product ids tell apart Visual C++ versions precisely, so it is the strongest signal.
* Without a Rich header, the Optional Header's linker version and the names of the sections
  (`.text`/`.rdata` for MSVC, a `.CRT`/`.bss` + GCC markers for MinGW) narrow it down.
"""

from __future__ import annotations

import hashlib
import struct

from .n64 import RomError

# Machine types we handle (COFF header, offset 4 of the PE header).
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
MACHINES = {IMAGE_FILE_MACHINE_I386: "x86", IMAGE_FILE_MACHINE_AMD64: "x86_64"}

# A few well-known MSVC Rich-header product ids -> Visual C++ marketing name. The id is the high
# 16 bits of each @comp.id record; the low 16 bits are the build number.
MSVC_PRODUCTS = {
    0x0A: "Visual C++ 6.0", 0x15: "Visual C++ 6.0",
    0x5D: "Visual C++ 7.0 (2002)", 0x6D: "Visual C++ 7.1 (2003)",
    0x83: "Visual C++ 8.0 (2005)", 0x9D: "Visual C++ 9.0 (2008)",
    0xAA: "Visual C++ 10.0 (2010)", 0xC9: "Visual C++ 11.0 (2012)",
    0xDB: "Visual C++ 12.0 (2013)", 0x104: "Visual C++ 14.0 (2015)",
    0x105: "Visual C++ 14.1x (2017)", 0x106: "Visual C++ 14.2x (2019)",
    0x107: "Visual C++ 14.3x (2022)",
}


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", data, 0x3C)[0]
    return 0 < off < len(data) - 4 and data[off:off + 4] == b"PE\x00\x00"


def _rich_header(data: bytes, pe_off: int) -> list[tuple[int, int, int]]:
    """The decoded @comp.id records (product_id, build, use_count), or [] if there is no
    Rich header. It ends with the ASCII tag `Rich` + a 4-byte XOR key; it starts at the
    `DanS` marker, which is the key XORed into the first dword."""
    blob = data[:pe_off]
    end = blob.rfind(b"Rich")
    if end < 0 or end + 8 > len(blob):
        return []
    key = struct.unpack_from("<I", blob, end + 4)[0]
    start = blob.rfind(b"DanS")
    if start < 0 or start >= end:
        # DanS is masked by the key; search for it decoded instead.
        for i in range(0, end, 4):
            if struct.unpack_from("<I", blob, i)[0] ^ key == 0x536E6144:  # "DanS"
                start = i
                break
        if start < 0:
            return []
    records = []
    for i in range(start + 16, end, 8):  # skip DanS + three padding dwords
        comp = struct.unpack_from("<I", blob, i)[0] ^ key
        count = struct.unpack_from("<I", blob, i + 4)[0] ^ key
        records.append((comp >> 16, comp & 0xFFFF, count))
    return records


def guess_compiler(data: bytes, pe_off: int, linker_major: int, sections: list[str]) -> tuple[str, str]:
    """(toolchain family id, human description). Family is one of MSVC, MINGW, CLANG."""
    for product, _build, _count in _rich_header(data, pe_off):
        if product in MSVC_PRODUCTS:
            return "MSVC", MSVC_PRODUCTS[product]
    if any(s in (".CRT", ".bss") for s in sections) or any(s.startswith(".debug_") for s in sections):
        return "MINGW", "GCC / MinGW"
    if linker_major:
        return "MSVC", f"MSVC-family linker {linker_major}.x"
    return "MSVC", "Unknown PC compiler"


def read_pe(data: bytes, name: str = "") -> tuple[bytes, dict]:
    """Describe a Windows program and guess its compiler. Returns (image bytes, info dict),
    matching the shape the other platforms return from read_* ."""
    if not is_pe(data):
        raise RomError("this isn't a Windows PC program (no MZ/PE header)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    machine, n_sections = struct.unpack_from("<HH", data, pe_off + 4)
    if machine not in MACHINES:
        raise RomError(f"unsupported PE machine 0x{machine:04X} (only x86 and x86-64 PC programs)")
    size_opt = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]  # 0x10B PE32, 0x20B PE32+
    linker_major, linker_minor = data[opt_off + 2], data[opt_off + 3]
    entry = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_base = (struct.unpack_from("<Q", data, opt_off + 24)[0] if magic == 0x20B
                  else struct.unpack_from("<I", data, opt_off + 28)[0])
    sec_off = opt_off + size_opt
    sections = []
    for i in range(n_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        sections.append(data[base:base + 8].split(b"\x00", 1)[0].decode("ascii", "replace"))
    family, description = guess_compiler(data, pe_off, linker_major, sections)
    title = (name.rsplit("/", 1)[-1] or "PC program").removesuffix(".exe").removesuffix(".EXE")
    return data, {
        "title": title, "game_code": "", "region": "PC", "version": 0,
        "entrypoint": image_base + entry, "gp": 0, "load": image_base, "size": len(data),
        "sha1": hashlib.sha1(data).hexdigest(), "byte_order": "pe", "platform": "pc",
        "arch": MACHINES[machine], "bits": 64 if magic == 0x20B else 32,
        "linker_version": f"{linker_major}.{linker_minor}", "sections": sections,
        "compiler_guess": family, "compiler_name": description, "boot": name,
    }
