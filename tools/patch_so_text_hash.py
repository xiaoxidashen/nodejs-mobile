#!/usr/bin/env python3
"""
编译后回填 SO .text 哈希：
1) 解析 ELF，定位 .text section；
2) 计算 .text 的 SHA-256；
3) 通过固定魔数定位 hash 槽位并覆盖写入。
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

AG_SI_MAGIC = bytes([0xA6, 0x5D, 0xC2, 0x19, 0x7E, 0x34, 0xEB, 0x90])
AG_SI_HASH_SIZE = 32


# 生成与 so_self_integrity.c 中一致的占位符字节序列。
def ag_si_placeholder_hash() -> bytes:
    return bytes((((i * 0x3D + 0x27) ^ 0xA5) & 0xFF) for i in range(AG_SI_HASH_SIZE))


# 解析命令行参数并返回配置对象。
def ag_si_parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Patch SO .text hash slot.")
    parser.add_argument("--so", required=True, help="目标 so 文件路径")
    parser.add_argument("--output", help="输出路径；不传则原地覆盖")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="原地覆盖时不生成 .bak 备份",
    )
    return parser.parse_args()


# 按 ELF 位宽读取 section header 关键字段。
def ag_si_read_section_header(blob: bytes, shoff: int, shentsize: int, index: int, elf_class: int) -> tuple[int, int, int]:
    base = shoff + shentsize * index
    if elf_class == 2:
        fmt = "<IIQQQQIIQQ"
        need = struct.calcsize(fmt)
        if base + need > len(blob):
            raise ValueError("section header 越界（ELF64）")
        sh_name, _, _, _, sh_offset, sh_size, _, _, _, _ = struct.unpack_from(fmt, blob, base)
        return sh_name, sh_offset, sh_size

    fmt = "<IIIIIIIIII"
    need = struct.calcsize(fmt)
    if base + need > len(blob):
        raise ValueError("section header 越界（ELF32）")
    sh_name, _, _, _, sh_offset, sh_size, _, _, _, _ = struct.unpack_from(fmt, blob, base)
    return sh_name, sh_offset, sh_size


# 解析 ELF 并返回 .text 的文件偏移和长度。
def ag_si_find_text_section(blob: bytes) -> tuple[int, int]:
    if len(blob) < 16 or blob[0:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件")

    elf_class = blob[4]
    elf_data = blob[5]
    if elf_data != 1:
        raise ValueError("仅支持小端 ELF")

    if elf_class == 2:
        if len(blob) < 64:
            raise ValueError("ELF64 头长度不足")
        e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    elif elf_class == 1:
        if len(blob) < 52:
            raise ValueError("ELF32 头长度不足")
        e_shoff = struct.unpack_from("<I", blob, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", blob, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", blob, 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", blob, 0x32)[0]
    else:
        raise ValueError("不支持的 ELF class")

    if e_shnum == 0:
        raise ValueError("section 数量为 0，暂不支持扩展索引")
    if e_shstrndx >= e_shnum:
        raise ValueError("shstrndx 非法")
    if e_shoff <= 0 or e_shentsize <= 0:
        raise ValueError("section header 表无效")
    if e_shoff + e_shentsize * e_shnum > len(blob):
        raise ValueError("section header 表越界")

    _, shstr_off, shstr_size = ag_si_read_section_header(blob, e_shoff, e_shentsize, e_shstrndx, elf_class)
    if shstr_off + shstr_size > len(blob):
        raise ValueError("shstrtab 越界")
    shstr = blob[shstr_off : shstr_off + shstr_size]

    for i in range(e_shnum):
        sh_name, sec_off, sec_size = ag_si_read_section_header(blob, e_shoff, e_shentsize, i, elf_class)
        if sh_name >= len(shstr):
            continue
        end = shstr.find(b"\x00", sh_name)
        if end < 0:
            continue
        name = shstr[sh_name:end]
        if name == b".text":
            if sec_size == 0:
                raise ValueError(".text 长度为 0")
            if sec_off + sec_size > len(blob):
                raise ValueError(".text 越界")
            return sec_off, sec_size

    raise ValueError("未找到 .text section")


# 统计魔数出现次数并返回唯一位置。
def ag_si_find_unique_magic(blob: bytes) -> int:
    first = blob.find(AG_SI_MAGIC)
    if first < 0:
        raise ValueError("未找到 hash 槽位魔数")
    second = blob.find(AG_SI_MAGIC, first + 1)
    if second >= 0:
        raise ValueError("找到多个 hash 槽位魔数，无法唯一定位")
    return first


# 按魔数位置覆盖写入 hash，并返回新字节数组与偏移信息。
def ag_si_patch_slot(blob: bytes, digest: bytes) -> tuple[bytes, int, int]:
    if len(digest) != AG_SI_HASH_SIZE:
        raise ValueError("digest 长度不是 32 字节")

    magic_off = ag_si_find_unique_magic(blob)
    hash_off = magic_off + len(AG_SI_MAGIC)
    hash_end = hash_off + AG_SI_HASH_SIZE
    if hash_end > len(blob):
        raise ValueError("hash 槽位越界")

    patched = bytearray(blob)
    patched[hash_off:hash_end] = digest
    return bytes(patched), magic_off, hash_off


# 原地写入时按需生成备份文件，避免误覆盖不可恢复。
def ag_si_backup_if_needed(src: Path, original: bytes, no_backup: bool) -> None:
    if no_backup:
        return
    backup = Path(str(src) + ".bak")
    if backup.exists():
        return
    backup.write_bytes(original)


# 执行完整回填流程并输出结果摘要。
def ag_si_main() -> None:
    args = ag_si_parse_args()
    so_path = Path(args.so)
    if not so_path.exists():
        raise FileNotFoundError(f"so 文件不存在: {so_path}")

    original = so_path.read_bytes()
    text_off, text_size = ag_si_find_text_section(original)
    digest = hashlib.sha256(original[text_off : text_off + text_size]).digest()

    patched, magic_off, hash_off = ag_si_patch_slot(original, digest)

    output_path = Path(args.output) if args.output else so_path
    if output_path.resolve() == so_path.resolve():
        ag_si_backup_if_needed(so_path, original, args.no_backup)
    output_path.write_bytes(patched)

    placeholder = ag_si_placeholder_hash().hex()
    print(f"so: {so_path}")
    print(f".text offset={text_off} size={text_size}")
    print(f"slot magic offset={magic_off}, hash offset={hash_off}")
    print(f"placeholder(default)={placeholder}")
    print(f"patched sha256={digest.hex()}")
    print(f"output: {output_path}")


if __name__ == "__main__":
    ag_si_main()

