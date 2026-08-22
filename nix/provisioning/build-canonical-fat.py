#!/usr/bin/env python3
"""Build the closed outer FAT32 profile verified by mediacontract.

This is a build-time serializer, not a general FAT implementation. It emits
one root directory cluster, one exact label, four files in fixed order, exact
contiguous allocation, normalized 1980 dates, and zero in every unowned byte.
"""

import argparse
import os
import struct


SECTOR_BYTES = 512
RESERVED_SECTORS = 32
FAT_COUNT = 2
ROOT_CLUSTER = 2
END_OF_CHAIN = 0x0FFFFFFF
CANONICAL_DATE = 0x0021
VOLUME_ID = 0x4B414942
LABEL = b"KAIBA_BOOT "

FILES = (
    ("boot.img", b"BOOT    IMG", True),
    ("boot.sig", b"BOOT    SIG", True),
    ("config.txt", b"CONFIG  TXT", True),
    ("kaiba-media-binding.json", b"KAIBA-~1JSO", False),
)


def put16(buffer, offset, value):
    struct.pack_into("<H", buffer, offset, value)


def put32(buffer, offset, value):
    struct.pack_into("<I", buffer, offset, value)


def lfn_checksum(short_name):
    value = 0
    for byte in short_name:
        value = (((value >> 1) | ((value & 1) << 7)) + byte) & 0xFF
    return value


def lfn_entries(name, short_name):
    units = [ord(character) for character in name] + [0]
    count = (len(units) + 12) // 13
    units.extend([0xFFFF] * (count * 13 - len(units)))
    checksum = lfn_checksum(short_name)
    entries = []
    slots = ((1, 5), (14, 6), (28, 2))
    for ordinal in range(count, 0, -1):
        entry = bytearray(32)
        entry[0] = ordinal | (0x40 if ordinal == count else 0)
        entry[11] = 0x0F
        entry[13] = checksum
        chunk = units[(ordinal - 1) * 13 : ordinal * 13]
        index = 0
        for offset, slot_count in slots:
            for slot in range(slot_count):
                put16(entry, offset + slot * 2, chunk[index])
                index += 1
        entries.append(entry)
    return entries


def directory_entry(short_name, lowercase, first_cluster, size):
    entry = bytearray(32)
    entry[0:11] = short_name
    entry[11] = 0x20
    if lowercase:
        entry[12] = 0x18
    put16(entry, 16, CANONICAL_DATE)
    put16(entry, 18, CANONICAL_DATE)
    put16(entry, 20, first_cluster >> 16)
    put16(entry, 24, CANONICAL_DATE)
    put16(entry, 26, first_cluster & 0xFFFF)
    put32(entry, 28, size)
    return entry


def fat_geometry(total_sectors):
    sectors_per_cluster = 1
    sectors_per_fat = 1
    for _ in range(64):
        data_sectors = total_sectors - RESERVED_SECTORS - FAT_COUNT * sectors_per_fat
        if data_sectors <= 0:
            raise ValueError("FAT metadata consumes the whole filesystem")
        cluster_count = data_sectors // sectors_per_cluster
        required = ((cluster_count + 2) * 4 + SECTOR_BYTES - 1) // SECTOR_BYTES
        if required == sectors_per_fat:
            break
        sectors_per_fat = required
    else:
        raise ValueError("FAT geometry did not converge")
    data_sectors = total_sectors - RESERVED_SECTORS - FAT_COUNT * sectors_per_fat
    cluster_count = data_sectors // sectors_per_cluster
    if cluster_count < 65525 or cluster_count > 0x0FFFFFF5:
        raise ValueError("filesystem size is outside the canonical FAT32 range")
    if sectors_per_fat * SECTOR_BYTES > 64 * 1024 * 1024:
        raise ValueError("FAT allocation table exceeds verifier bound")
    return sectors_per_cluster, sectors_per_fat, cluster_count


def boot_sector(total_sectors, sectors_per_cluster, sectors_per_fat):
    sector = bytearray(SECTOR_BYTES)
    sector[0:3] = bytes((0xEB, 0x58, 0x90))
    sector[3:11] = b"KAIBA   "
    put16(sector, 11, SECTOR_BYTES)
    sector[13] = sectors_per_cluster
    put16(sector, 14, RESERVED_SECTORS)
    sector[16] = FAT_COUNT
    sector[21] = 0xF8
    put16(sector, 24, 32)
    put16(sector, 26, 8)
    put32(sector, 32, total_sectors)
    put32(sector, 36, sectors_per_fat)
    put32(sector, 44, ROOT_CLUSTER)
    put16(sector, 48, 1)
    put16(sector, 50, 6)
    sector[64] = 0x80
    sector[66] = 0x29
    put32(sector, 67, VOLUME_ID)
    sector[71:82] = LABEL
    sector[82:90] = b"FAT32   "
    sector[510:512] = bytes((0x55, 0xAA))
    return sector


def fsinfo_sector():
    sector = bytearray(SECTOR_BYTES)
    put32(sector, 0, 0x41615252)
    put32(sector, 484, 0x61417272)
    put32(sector, 488, 0xFFFFFFFF)
    put32(sector, 492, 0xFFFFFFFF)
    put32(sector, 508, 0xAA550000)
    return sector


def write_at(output, offset, data):
    output.seek(offset)
    written = output.write(data)
    if written != len(data):
        raise OSError("short write while serializing FAT image")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-bytes", required=True, type=int)
    parser.add_argument("--output", required=True)
    parser.add_argument("--boot-image", required=True)
    parser.add_argument("--boot-signature", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--media-binding", required=True)
    arguments = parser.parse_args()

    if arguments.size_bytes <= 0 or arguments.size_bytes % SECTOR_BYTES != 0:
        raise ValueError("FAT size must be a positive whole number of sectors")
    total_sectors = arguments.size_bytes // SECTOR_BYTES
    if total_sectors > 0xFFFFFFFF:
        raise ValueError("FAT sector count exceeds the canonical 32-bit BPB")

    paths = (
        arguments.boot_image,
        arguments.boot_signature,
        arguments.config,
        arguments.media_binding,
    )
    sizes = []
    for path in paths:
        stat = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path) or stat.st_size <= 0 or stat.st_size > 0xFFFFFFFF:
            raise ValueError(f"input is not one non-empty bounded regular file: {path}")
        sizes.append(stat.st_size)

    sectors_per_cluster, sectors_per_fat, cluster_count = fat_geometry(total_sectors)
    cluster_bytes = sectors_per_cluster * SECTOR_BYTES
    cluster_counts = [(size + cluster_bytes - 1) // cluster_bytes for size in sizes]
    if ROOT_CLUSTER + sum(cluster_counts) >= cluster_count + 2:
        raise ValueError("canonical files do not fit in the FAT data area")

    first_clusters = []
    next_cluster = ROOT_CLUSTER + 1
    for count in cluster_counts:
        first_clusters.append(next_cluster)
        next_cluster += count

    allocation = bytearray(sectors_per_fat * SECTOR_BYTES)
    put32(allocation, 0, 0x0FFFFFF8)
    put32(allocation, 4, END_OF_CHAIN)
    put32(allocation, ROOT_CLUSTER * 4, END_OF_CHAIN)
    for first, count in zip(first_clusters, cluster_counts):
        for index in range(count):
            cluster = first + index
            put32(allocation, cluster * 4, cluster + 1 if index + 1 < count else END_OF_CHAIN)

    root = bytearray(cluster_bytes)
    label_entry = bytearray(32)
    label_entry[0:11] = LABEL
    label_entry[11] = 0x08
    put16(label_entry, 16, CANONICAL_DATE)
    put16(label_entry, 18, CANONICAL_DATE)
    put16(label_entry, 24, CANONICAL_DATE)
    entries = [label_entry]
    for (name, short_name, lowercase), first, size in zip(FILES, first_clusters, sizes):
        if name == "kaiba-media-binding.json":
            entries.extend(lfn_entries(name, short_name))
        entries.append(directory_entry(short_name, lowercase, first, size))
    directory_bytes = b"".join(entries)
    if len(directory_bytes) + 32 > len(root):
        raise ValueError("canonical root directory does not fit in one cluster")
    root[: len(directory_bytes)] = directory_bytes

    os.makedirs(os.path.dirname(arguments.output), exist_ok=True)
    with open(arguments.output, "w+b") as output:
        output.truncate(arguments.size_bytes)
        boot = boot_sector(total_sectors, sectors_per_cluster, sectors_per_fat)
        fsinfo = fsinfo_sector()
        write_at(output, 0, boot)
        write_at(output, SECTOR_BYTES, fsinfo)
        write_at(output, 6 * SECTOR_BYTES, boot)
        write_at(output, 7 * SECTOR_BYTES, fsinfo)
        first_fat_offset = RESERVED_SECTORS * SECTOR_BYTES
        write_at(output, first_fat_offset, allocation)
        write_at(output, first_fat_offset + len(allocation), allocation)
        data_offset = (RESERVED_SECTORS + FAT_COUNT * sectors_per_fat) * SECTOR_BYTES
        write_at(output, data_offset, root)
        for path, first in zip(paths, first_clusters):
            output.seek(data_offset + (first - ROOT_CLUSTER) * cluster_bytes)
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    if output.write(chunk) != len(chunk):
                        raise OSError("short write while copying FAT payload")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(arguments.output, 0o444)


if __name__ == "__main__":
    main()
