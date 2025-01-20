import concurrent.futures
import os
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple, Tuple

import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_segment
import idaapi


@dataclass
class StructPatterns:
    class_t: struct.Struct = struct.Struct("<QQQQQ")
    class_ro_t: struct.Struct = struct.Struct("<IIIIQQQQQQQ")
    method_t: struct.Struct = struct.Struct("<iii")
    ptr: struct.Struct = struct.Struct("<Q")


PATTERNS = StructPatterns()


class MemoryBlock(NamedTuple):
    """Store pre-fetched memory block and its address range."""

    start_addr: int
    data: bytes
    size: int

    def contains(self, addr: int) -> bool:
        return self.start_addr <= addr < self.start_addr + self.size

    def get_offset(self, addr: int) -> int:
        return addr - self.start_addr


class MemoryRegion:
    """Manage a collection of memory blocks.
    IDA APIs can only be called from the main thread, so worker threads
    operate on these pre-fetched memory blocks.
    """

    def __init__(self, blocks: list[MemoryBlock]):
        self.blocks = blocks

    def read_bytes(self, addr: int, size: int) -> bytes | None:
        for block in self.blocks:
            if block.contains(addr) and block.contains(addr + size - 1):
                offset = block.get_offset(addr)
                return block.data[offset : offset + size]
        return None


@lru_cache(maxsize=10000)
def get_string(ea: int) -> str | None:
    if result := ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C):
        return result.decode()

    # Failed to read the string directly. Maybe it's a pointer to a string
    if ptr := ida_bytes.get_qword(ea):
        if result := ida_bytes.get_strlit_contents(ptr, -1, ida_nalt.STRTYPE_C):
            return result.decode()
    return None


def fetch_memory_regions(class_ptrs: list[int]) -> list[MemoryBlock]:
    regions: list[MemoryBlock] = []
    if not class_ptrs:
        return regions

    addresses_to_read = set()
    for ptr in class_ptrs:
        addresses_to_read.add(ptr)

        # Read class struct
        data = ida_bytes.get_bytes(ptr, PATTERNS.class_t.size)
        isa, _, _, _, info = PATTERNS.class_t.unpack(data)
        info = (info >> 3) << 3
        addresses_to_read.add(isa)
        addresses_to_read.add(info)

        # Read class RO for class name and instance methods
        data = ida_bytes.get_bytes(info, PATTERNS.class_ro_t.size)
        class_ro = PATTERNS.class_ro_t.unpack(data)
        if class_ro[6]:  # methods list
            addresses_to_read.add(class_ro[6])

        # Meta class info
        meta_data = ida_bytes.get_bytes(isa, PATTERNS.class_t.size)
        _, _, _, _, meta_info = PATTERNS.class_t.unpack(meta_data)
        meta_info = (meta_info >> 3) << 3
        addresses_to_read.add(meta_info)
        meta_ro_data = ida_bytes.get_bytes(meta_info, PATTERNS.class_ro_t.size)
        meta_ro = PATTERNS.class_ro_t.unpack(meta_ro_data)
        if meta_ro[6]:
            addresses_to_read.add(meta_ro[6])

    # Group addresses into blocks of 4KB
    block_size = 4096
    sorted_addrs = sorted(addresses_to_read)
    current_block_start = sorted_addrs[0]
    current_block_end = current_block_start
    for addr in sorted_addrs:
        if addr > current_block_end + block_size:

            size = current_block_end - current_block_start
            if size > 0:
                data = ida_bytes.get_bytes(current_block_start, size)
                regions.append(MemoryBlock(current_block_start, data, size))
            current_block_start = addr
        current_block_end = max(current_block_end, addr + block_size)

    if current_block_end > current_block_start:
        size = current_block_end - current_block_start
        data = ida_bytes.get_bytes(current_block_start, size)
        regions.append(MemoryBlock(current_block_start, data, size))
    return regions


def process_class_batch(class_ptrs: list[int], memory: MemoryRegion) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for ptr in class_ptrs:
        try:
            if data := memory.read_bytes(ptr, PATTERNS.class_t.size):
                isa, superclass, _, _, info = PATTERNS.class_t.unpack(data)
                info = (info >> 3) << 3

                if ro_data := memory.read_bytes(info, PATTERNS.class_ro_t.size):
                    class_ro = PATTERNS.class_ro_t.unpack(ro_data)
                    methods_data = None
                    if class_ro[6]:
                        methods_data = memory.read_bytes(class_ro[6], 8)
                    results.append(
                        {
                            "ptr": ptr,
                            "isa": isa,
                            "superclass": superclass,
                            "info": info,
                            "methods_ptr": class_ro[6],
                            "methods_data": methods_data,
                            "name_ptr": class_ro[5],
                        }
                    )
        except Exception as exc:
            print(f"Failed to process class at {ptr}: {str(exc)}")
            continue
    return results


def fetch_method_regions(collected_info: list[dict[str, Any]]) -> list[MemoryBlock]:
    addresses_to_read: set[int] = set()
    for info in collected_info:
        if not info["methods_ptr"] or not info["methods_data"]:
            continue

        methods_ptr = info["methods_ptr"]
        addresses_to_read.add(methods_ptr)

        first_method = methods_ptr + 8
        method_count = struct.unpack("<I", info["methods_data"][4:8])[0]
        for i in range(method_count):
            method_addr = first_method + (i * 12)
            addresses_to_read.add(method_addr)
            addresses_to_read.add(method_addr + 12)

    regions: list[MemoryBlock] = []
    sorted_addrs = sorted(addresses_to_read)
    if not sorted_addrs:
        return regions

    block_size = 4096
    current_block_start = sorted_addrs[0]
    current_block_end = current_block_start
    for addr in sorted_addrs:
        if addr > current_block_end + block_size:
            size = current_block_end - current_block_start
            if size > 0:
                data = ida_bytes.get_bytes(current_block_start, size)
                regions.append(MemoryBlock(current_block_start, data, size))
            current_block_start = addr
        current_block_end = max(current_block_end, addr + block_size)

    if current_block_end > current_block_start:
        size = current_block_end - current_block_start
        data = ida_bytes.get_bytes(current_block_start, size)
        regions.append(MemoryBlock(current_block_start, data, size))

    return regions


def process_methods_batch(class_infos: list[dict[str, Any]], memory: MemoryRegion) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for info in class_infos:
        try:
            if not info["methods_ptr"] or not info["methods_data"]:
                continue

            methods_ptr = info["methods_ptr"]
            count = struct.unpack("<I", info["methods_data"][4:8])[0]
            first_method = methods_ptr + 8

            methods = []
            for i in range(count):
                method_addr = first_method + (i * 12)
                if method_data := memory.read_bytes(method_addr, PATTERNS.method_t.size):
                    name_offset, types_offset, imp_offset = PATTERNS.method_t.unpack(method_data)
                    methods.append(
                        {
                            "addr": method_addr,
                            "name_ptr": method_addr + name_offset,
                            "types_ptr": method_addr + types_offset,
                            "imp": method_addr + imp_offset,
                        }
                    )

            results.append(
                {"name_ptr": info["name_ptr"], "ptr": info["ptr"], "superclass": info["superclass"], "methods": methods}
            )

        except Exception as exc:
            print(f"Failed to process methods for class at {info['ptr']}: {str(exc)}")
            continue

    return results


def extract_all_classes() -> dict:
    start_time = time.time()

    classes: dict[str, dict] = {}
    if segment := ida_segment.get_segm_by_name("__objc_classlist"):

        segment_data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
        class_pointers: list[int] = []
        for i in range(0, len(segment_data), 8):
            if ptr := struct.unpack("<Q", segment_data[i : i + 8])[0]:
                class_pointers.append(ptr)

        # IDA APIs can only be called from the main thread, so all memory that will be needed
        # by the workers has be pre-fetched upfront before starting the worker threads
        ida_kernwin.replace_wait_box("HIDECANCEL\nPre-fetching memory regions...")
        memory_blocks = fetch_memory_regions(class_pointers)
        memory = MemoryRegion(memory_blocks)

        worker_count = os.cpu_count() or 1
        batch_size_per_worker = 2000
        class_batches = [
            class_pointers[i : i + batch_size_per_worker] for i in range(0, len(class_pointers), batch_size_per_worker)
        ]
        class_info = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            class_futures: list[concurrent.futures.Future] = []

            for batch in class_batches:
                class_futures.append(executor.submit(process_class_batch, batch, memory))

            for i, future in enumerate(as_completed(class_futures)):
                progress = int(i * 100 / len(class_batches))
                ida_kernwin.replace_wait_box(f"HIDECANCEL\nCollecting class info... ({progress}%)")
                class_info.extend(future.result())

        ida_kernwin.replace_wait_box("HIDECANCEL\nPre-fetching method memory regions...")
        method_blocks = fetch_method_regions(class_info)
        method_memory = MemoryRegion(method_blocks)

        method_batch_size = 5000
        method_batches = [class_info[i : i + method_batch_size] for i in range(0, len(class_info), method_batch_size)]
        total_methods_all_batches = sum(len(batch) for batch in method_batches)

        processed_classes: list[dict[str, Any]] = []
        completed_count = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            method_futures: list[concurrent.futures.Future] = []
            for batch in method_batches:
                method_futures.append(executor.submit(process_methods_batch, batch, method_memory))

            for i, future in enumerate(as_completed(method_futures)):
                completed_count += len(method_batches[i])
                progress = int(completed_count * 100 / total_methods_all_batches)
                ida_kernwin.replace_wait_box(
                    f"HIDECANCEL\nProcessing methods {completed_count}/{total_methods_all_batches}... ({progress}%)"
                )
                processed_classes.extend(future.result())

        total_methods = sum(len(info["methods"]) for info in processed_classes)
        processed_methods = 0
        for i, info in enumerate(processed_classes):
            try:
                if name := get_string(info["name_ptr"]):
                    methods = []
                    for method in info["methods"]:
                        processed_methods += 1
                        progress = int(processed_methods * 100 / total_methods)
                        ida_kernwin.replace_wait_box(
                            f"HIDECANCEL\nDecompiling methods {processed_methods}/{total_methods}... ({progress}%)"
                        )
                        if method_name := get_string(method["name_ptr"]):
                            try:
                                decompiled = str(ida_hexrays.decompile(method["imp"]))
                                methods.append(
                                    {
                                        "name": method_name,
                                        "type": get_string(method["types_ptr"]),
                                        "implementation": method["imp"],
                                        "decompiled": decompiled,
                                    }
                                )
                            except Exception as exc:
                                print(f"Failed to decompile method {method_name}: {str(exc)}")
                                continue

                    classes[name] = {
                        "name": name,
                        "address": info["ptr"],
                        "superclass": info["superclass"],
                        "methods": methods,
                    }
            except Exception as exc:
                print(f"Failed to process methods for class at {info['ptr']}: {str(exc)}")
                continue

        end_time = time.time()
        elapsed_seconds = end_time - start_time
        elapsed_minutes = elapsed_seconds / 60
        print("\nExtraction complete:")
        print(f"Total classes: {len(classes)}")
        print(f"Total methods: {total_methods_all_batches}")
        print(f"Time elapsed: {elapsed_minutes:.2f} minutes")
        print(f"Average extraction rate: {len(classes) / elapsed_seconds:.1f} classes/second")
        print(f"Average decompilation rate: {total_methods_all_batches / elapsed_seconds:.1f} methods/second")
    return classes


def generate_source_files(classes: dict, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    def process_class_file(item: Tuple[str, dict]):
        try:
            class_name, info = item
            output = [f"@implementation {class_name}\n"]

            if info.get("class_methods"):
                output.extend(m["decompiled"] for m in info["class_methods"])

            if info.get("methods"):
                output.extend(m["decompiled"] for m in info["methods"])

            output.append("\n@end\n")
            (output_dir / f"{class_name}.m").write_text("\n".join(output))
        except Exception as exc:
            print(f"Failed to write source file for {item[0]}: {str(exc)}")

    worker_count = os.cpu_count() or 1
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        list(executor.map(process_class_file, classes.items()))


class ObjCSourceExport(ida_idaapi.plugin_t):
    flags = 0
    comment = "Objc source export"
    help = comment
    wanted_name = "Export .m files"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self) -> int:
        if idaapi.IDA_SDK_VERSION < 900:
            ida_kernwin.warning("Objc Source Export is only tested on IDA 9")

        return ida_idaapi.PLUGIN_OK

    def run(self, _: Any) -> None:
        try:
            ida_kernwin.show_wait_box("HIDECANCEL\nGenerating .m files...")
            if not ida_hexrays.init_hexrays_plugin():
                return

            for_saving = True
            binary_name = ida_nalt.get_root_filename()
            output_file_dir_hint = f"{binary_name}_exported"
            if output_path := ida_kernwin.ask_file(for_saving, output_file_dir_hint, "Select output directory"):
                decompiled_class_details = extract_all_classes()
                generate_source_files(decompiled_class_details, Path(output_path))

        except Exception as e:
            ida_kernwin.warning(f"Failed to generate source files: {e}")
        finally:
            ida_kernwin.hide_wait_box()

    def term(self) -> None:
        pass


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:
    return ObjCSourceExport()
