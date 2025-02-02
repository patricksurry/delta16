from typing import Generator
from itertools import groupby

from .inst import Instruction
from .util import pack16, addr16, fletcher16
from .util import find_fragments
from .util import RelocationTable, IndexMapping


class Delta16:
    def __init__(self, src: bytes, src_addr = 0):
        self.src = src
        self.src_addr = src_addr
        self.rtab = RelocationTable()

    def decode(self, delta: bytes) -> bytes:
        # confirm the delta is valid and applies to this source
        assert addr16(delta[0:2]) == 0x0d16
        assert addr16(delta[2:4]) == self.src_addr
        assert addr16(delta[4:6]) == len(self.src)
        assert addr16(delta[6:8]) == fletcher16(self.src)
        dst_addr = addr16(delta[8:10])
        dst = b''.join(list(self._decode(delta[10:-2], dst_addr)))
        assert addr16(delta[-2:]) == fletcher16(dst)
        return dst

    def encode(self, dst: bytes, dst_addr: int | None = None, chunk_size=64) -> bytes:
        if dst_addr is None:
            dst_addr = self.src_addr

        return (
              pack16(0x0d16)
            + pack16(self.src_addr)
            + pack16(len(self.src))
            + pack16(fletcher16(self.src))
            + pack16(dst_addr)
            + b''.join(inst.encode() for inst in self._encode(dst, dst_addr, chunk_size))
            + pack16(fletcher16(dst))
        )

    def _decode(self, delta: bytes, dst_addr: int) -> Generator[bytes, None, None]:

        entries: list[IndexMapping] = []
        entry: IndexMapping = None

        # for first pass use a dummy table that uses identity mapping
        self.rtab = RelocationTable.identity()

        for ready in range(2):
            data = bytearray(delta)
            i_src, i_dst = 0, 0
            while True:
                inst, data = Instruction.decode(data)

                if not ready:
                    # start or finish a relocation table entry?
                    if entry and inst.op in ('INS', 'SKP', 'END'):
                        entry = entry._replace(length = i_src - entry.start)
                        entries.append(entry)
                        entry = None
                    elif entry is None and inst.op not in ('INS', 'SKP', 'END'):   # CPx, RPL, MOV, SKP
                        entry = IndexMapping(i_src, i_dst-i_src, 0)

                if inst.op == 'END':
                    assert not data, f"decode: unexpected data[{len(data)}] after END"
                    # next pass
                    break

                decoded, i_dst, i_src = inst.apply(self.src, i_dst, i_src, self.rtab.relocate)
                if ready:
                    yield decoded

            if not ready:
                self.rtab = RelocationTable(
                    entries,
                    addr_start = self.src_addr,
                    addr_offset = dst_addr - self.src_addr
                )

    def _encode(self, dst: bytes, dst_addr: int, block_size=64) -> Generator[Instruction, None, None]:
        """post-process the simple instruction stream with merge options"""
        prev: Instruction | None = None
        for next in self._encbase(dst, dst_addr, block_size):
            if prev:
                if merged := prev.elide(next):
                    prev = merged
                    next = None
                yield prev
            prev = next

        yield prev

    def _encbase(self, dst: bytes, dst_addr: int, block_size=64) -> Generator[Instruction, None, None]:
        i_src, i_dst = 0, 0

        fragments = find_fragments(dst, self.src, block_size=block_size)
        self.rtab = RelocationTable(
            fragments,
            addr_start = self.src_addr,
            addr_offset = dst_addr - self.src_addr
        )

        # mark the end with an empty fragment
        fragments.append(IndexMapping(start=0, length=0, offset=len(dst)))
        while fragments:
            fragment = fragments.pop(0)
            # handle non-aligned section before next fragment
            n_dst = fragment.map_start - i_dst
            n_src = 0 if fragment.empty else fragment.start - i_src

            # note dt must be non-negative, but dr is arbitrary
            assert n_dst >= 0, f"fragments not sequential for target"

            if n_dst > 0:
                yield Instruction('INS', n_dst, dst[i_dst:i_dst+n_dst])
                i_dst += n_dst

            if n_src != 0:
                yield Instruction('SKP', n_src)
                i_src += n_src

            assert i_dst == fragment.map_start and (fragment.empty or i_src == fragment.start)

            # done?
            if fragment.empty:
                assert fragment.map_start == len(dst), f"unaligned footer fragment"
                break

            # deal with the aligned section

            # analyze the tail beyond the fragments for relocations
            tail = min(fragments[0].map_start - fragment.map_end, len(self.src) - fragment.end)
            # calculate the difference between the fragments
            # construct a sequence of values 0=match, 1=diff, 2=reloc

            n = fragment.length + tail
            dst_frag = dst[fragment.map_start:][:n]
            src_frag = self.src[fragment.start:][:n]
            diff = bytearray([1 if x != y else 0 for (x, y) in zip(dst_frag, src_frag)])
            for (i, d) in enumerate(diff):
                if d != 1:
                    # only consider differences for relocation
                    continue
                if i > 0 and diff[i-1] == 1 and (
                        addr16(dst_frag[i-1:]) == self.rtab.relocate(addr16(src_frag[i-1:]))
                    ):
                    diff[i-1:i+1] = bytes([2,2])
                elif i+1 < len(diff) and (
                        addr16(dst_frag[i:]) == self.rtab.relocate(addr16(src_frag[i:]))
                    ):
                    diff[i:i+2] = bytes([2,2])
                elif i >= fragment.length:
                    # stop if we find a mismatched index in the tail that isn't relocatable
                    diff = diff[:i]
                    break

            # now we can simply run-length code the difference map
            for v, g in groupby(diff):
                n = len(list(g))
                match v:
                    case 0:
                        yield Instruction('CPY', n)
                    case 1:
                        yield Instruction('RPL', n, dst[i_dst:i_dst+n])
                    case 2:
                        assert n & 1 == 0, f"MOV acts on pairs, but n={n}"
                        yield Instruction('MOV', n >> 1)
                i_dst += n
                i_src += n

            assert i_dst >= fragment.map_end, "Failed to consume fragment"

        assert i_dst == len(dst)
        yield Instruction('END')