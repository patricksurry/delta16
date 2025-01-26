from typing import Literal, Generator
from itertools import groupby

from .util import pack16, addr16, fletcher16
from .util import find_fragments
from .util import RelocationTable, IndexMapping


class Delta16:
    def __init__(self, src: bytes, src_addr = 0):
        self.src = src
        self.src_addr = src_addr

    def decode(self, delta: bytes) -> bytes:
        # confirm the delta is valid and applies to this source
        assert addr16(delta[0:2]) == 0x0d16
        assert addr16(delta[2:4]) == self.src_addr
        assert addr16(delta[4:6]) == len(self.src)
        assert addr16(delta[6:8]) == fletcher16(self.src)

        # build relocation table
        dst_addr = addr16(delta[8:10])
        dst = b''.join(list(self._dec(delta[10:], dst_addr)))
        print(self.src)
        print(dst)
        assert addr16(delta[-2:]) == fletcher16(dst)
        return dst

    def encode(self, dst: bytes, dst_addr = None, chunk_size=64) -> bytes:
        if dst_addr is None:
            dst_addr = self.src_addr

        return (
              pack16(0x0d16)
            + pack16(self.src_addr)
            + pack16(len(self.src))
            + pack16(fletcher16(self.src))
            + pack16(dst_addr)
            + b''.join(list(self._enc(dst, dst_addr, chunk_size)))
            + pack16(fletcher16(dst))
        )

    @staticmethod
    def _pack_op(v: int, n: int) -> bytes:
        assert n > 0
        return bytes([v | n]) if n < 64 else (bytes([v]) + pack16(n))

    def _encode_op(self, op: Literal['CPY', 'RPL', 'RLO', 'ADD', 'SKP', 'END'], n = 0) -> bytes:
        assert (op == 'END' and n == 0) or n > 0 or op == 'SKP'
        data = self.dst[self.dst_offset:]
        if op in ('CPY', 'RPL', 'RLO', 'ADD'):
            self.dst_offset += n
        if op in ('CPY', 'RPL', 'RLO', 'SKP'):
            self.src_offset += n

        match op:
            case 'END':
                assert n == 0
                return bytes([0])
            case 'CPY':
                return self._pack_op(0b0100_0000, n)
            case 'ADD':
                assert len(data) >= n
                return self._pack_op(0b1000_0000, n) + data[:n]
            case 'SKP':
                return self._pack_op(0b1100_0000, (n + 0x10000) & 0xffff)
            case 'RPL':
                assert len(data) >= n
                q, r = divmod(n, 31)
                return bytes([0b0001_1111] * q + [0b0000_0000 | r]) + data[:n]
            case 'RLO':
                assert n & 1 == 0, "RLO must have even argument"
                q, r = divmod(n>>1, 31)
                return bytes([0b0011_1111] * q + [0b0010_0000 | r])

    @staticmethod
    def _decode_op(data: bytearray) -> tuple[str, int]:
        op = None
        v = data.pop(0)
        if v == 0:
            return ('END', 0)

        n = v & (0b0011_1111 if v & 0b1100_0000 else 0b0001_1111)
        if not n:
            n = addr16(data)
            data.pop(0)
            data.pop(0)

        match v & 0b1100_0000:
            case 0b0000_0000:
                op = 'RLO' if v & 0b0010_0000 else 'RPL'
            case 0b0100_0000:
                op = 'CPY'
            case 0b1000_0000:
                op = 'ADD'
            case 0b1100_0000:
                op = 'SKP'

        return (op, n)


    def _dec(self, delta: bytes, dst_addr: int) -> Generator[bytes, None, None]:
        delta = bytearray(delta)
        self.src_offset, self.dst_offset = 0, 0
        # TODO relocation
        while True:
            op, n = self._decode_op(delta)
            match op:
                case 'END':
                    return
                case 'CPY':
                    yield self.src[self.src_offset:][:n]
                    self.src_offset += n
                    self.dst_offset += n
                case 'ADD':
                    yield delta[:n]
                    delta = delta[n:]
                    self.dst_offset += n
                case 'SKP':
                    yield bytes()
                    self.src_offset += n
                    self.src_offset &= 0xffff
                case 'RPL':
                    yield delta[:n]
                    delta = delta[n:]
                    self.src_offset += n
                    self.dst_offset += n
                case 'RLO':
                    #TODO
                    yield b''.join(pack16(addr16(self.src[self.src_offset + 2*i:])) for i in range(n))
                    self.src_offset += 2*n
                    self.dst_offset += 2*n


    def _enc(self, dst: bytes, dst_addr: int, block_size=64) -> Generator[bytes, None, None]:
        self.src_offset, self.dst_offset = 0, 0
        self.dst = dst

        fragments = find_fragments(self.dst, self.src, block_size=block_size)

        relocate = RelocationTable(
            fragments, addr_start = self.src_addr, addr_offset = dst_addr - self.src_addr
        ).relocate

        # mark the end with an empty fragment
        fragments.append(IndexMapping(start=0, length=0, offset=len(self.dst)))
        while fragments:
            fragment = fragments.pop(0)
            # handle non-aligned section before next fragment
            dst_n = fragment.map_start - self.dst_offset
            src_n = 0 if fragment.empty else fragment.start - self.src_offset

            # note dt must be non-negative, but dr is arbitrary
            assert dst_n >= 0, f"fragments not sequential for target"

            if dst_n > 0:
                yield self._encode_op('ADD', dst_n)
            if src_n != 0:
                yield self._encode_op('SKP', src_n)

            assert self.dst_offset == fragment.map_start and (fragment.empty or self.src_offset == fragment.start)

            # done?
            if fragment.empty:
                assert fragment.map_start == len(self.dst), f"unaligned footer fragment"
                break

            # deal with the aligned section

            # analyze the tail beyond the fragments for relocations
            tail = min(fragments[0].map_start - fragment.map_end, len(self.src) - fragment.end)
            # calculate the difference between the fragments
            # construct a sequence of values 0=match, 1=diff, 2=reloc

            n = fragment.length + tail
            dst_frag = self.dst[fragment.map_start:][:n]
            src_frag = self.src[fragment.start:][:n]
            diff = bytearray([1 if x != y else 0 for (x, y) in zip(dst_frag, src_frag)])
            for (i, d) in enumerate(diff):
                if d != 1:
                    # only consider differences for relocation
                    continue
                if i > 0 and diff[i-1] == 1 and (
                        addr16(dst_frag[i-1:]) == relocate(addr16(src_frag[i-1:]))
                    ):
                    diff[i-1:i+1] = bytes([2,2])
                elif i+1 < len(diff) and (
                        addr16(dst_frag[i:]) == relocate(addr16(src_frag[i:]))
                    ):
                    diff[i:i+2] = bytes([2,2])
                elif i >= fragment.length:
                    # stop if we find a mismatched index in the tail that isn't relocatable
                    diff = diff[:i]
                    break

            if fragment.length != len(diff):
                print(f"Extended fragment to length {len(diff)} > {fragment.length} with tail {tail}")

            # now we can simply run-length code the difference map
            for v, g in groupby(diff):
                dst_n = len(list(g))
                yield self._encode_op({0: 'CPY', 1: 'RPL', 2: 'RLO'}[v], dst_n)

            assert self.dst_offset >= fragment.map_end, "Failed to consume fragment"

        assert self.dst_offset == len(dst)
        yield self._encode_op('END')