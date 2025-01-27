from typing import Literal, Generator, Callable
from itertools import groupby

from .util import pack16, addr16, fletcher16
from .util import hexstring
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
        dst_addr = addr16(delta[8:10])
        dst = b''.join(list(self._dec(delta[10:], dst_addr)))
        open('tmp.dat', 'wb').write(dst)
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
            + b''.join(list(self._enc(dst, dst_addr, chunk_size)))
            + pack16(fletcher16(dst))
        )

    @staticmethod
    def _pack_op(v: int, n: int) -> bytes:
        assert n > 0
        return bytes([v | n]) if n < 64 else (bytes([v]) + pack16(n))

    @staticmethod
    def _encode_op(op: Literal['CPY', 'RPL', 'RLO', 'ADD', 'SKP', 'END'], n = 0, data: bytes | None = None) -> bytes:
        assert (op == 'END' and n == 0) or n > 0 or (op == 'SKP' and n < 0)

        match op:
            case 'END':
                assert n == 0
                return bytes([0])
            case 'CPY':
                return Delta16._pack_op(0b0100_0000, n)
            case 'ADD':
                assert data and len(data) >= n
                return Delta16._pack_op(0b1000_0000, n) + data[:n]
            case 'SKP':
                return Delta16._pack_op(0b1100_0000, (n + 0x10000) & 0xffff)
            case 'RPL':
                assert data and len(data) >= n
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

        entries: list[IndexMapping] = []
        entry: IndexMapping = None
        relocate: Callable[[int], int] = lambda x: x   # dummy for first pass

        for ready in range(2):
            data = bytearray(delta)
            i_src, i_dst = 0, 0
            while True:
                op, n = self._decode_op(data)

                if ready:
                    pass
                    # print(f"{op} {n}".ljust(16), f"{hexstring(data[:4])} ...".ljust(16), f"{i_dst:04x}  {i_src:04x}: {hexstring(self.src[i_src:][:4])} ...")

                if not ready:
                    # start or finish a relocation table entry?
                    if entry and op in ('ADD', 'SKP', 'END'):
                        entry = entry._replace(length = i_src - entry.start)
                        entries.append(entry)
                        entry = None
                    elif entry is None and op not in ('ADD', 'SKP', 'END'):   # CPY, RPL, RLO, SKP
                        entry = IndexMapping(i_src, i_dst-i_src, 0)

                match op:
                    case 'END':
                        # second pass?
                        if not ready:
                            break
                        else:
                            return
                    case 'CPY':
                        if ready:
                            yield self.src[i_src:][:n]
                        i_src += n
                        i_dst += n
                    case 'ADD':
                        if ready:
                            yield data[:n]
                        data = data[n:]
                        i_dst += n
                    case 'SKP':
                        if ready:
                            yield bytes()
                        i_src += n
                        i_src &= 0xffff
                    case 'RPL':
                        if ready:
                            yield data[:n]
                        data = data[n:]
                        i_src += n
                        i_dst += n
                    case 'RLO':
                        if ready:
                            yield b''.join(pack16(relocate(addr16(self.src[i_src + 2*i:]))) for i in range(n))
                        i_src += 2*n
                        i_dst += 2*n

            print('inferred entries', entries)
            relocate = RelocationTable(
                entries, addr_start = self.src_addr, addr_offset = dst_addr - self.src_addr
            ).relocate

    def _enc(self, dst: bytes, dst_addr: int, block_size=64) -> Generator[bytes, None, None]:
        i_src, i_dst = 0, 0

        def debug(op, n):
            pass
            # print(f"{op} {n}".ljust(16), f"{i_dst:04x}: {hexstring(dst[i_dst:][:4])} ...".ljust(24), f"{i_src:04x}: {hexstring(self.src[i_src:][:4])} ...")

        fragments = find_fragments(dst, self.src, block_size=block_size)
        print('actual entries', fragments)
        relocate = RelocationTable(
            fragments, addr_start = self.src_addr, addr_offset = dst_addr - self.src_addr
        ).relocate

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
                debug('ADD', n_dst)
                yield self._encode_op('ADD', n_dst, dst[i_dst:])
                i_dst += n_dst

            if n_src != 0:
                debug('SKP', n_src)
                yield self._encode_op('SKP', n_src)
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
                n = len(list(g))
                op = {0: 'CPY', 1: 'RPL', 2: 'RLO'}[v]
                debug(op, n)
                yield self._encode_op(op, n, dst[i_dst:])
                i_dst += n
                i_src += n

            assert i_dst >= fragment.map_end, "Failed to consume fragment"

        assert i_dst == len(dst)
        debug('END', 0)
        yield self._encode_op('END')