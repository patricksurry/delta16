from typing import Literal, Generator, Callable
from itertools import groupby
import logging

from .util import pack16, addr16, fletcher16
from .util import hexstring
from .util import find_fragments
from .util import RelocationTable, IndexMapping


#TODO could use skp8/skp16 kind of thing?

Op = Literal['END', 'CPY', 'INS', 'SKP', 'RPL', 'MOV', 'CPR', 'CPM']

opmap: dict[Op, str] = dict(
    END='0000_0000',        # must match first

    CPM='0000_nnnn',        # small copy + mov 1 fragment
    CPR='0001_nnnn',        # small copy + rpl 1 fragment
    RPL='0010_nnnn',
    MOV='0011_nnnn',

    CPY='01nn_nnnn',
    INS='10nn_nnnn',
    SKP='11nn_nnnn',        # TODO signed is better?
)

# prefix for the opcode
opcode = {k: int(v.replace('n','0'),2) for (k, v) in opmap.items()}
# mask for the payload
opmask = {k: int(v.replace('1','0').replace('n','1'),2) for (k, v) in opmap.items()}
# flag for opcodes accepting data
opdata = {k: k in {'INS', 'RPL', 'CPR'} for k in opcode}

assert (opcode['CPR'] & ~opmask['CPR']) != (opcode['END'] & ~opmask['END'])

pending_copy = 0

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
    def _encode_op(op: Op, n = 0, data: bytes = bytes()) -> bytes:
        global pending_copy
        out = bytes()
        if pending_copy:
            if n == 1 and op in ('MOV', 'RPL'):
                op = 'CPM' if op == 'MOV' else 'CPR'
                n = pending_copy
            else:
                out = Delta16._encode_op_inner('CPY', pending_copy)
            pending_copy = 0
        if op == 'CPY':
            pending_copy = n
        else:
            out += Delta16._encode_op_inner(op, n, data)
        return out

    @staticmethod
    def _encode_op_inner(op: Op, n = 0, data: bytes = bytes()) -> bytes:
        if op == 'SKP':
            n = (n + 0x10000) & 0xffff

        assert (op == 'END' and n == 0) or n > 0

        nd = 1 if op == 'CPR' else n

        if opdata[op]:
            assert data and len(data) >= nd, f"_encode_op: {op} expected data[:{nd}], got {len(data)}"
        else:
            assert not data, f"_encode_op: {op} unexpected data"

        # the maximum value we can pack with the opcode is limit
        limit = opmask[op]
        # we encode the count as a packed value nnn as follows:
        # nnn = 0 means the next two bytes give the little endian value count
        # nnn = limit means the next byte stores count - limit
        # nnn in 1...limit-1 gives the actual count

        v = opcode[op]
        if n > 255 + limit:
            if v != opcode['END']:
                # can't encode MOV n16 since it clashes with END
                return bytes([v | 0]) + pack16(n) + data[:nd]
            else:
                # Nb. must not use this for CPR
                k = 255+limit
                return bytes([v | limit, 255]) + data[:k] + Delta16._encode_op(op, n-k, data[k:])
        elif op != 'END' and n >= limit:
            # single byte length
            return bytes([v | limit, n-limit]) + data[:nd]
        else:
            # packed length
            return bytes([v | n]) + data[:nd]

    @staticmethod
    def _decode_op(data: bytearray) -> tuple[str, int]:
        v = data.pop(0)

        op = next(op for op, pfx in opcode.items() if v & ~opmask[op] == pfx)
        limit = opmask[op]
        n = v & limit
        if op != 'END':
            if n == 0:
                n = addr16(data)
                data.pop(0)
                data.pop(0)
            elif n == limit:
                n += data[0]
                data.pop(0)

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
                   logging.debug(
                       f"{op} {n}".ljust(16) + f"{hexstring(data[:4])} ...".ljust(16)
                       + f"{i_dst:04x}  {i_src:04x}: {hexstring(self.src[i_src:][:4])} ..."
                    )

                if not ready:
                    # start or finish a relocation table entry?
                    if entry and op in ('INS', 'SKP', 'END'):
                        entry = entry._replace(length = i_src - entry.start)
                        entries.append(entry)
                        entry = None
                    elif entry is None and op not in ('INS', 'SKP', 'END'):   # CPY, RPL, MOV, SKP
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
                    case 'CPR':
                        if ready:
                            yield self.src[i_src:][:n] + data[:1]
                        data = data[1:]
                        i_src += n+1
                        i_dst += n+1
                    case 'CPM':
                        if ready:
                            yield self.src[i_src:][:n] + pack16(relocate(addr16(self.src[i_src+n:])))
                        i_src += n+2
                        i_dst += n+2
                    case 'INS':
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
                    case 'MOV':
                        if ready:
                            yield b''.join(pack16(relocate(addr16(self.src[i_src + 2*i:]))) for i in range(n))
                        i_src += 2*n
                        i_dst += 2*n

            logging.debug(f"inferred relocation entries {entries}")
            relocate = RelocationTable(
                entries, addr_start = self.src_addr, addr_offset = dst_addr - self.src_addr
            ).relocate

    def _enc(self, dst: bytes, dst_addr: int, block_size=64) -> Generator[bytes, None, None]:
        i_src, i_dst = 0, 0

        def dbg(op, n):
            logging.debug(
                f"{op} {n}".ljust(16) + f"{i_dst:04x}: {hexstring(dst[i_dst:][:4])} ...".ljust(24)
                + f"{i_src:04x}: {hexstring(self.src[i_src:][:4])} ..."
            )

        fragments = find_fragments(dst, self.src, block_size=block_size)
        logging.debug(f"found relocation fragments {fragments}")
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
                dbg('INS', n_dst)
                yield self._encode_op('INS', n_dst, dst[i_dst:])
                i_dst += n_dst

            if n_src != 0:
                dbg('SKP', n_src)
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
                logging.debug(f"extended fragment {fragment} to length {len(diff)}")

            # now we can simply run-length code the difference map
            for v, g in groupby(diff):
                n = len(list(g))
                op = {0: 'CPY', 1: 'RPL', 2: 'MOV'}[v]
                arg = n
                if op == 'MOV':
                    assert n & 1 == 0, f"MOV acts on pairs, but n={n}"
                    arg >>= 1
                dbg(op, arg)
                if op == 'RPL':
                    yield self._encode_op(op, arg, dst[i_dst:])
                else:
                    yield self._encode_op(op, arg)
                i_dst += n
                i_src += n

            assert i_dst >= fragment.map_end, "Failed to consume fragment"

        assert i_dst == len(dst)
        dbg('END', 0)
        yield self._encode_op('END')