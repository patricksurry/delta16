import numpy as np
from typing import Callable
from collections import namedtuple


Relocator = Callable[[int], int]


class IndexMapping(namedtuple('IndexMapping', ['start', 'offset', 'length'])):
    __slots__ = ()

    @property
    def empty(self):
        return not self.length

    def map(self, i: int):
        if self.start <= i < self.start + self.length:
            return i + self.offset
        else:
            return None

    @property
    def end(self):
        return self.start + self.length

    @property
    def map_start(self):
        return self.start + self.offset

    @property
    def map_end(self):
        return self.map_start + self.length


class RelocationTable:
    def __init__(self, entries: list[IndexMapping] = [], addr_start = 0, addr_offset = 0):
        self.entries = [
            IndexMapping(e.start + addr_start, e.offset + addr_offset, e.length)
            for e in entries
        ]

    def relocate(self, addr) -> int | None:
        a = None
        for e in self.entries:
            if a := e.map(addr):
                break
        return a


def pack16(n: int) -> bytes:
    assert 0 <= n < 1 << 16
    return bytes([n & 0xff, n >> 8])


def hexstring(d: bytes):
    return " ".join(f"{v:02x}" for v in d)


def addr16(xs: bytes):
    assert len(xs) >= 2
    return xs[0] | xs[1] << 8


def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for byte in data:
        sum1 += byte
        if sum1 >= 255:
            sum1 -= 255
        sum2 += sum1
        if sum2 >= 255:
            sum2 -= 255
    return (sum2 << 8) | sum1


def find_overlap(a: bytes, b: bytes, max_error_run=16, prefix=0) -> tuple[int, int]:
    """
    greedy match for longest overlap between a and b allowing up to
    max_error_run mismatching bytes
    with optional prefix, restart after failure until end of prefix

    return result as (offset, length)
    """
    limit = min(len(a), len(b))
    assert prefix < limit

    err = 0
    i = 0
    start = None
    while i < limit:
        if a[i] != b[i]:
            err += 1
        else:
            err = 0
            if start is None:
                start = i

        i += 1
        if err > max_error_run and start is not None:
            if i < prefix + max_error_run:
                start = None
            else:
                break

    if start is None:
        return None
    else:
        # remove err chars, with i pointing past last character
        n = i - start - err
        assert a[start] == b[start] and a[start+n-1] == b[start+n-1]
        return (start, n)


def find_fragments(dst: bytes, src: bytes, block_size=64) -> list[IndexMapping]:
    """
    find matching fragments between dst and src, with at least block_size/2 overlap
    returns a list of matches in increasing (and non-overlapping) dst order
    """
    if not (dst and src):
        return []

    min_size = block_size
    min_overlap = max(2, block_size // 2)
    block_size = min(block_size, len(src))

    # make a rectangular array of shifted src strings
    # so that we can match a chunk of src at all possible spots
    # e.g. given "abcdefghij" of length 10 and block size 4
    # we'd make an array of shape 10-4+1 = 7 x 4 and can
    # match a string like "dcfi" like so:
    #
    #    abcdefg  d  0001000
    #    bcdefgh  c  0100000
    #    cdefghi  f  0001000
    #    defghij  i  0000010
    #                -------
    #                0102010
    #       ^-----------^------- best match @ index 3
    #
    # Note this will miss partial matches at the start or end
    # of src, e.g. "zabc" will score 0.  But we use this
    # to find an aligned block, and then extend the matching fragment
    # from there.

    # shape (n-block_size+1, block_size)
    a = np.frombuffer(src, dtype='uint8')
    cmp = np.stack([
        a[i:i-block_size+1 or None] for i in range(block_size)
    ]).T

    i_dst = 0
    matches = []

    while i_dst < len(dst):
        # take next chunk of dst
        chunk = np.frombuffer(dst[i_dst:i_dst+block_size], dtype='uint8')
        # compare it against all the substrings of src, counting matches
        similarity = (chunk == cmp[:,:len(chunk)]).sum(axis=1)
        # find the offset with the biggest overlap
        i_src = int(similarity.argmax())    # index to src
        # if we got at least 50% match, find the overlapping length
        match = None
        if similarity[i_src] >= min_overlap:
            # allow the match to extend backward from the end of the last one
            # but not before the start of either string
            lookback = 0 if not matches else min(
                i_dst - matches[-1].map_end,
                i_dst,
                i_src,
            )
            result = find_overlap(dst[i_dst - lookback:], src[i_src - lookback:], max_error_run=min_size//4, prefix=lookback)
            assert result
            (start, n) = result
            if n >= min_size:
                match = IndexMapping(i_src - lookback + start, i_dst - i_src, n)

        if match:
            assert not matches or match.map_start >= matches[-1].map_end, matches + [match]
            matches.append(match)
            i_dst = match.map_end
        else:
            i_dst += block_size

    return matches
