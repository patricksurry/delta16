from delta16.util import fletcher16
from delta16.util import hexstring
from delta16.util import addr16, pack16
from delta16.util import find_overlap, find_fragments
from delta16.util import RelocationTable, IndexMapping


def test_fletcher16():
    assert fletcher16(bytes([0x01, 0x02])) == 0x0403
    assert fletcher16(b"abcdefgh") == 0x0627


def test_hexstring():
    assert hexstring(bytes([0x0d, 0x16])) == '0d 16'


def test_addr16():
    assert addr16(bytes([0x0d, 0x16])) == 0x160d


def test_pack16():
    assert pack16(0x160d) == bytes([0x0d, 0x16])


def test_overlap1():
    assert find_overlap(
        b'the quick brown fox',
        b'THE quick x brown fox',
        0
    ) == (3, 7)


def test_overlap2():
    assert find_overlap(
        b'the quick brown fox',
        b'the QUicK x brown fox',
        3
    ) == (0, 10)


def test_fragments():
    assert find_fragments(
        b'the lazy dog was jumped by the quick brown fox',  # dst
        b'the quick brown fox jumps over the lazy dog',     # ref
        block_size = 8,
    ) == [
        IndexMapping(31, -31, 12),  # "the lazy dog"
        IndexMapping(0, 27, 19),
    ]

def test_relocation():
    t = RelocationTable([
            IndexMapping(start=0, offset=0, length=1024),
            IndexMapping(start=512, offset=2048-512, length=1024),
        ], addr_start=8192, addr_offset = 16384 - 8192)

    assert t.relocate(0) is None

    assert t.relocate(512+8192) == 512+16384

    assert t.relocate(1500+8192) == 1500+16384+2048-512