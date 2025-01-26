from delta16 import Delta16


def test_nil():
    assert len(Delta16(b'').encode(b'')) == 13


def test_identity():
    ref = b'the quick brown fox jumps over the lazy dog'
    s = Delta16(ref).encode(ref, chunk_size=8)
    assert len(s) == 14
    assert s[0:2] == bytes([0x16, 0x0d])
    assert s[2:4] == bytes([0, 0])      # src offset
    assert s[4:6] == bytes([len(ref), 0])
    assert s[8:10] == bytes([0, 0])     # dst offset
    assert s[10:12] == bytes([0x40|len(ref), 0])
    assert s[6:8] == s[12:14]


def test_roundtrip():
    ref = b'the quick brown fox jumps over the lazy dog'
    tgt = b'jumps over the lazy dog does the quick brown fox'
    delta = Delta16(ref).encode(tgt, chunk_size=8)
    assert tgt == Delta16(ref).decode(delta)


def test_reloc():
    # \x20\x00 points to the h in 'the lazy dog'
    ref = b'the quick brown f\x20\x00 jumps over the lazy dog'  # start offset length
    #                                            ^^^^^^^^^^^^      31   -15     12
    #       ^^^^^^^^^^^^^^^^^^^^^^^^^                               0    32     19
    # \x11\x00 points to the same h in 'the lazy dog'
    tgt = b'jumped over was the lazy dog by the quick brown f\x11\x00'
    #                       ^^^^^^^^^^^^
    #                                       ^^^^^^^^^^^^^^^^^^^^^^^^^

    # as written, the index mapping relocates the pointer
    s = Delta16(ref).encode(tgt, chunk_size=8)
    assert 0b0010_0001 in s
    # if we shift tgt with a leading space the pointer is no longer relocatable
    assert 0b0010_0001 not in Delta16(ref).encode(b' ' + tgt, chunk_size=8)
    assert Delta16(ref).decode(s) == tgt
