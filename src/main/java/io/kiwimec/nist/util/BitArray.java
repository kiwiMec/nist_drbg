package io.kiwimec.nist.util;

// Interesting bit class, compare BitSet
class BitArray {

    private static final int MASK = 63;
    private final long len;
    private long bits[] = null;

    public BitArray(long size) {
        if ((((size-1)>>6) + 1) > 2147483647) {
            throw new IllegalArgumentException(
                "Field size to large, max size = 137438953408");
        }else if (size < 1) {
            throw new IllegalArgumentException(
                "Field size to small, min size = 1");
        }
        len = size;
        bits = new long[(int) (((size-1)>>6) + 1)];
    }

    public boolean getBit(long pos) {
        return (bits[(int)(pos>>6)] & (1L << (pos&MASK))) != 0;
    }

    public void setBit(long pos, boolean b) {
        if (getBit(pos) != b) { bits[(int)(pos>>6)] ^= (1L << (pos&MASK)); }
    }

    public long getLength() {
        return len;
    }
}