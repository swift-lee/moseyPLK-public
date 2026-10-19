package android.content.pm;

public final class Signature {
    private final byte[] bytes;
    public Signature(byte[] bytes) { this.bytes = bytes.clone(); }
    public byte[] toByteArray() { return bytes.clone(); }
}
