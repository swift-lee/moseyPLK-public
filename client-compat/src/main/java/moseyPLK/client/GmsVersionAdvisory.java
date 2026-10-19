package moseyPLK.client;

/** Display-only metadata. This model never decides whether a hook may be installed. */
public final class GmsVersionAdvisory {
    public static final long LOWEST_KNOWN = 263161029L;
    public static final long HIGHEST_KNOWN = 263633035L;
    private static final long[] KNOWN = {263161029L, 263332035L, 263367035L,
            263436035L, 263465022L, 263633004L, 263633035L};

    public enum Position { BELOW_KNOWN_RANGE, WITHIN_KNOWN_RANGE, ABOVE_KNOWN_RANGE, UNKNOWN }
    public final Position position;
    public final long versionCode;
    public final boolean knownVersionCode;

    private GmsVersionAdvisory(Position position, long code, boolean known) {
        this.position = position; versionCode = code; knownVersionCode = known;
    }

    public static GmsVersionAdvisory evaluate(long code) {
        Position position = code <= 0 ? Position.UNKNOWN
                : code < LOWEST_KNOWN ? Position.BELOW_KNOWN_RANGE
                : code > HIGHEST_KNOWN ? Position.ABOVE_KNOWN_RANGE : Position.WITHIN_KNOWN_RANGE;
        boolean known = false;
        for (long candidate : KNOWN) known |= candidate == code;
        return new GmsVersionAdvisory(position, code, known);
    }

    public boolean needsRangeWarning() {
        return position == Position.BELOW_KNOWN_RANGE || position == Position.ABOVE_KNOWN_RANGE;
    }

    public String detail() {
        return "position=" + position.name().toLowerCase(java.util.Locale.ROOT)
                + " version_code=" + versionCode + " known_min=" + LOWEST_KNOWN
                + " known_max=" + HIGHEST_KNOWN + " known_version_code=" + knownVersionCode
                + " warning=" + needsRangeWarning() + " action=continue_semantic_resolution";
    }
}
