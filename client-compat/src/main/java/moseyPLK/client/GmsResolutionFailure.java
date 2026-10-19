package moseyPLK.client;

/** Stable diagnostic categories shared without a dependency on the DEX resolver. */
final class GmsResolutionFailure {
    interface Classified {
        String stage();
        String reason();
    }

    private GmsResolutionFailure() { }

    static final class AtStage extends Exception implements Classified {
        private static final long serialVersionUID = 1L;
        private final String phase;
        private final String category;

        AtStage(String stage, Throwable cause) {
            super("resolution_stage_rejected", cause);
            phase = token(stage) ? stage : "discovery";
            category = GmsResolutionFailure.reason(cause);
        }

        @Override public String stage() { return phase; }
        @Override public String reason() { return category; }
    }

    static String stage(Throwable failure, String fallback) {
        try {
            if (failure instanceof Classified) {
                String value = ((Classified) failure).stage();
                if (token(value)) return value;
            }
        } catch (Throwable ignored) { /* Untrusted diagnostic accessors cannot change the outcome. */ }
        return token(fallback) ? fallback : "discovery";
    }

    static String reason(Throwable failure) {
        if (failure == null) return "unknown_failure";
        // This wrapper captured an already-sanitized reason, which may be a Java
        // exception type (for example UnsatisfiedLinkError) rather than a rule token.
        if (failure instanceof AtStage) return ((AtStage) failure).category;
        try {
            String value = failure instanceof Classified
                    ? ((Classified) failure).reason() : failure.getMessage();
            if (failure instanceof Classified && value != null)
                value = value.split("[:=]", 2)[0];
            if (token(value)) return value;
        } catch (Throwable ignored) { /* Do not expose exception messages or descriptors. */ }
        String type = failure.getClass().getSimpleName();
        return type.matches("[A-Za-z][A-Za-z0-9_]{0,95}") ? type : "unknown_failure";
    }

    private static boolean token(String value) {
        return value != null && value.matches("[a-z][a-z0-9_]{0,95}");
    }
}
