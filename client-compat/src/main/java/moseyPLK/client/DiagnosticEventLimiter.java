package moseyPLK.client;

import java.util.HashMap;
import java.util.Map;

/** Bound diagnostic volume while preserving changed results and new instances. */
public final class DiagnosticEventLimiter {
    private final int maximumKeys;
    private final int maximumChanges;
    private final Map<String, String> last = new HashMap<String, String>();
    private final Map<String, Integer> changes = new HashMap<String, Integer>();

    public DiagnosticEventLimiter(int maximumKeys, int maximumChanges) {
        if (maximumKeys < 1 || maximumChanges < 1) throw new IllegalArgumentException();
        this.maximumKeys = maximumKeys;
        this.maximumChanges = maximumChanges;
    }

    public synchronized boolean admit(String key, String value) {
        if (key == null || value == null) return false;
        String previous = last.get(key);
        if (value.equals(previous)) return false;
        if (previous == null && last.size() >= maximumKeys) return false;
        Integer count = changes.get(key);
        int current = count == null ? 0 : count;
        if (current >= maximumChanges) return false;
        last.put(key, value);
        changes.put(key, current + 1);
        return true;
    }
}
