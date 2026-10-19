package moseyPLK.client;

import java.util.concurrent.atomic.AtomicBoolean;

/** A Phenotype hook remains inert until its backend installation has completed. */
final class GmsHookTransaction {
    interface Handle { void remove() throws Throwable; }
    interface Installer { Handle install(int role, GmsHookTransaction transaction) throws Throwable; }
    private final AtomicBoolean active = new AtomicBoolean();
    private boolean attempted;

    synchronized boolean install(Installer installer) throws Throwable {
        if (attempted) return active.get();
        attempted = true;
        Handle first = null;
        try {
            first = installer.install(0, this);
            if (first == null) throw new IllegalStateException("missing_first_hook_handle");
            active.set(true);
            return true;
        } catch (Throwable failure) {
            active.set(false);
            if (first != null) try { first.remove(); } catch (Throwable ignored) { /* inert */ }
            throw failure;
        }
    }

    boolean isActive() { return active.get(); }

    boolean shouldEnable(boolean hasThrowable, Object original, int argumentCount) {
        return active.get() && !hasThrowable && argumentCount == 0 && Boolean.FALSE.equals(original);
    }
}
