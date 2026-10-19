package moseyPLK.client.manager

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RefreshArbitrationTest {
    @Test fun foregroundRequestsRootOnceThenResumesWithSilentWork() {
        assertEquals(
            ForegroundDisposition.REQUEST_ROOT,
            foregroundDisposition(visible = true, automaticRootAttempted = false, ownerUser = true),
        )
        assertEquals(
            ForegroundDisposition.RESUME,
            foregroundDisposition(visible = true, automaticRootAttempted = true, ownerUser = true),
        )
        assertEquals(
            ForegroundDisposition.RESUME,
            foregroundDisposition(visible = true, automaticRootAttempted = false, ownerUser = false),
        )
        assertEquals(
            ForegroundDisposition.STOP_POLLING,
            foregroundDisposition(visible = false, automaticRootAttempted = false, ownerUser = true),
        )
    }

    @Test fun pullPromotesAnExistingSnapshotInsteadOfStartingAnother() {
        assertEquals(
            RefreshDisposition.PROMOTE_RUNNING,
            refreshDisposition(
                trigger = RefreshTrigger.PULL,
                refreshActive = true,
                issuingCommand = false,
                nativeWorkPending = false,
                pollActive = false,
            ),
        )
        assertEquals(
            RefreshDisposition.IGNORE,
            refreshDisposition(
                trigger = RefreshTrigger.SILENT,
                refreshActive = true,
                issuingCommand = false,
                nativeWorkPending = false,
                pollActive = false,
            ),
        )
    }

    @Test fun idlePullAndSilentRequestsCanStart() {
        RefreshTrigger.entries.forEach { trigger ->
            assertEquals(
                trigger.name,
                RefreshDisposition.START,
                refreshDisposition(
                    trigger = trigger,
                    refreshActive = false,
                    issuingCommand = false,
                    nativeWorkPending = false,
                    pollActive = false,
                ),
            )
        }
    }

    @Test fun commandNativeWorkAndPollingBlockFullSnapshots() {
        RefreshTrigger.entries.forEach { trigger ->
            listOf(
                Triple(true, false, false),
                Triple(false, true, false),
                Triple(false, false, true),
            ).forEach { (issuingCommand, nativeWorkPending, pollActive) ->
                assertEquals(
                    RefreshDisposition.IGNORE,
                    refreshDisposition(
                        trigger = trigger,
                        refreshActive = false,
                        issuingCommand = issuingCommand,
                        nativeWorkPending = nativeWorkPending,
                        pollActive = pollActive,
                    ),
                )
            }
        }
    }

    @Test fun silentAndPullRefreshesDriveOnlyTheirIntendedIndicators() {
        val silent = ManagerState().startRefresh(RefreshTrigger.SILENT)
        assertTrue(silent.refreshing)
        assertFalse(silent.pullRefreshing)

        val pull = ManagerState().startRefresh(RefreshTrigger.PULL)
        assertTrue(pull.refreshing)
        assertTrue(pull.pullRefreshing)
    }

    @Test fun pullPromotionUsesTheExistingSnapshotAndFinallyClearsBothIndicators() {
        val runningSilent = ManagerState().startRefresh(RefreshTrigger.SILENT)
        val promoted = runningSilent.promoteRefreshToPull()
        assertTrue(promoted.refreshing)
        assertTrue(promoted.pullRefreshing)

        val finished = promoted.finishRefresh()
        assertFalse(finished.refreshing)
        assertFalse(finished.pullRefreshing)
    }
}
