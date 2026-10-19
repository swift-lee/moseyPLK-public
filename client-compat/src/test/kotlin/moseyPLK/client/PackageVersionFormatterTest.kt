package moseyPLK.client

import org.junit.Assert.assertEquals
import org.junit.Test

class PackageVersionFormatterTest {
    @Test
    fun appendsVersionCodeInParentheses() {
        assertEquals("1.2.3 (42)", formatPackageVersion("1.2.3", 42))
    }

    @Test
    fun preservesParenthesizedVersionName() {
        assertEquals(
            "26.36.33 (260400-986028547) (263633035)",
            formatPackageVersion("26.36.33 (260400-986028547)", 263633035),
        )
    }
}
