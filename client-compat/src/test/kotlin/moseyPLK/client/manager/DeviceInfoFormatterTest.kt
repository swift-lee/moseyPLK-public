package moseyPLK.client.manager

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceInfoFormatterTest {
    @Test fun formatsPublicBuildFieldsAndDeduplicatesCaseInsensitively() {
        assertEquals(
            DeviceInfo("OnePlus PLK110", "Qualcomm SM8650"),
            DeviceInfoFormatter.format(
                manufacturer = " OnePlus ",
                brand = "oneplus",
                model = " PLK110 ",
                socManufacturer = " Qualcomm ",
                socModel = " SM8650 ",
                supportedAbis = listOf("arm64-v8a"),
            ),
        )
    }

    @Test fun removesBlankUnknownNullAndRepeatedValues() {
        assertEquals(
            DeviceInfo("OnePlus", "SM8650"),
            DeviceInfoFormatter.format(
                manufacturer = "OnePlus",
                brand = " ONEPLUS ",
                model = "unknown",
                socManufacturer = " NULL ",
                socModel = "SM8650",
                supportedAbis = listOf("arm64-v8a"),
            ),
        )
    }

    @Test fun fallsBackToFirstValidSupportedAbiForMissingSoc() {
        assertEquals(
            DeviceInfo("OPPO PLK110", "arm64-v8a"),
            DeviceInfoFormatter.format(
                manufacturer = "OPPO",
                brand = " ",
                model = "PLK110",
                socManufacturer = "unknown",
                socModel = null,
                supportedAbis = listOf(" ", "NULL", " arm64-v8a ", "armeabi-v7a"),
            ),
        )
    }

    @Test fun returnsChineseUnknownWhenNoPublicIdentityIsUsable() {
        assertEquals(
            DeviceInfo(),
            DeviceInfoFormatter.format(
                manufacturer = null,
                brand = "unknown",
                model = " null ",
                socManufacturer = "",
                socModel = "UNKNOWN",
                supportedAbis = listOf(null, " ", "null"),
            ),
        )
    }
}
