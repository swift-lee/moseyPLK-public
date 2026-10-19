package moseyPLK.client.manager

/** Closed command vocabulary; neither UI text nor snapshot contents become executable code. */
object RootCommands {
    const val HELPER = "/data/adb/modules/moseyPLK.service/control.sh"
    const val LEGACY_PACKAGE = "top.netkumiko.moseyclientcompat"
    private const val MODULES_DIR = "/data/adb/modules"
    /** A secondary GMS or Mosey process does not establish that the main process is running. */
    internal val processFilter = """
        NR == 1 { if (${'$'}1 != "UID" || ${'$'}2 != "NAME") exit 2; next }
        ${'$'}1 == expected && ${'$'}2 == target { found=1 }
        END { if (NR < 1) exit 2; print found ? "running" : "stopped" }
    """.trimIndent()

    private fun quoted(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    fun bounded(script: String, seconds: Int = 12): String {
        require(seconds in 1..30)
        return "/system/bin/timeout -k 1 $seconds /system/bin/sh -c " + quoted(script)
    }

    fun helper(command: String): String {
        require(command in setOf("capabilities", "status", "start", "stop", "restart"))
        // The helper is a root-owned module file. Do not execute a symlink or an app-owned replacement.
        return bounded("""
            [ "${'$'}(id -u)" = 0 ] || exit 70
            [ ! -L '$HELPER' ] && [ -f '$HELPER' ] || exit 71
            [ "${'$'}(stat -c %u '$HELPER')" = 0 ] || exit 72
            exec /system/bin/sh '$HELPER' '$command'
        """.trimIndent(), 15)
    }

    fun application(action: ControlAction): String = bounded(when (action) {
        ControlAction.GMS_STOP -> "am force-stop --user 0 ${TargetApp.GMS.packageName}"
        else -> error("not an application action")
    }, 15)

    /** Reads only the two fixed target locations, through a checked open file descriptor. */
    fun snapshot(target: TargetApp, uid: Int): String {
        require(uid in 10000..99999)
        val base = "/data/user/0/${target.packageName}"
        val file = "$base/code_cache/moseyplk-hook-state-v1.json"
        return bounded("""
            [ ! -L '$base' ] && [ ! -L '$base/code_cache' ] && [ ! -L '$file' ] || exit 73
            [ -f '$file' ] || exit 74
            [ "${'$'}(stat -c %u '$base')" = $uid ] && [ "${'$'}(stat -c %u '$base/code_cache')" = $uid ] || exit 75
            before=${'$'}(stat -c '%u %a %s %d:%i' '$file') || exit 76
            exec 3< '$file' || exit 77
            opened=${'$'}(stat -Lc '%u %a %s %d:%i' /proc/${'$'}${'$'}/fd/3) || exit 78
            [ "${'$'}before" = "${'$'}opened" ] && [ ! -L '$file' ] && [ -f /proc/${'$'}${'$'}/fd/3 ] || exit 79
            set -- ${'$'}opened
            [ "${'$'}1" = $uid ] && [ "${'$'}2" = 600 ] || exit 80
            [ "${'$'}3" -gt 0 ] && [ "${'$'}3" -le 16384 ] || exit 81
            head -c 16385 <&3
        """.trimIndent())
    }

    fun process(pid: Int): String {
        require(pid > 0)
        // stat is sampled twice; the Kotlin reader compares it before accepting the identity.
        return bounded("""
            cat /proc/$pid/stat || exit 82
            awk '/^Uid:/ { print ${'$'}2 }' /proc/$pid/status || exit 83
            tr '\000' '\n' < /proc/$pid/cmdline | head -n 1
            cat /proc/$pid/stat || exit 84
        """.trimIndent())
    }

    fun processes(target: TargetApp, uid: Int): String {
        return bounded(processesScript(target, uid))
    }

    internal fun processesScript(target: TargetApp, uid: Int): String {
        require(uid in 10000..99999)
        return "mosey_listing=${'$'}(ps -A -o UID,NAME) || exit 88\n" +
            "printf '%s\\n' \"${'$'}mosey_listing\" | awk -v expected=$uid -v target='${target.packageName}' " + quoted(processFilter)
    }

    /** Reads the fixed active KSU module directory and its marker files; never runs module code. */
    val modulePresence: String = bounded(modulePresenceScript(), 8)

    // The directory and expected owner arguments allow isolated host fixtures. The production
    // command above always uses /data/adb/modules and uid 0; neither value comes from the UI.
    internal fun modulePresenceScript(modulesDir: String = MODULES_DIR, expectedOwner: Int = 0): String {
        require(modulesDir.matches(Regex("/[A-Za-z0-9._/-]+")) && ".." !in modulesDir.split('/'))
        require(expectedOwner >= 0)
        val parentDir = modulesDir.substringBeforeLast('/')
        require(parentDir.isNotEmpty())
        val moduleDir = "$modulesDir/moseyPLK.service"
        return """
            [ "${'$'}(id -u)" = 0 ] || exit 90
            parent=${quoted(parentDir)}
            [ ! -L "${'$'}parent" ] && [ -d "${'$'}parent" ] &&
                [ "${'$'}(stat -c %u "${'$'}parent" 2>/dev/null)" = $expectedOwner ] || exit 91
            modules=${quoted(modulesDir)}
            if [ ! -e "${'$'}modules" ] && [ ! -L "${'$'}modules" ]; then
                printf 'absent\n'
                exit 0
            fi
            [ ! -L "${'$'}modules" ] && [ -d "${'$'}modules" ] &&
                [ "${'$'}(stat -c %u "${'$'}modules" 2>/dev/null)" = $expectedOwner ] || exit 91
            ls -A ${quoted(modulesDir)} >/dev/null 2>&1 || exit 92
            module=${quoted(moduleDir)}
            if [ ! -e "${'$'}module" ] && [ ! -L "${'$'}module" ]; then
                printf 'absent\n'
                exit 0
            fi
            [ ! -L "${'$'}module" ] && [ -d "${'$'}module" ] &&
                [ "${'$'}(stat -c %u "${'$'}module" 2>/dev/null)" = $expectedOwner ] || exit 93
            prop="${'$'}module/module.prop"
            [ ! -L "${'$'}prop" ] && [ -f "${'$'}prop" ] || exit 94
            before=${'$'}(stat -c '%u %s %d:%i' "${'$'}prop" 2>/dev/null) || exit 94
            exec 3< "${'$'}prop" || exit 94
            opened=${'$'}(stat -Lc '%u %s %d:%i' /proc/${'$'}${'$'}/fd/3 2>/dev/null) || exit 94
            [ "${'$'}before" = "${'$'}opened" ] && [ ! -L "${'$'}prop" ] || exit 94
            set -- ${'$'}opened
            [ "${'$'}1" = $expectedOwner ] && [ "${'$'}2" -gt 0 ] && [ "${'$'}2" -le 4096 ] || exit 94
            awk '/^id=/ { ids++; if (${'$'}0 == "id=moseyPLK.service") matches++ }
                 END { if (ids != 1 || matches != 1) exit 1 }' <&3 || exit 94
            has_remove=0
            has_disable=0
            has_update=0
            for marker in remove disable update; do
                flag="${'$'}module/${'$'}marker"
                if [ -e "${'$'}flag" ] || [ -L "${'$'}flag" ]; then
                    [ ! -L "${'$'}flag" ] && [ -f "${'$'}flag" ] &&
                        [ "${'$'}(stat -c %u "${'$'}flag" 2>/dev/null)" = $expectedOwner ] || exit 95
                    case "${'$'}marker" in
                        remove) has_remove=1 ;;
                        disable) has_disable=1 ;;
                        update) has_update=1 ;;
                    esac
                fi
            done
            if [ "${'$'}has_remove" = 1 ]; then printf 'pending_removal\n'
            elif [ "${'$'}has_disable" = 1 ]; then printf 'disabled\n'
            elif [ "${'$'}has_update" = 1 ]; then printf 'updating\n'
            else printf 'present\n'; fi
        """.trimIndent()
    }

    val bootIdentity: String = bounded("""
        settings get global boot_count || exit 85
        cat /proc/sys/kernel/random/boot_id || exit 86
    """.trimIndent())

    /** Legacy releases expose module.prop without the new control protocol. */
    val moduleVersion: String = bounded("""
        p='/data/adb/modules/moseyPLK.service/module.prop'
        [ ! -L "${'$'}p" ] && [ -f "${'$'}p" ] && [ "${'$'}(stat -c %u "${'$'}p")" = 0 ] || exit 87
        head -c 4096 "${'$'}p" | sed -n '/^version=/p;/^versionCode=/p'
    """.trimIndent())
}
