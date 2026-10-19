#!/system/bin/sh
# Read-only checks. The caller supplies fixed paths and its current record dir.
registration_token() {
    sed 's/^.*) //' "$PROC_ROOT/$1/stat" 2>/dev/null | awk '{print $20}'
}

registration_alive() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "$PROC_ROOT/$1/stat" ] || return 1
    registration_state=$(sed 's/^.*) //' "$PROC_ROOT/$1/stat" 2>/dev/null | awk '{print $1}')
    case "$registration_state" in ''|Z|X) return 1 ;; esac
}

registration_identity() {
    registration_alive "$1" || return 1
    [ "$(registration_token "$1")" = "$2" ] || return 1
    [ "$(readlink "$PROC_ROOT/$1/exe" 2>/dev/null)" = "$BIN" ] || return 1
    [ "$(cat "$PROC_ROOT/$1/attr/current" 2>/dev/null)" = 'u:r:mosey_server:s0' ] || return 1
    awk '
        /^Uid:/ { uid=(NF==5 && $2==1000 && $3==1000 && $4==1000 && $5==1000) }
        /^Gid:/ { gid=(NF==5 && $2==1000 && $3==1000 && $4==1000 && $5==1000) }
        /^Groups:/ { for(i=2;i<=NF;i++) if($i==3003) inet=1 }
        /^CapInh:/ { inh=($2=="0000000000003000") }
        /^CapPrm:/ { prm=($2=="0000000000003000") }
        /^CapEff:/ { eff=($2=="0000000000003000") }
        /^CapAmb:/ { amb=($2=="0000000000003000") }
        END { exit !(uid && gid && inet && inh && prm && eff && amb) }
    ' "$PROC_ROOT/$1/status" || return 1
    [ "$(registration_token "$1")" = "$2" ] && registration_alive "$1"
}

registration_binder() {
    timeout -k 1 5 service list >"$OUT/binder-$1.txt" 2>&1
    binder_rc=$?
    printf 'BINDER_QUERY=%s RC=%s\n' "$1" "$binder_rc" >>"$OUT/context.txt"
    [ "$binder_rc" = 0 ] || return 2
    # A truncated rc=0 reply is not proof of absence. Validate the complete
    # list shape and entry count before treating a missing exact name as safe.
    awk -v name="$SERVICE_NAME:" '
        NR==1 {
            if($0 !~ /^Found [0-9]+ services:$/) bad=1
            expected=$2
            next
        }
        {
            if(NF!=3 || $1 !~ /^[0-9]+$/ || $1!=entries ||
                    $2 !~ /:$/ || $3 !~ /^\[[^][]*\]$/) bad=1
            entries++
            if($2==name) found=1
        }
        END {
            if(NR<1 || bad || entries!=expected) exit 2
            exit(found ? 0 : 1)
        }
    ' "$OUT/binder-$1.txt"
}

registration_system_app() {
    # Only the active package block counts. Hidden-system-package flags do not.
    awk '
        /^Packages:/ { packages=1; next }
        /^[^ ]/ && !/^Packages:/ { packages=0; active=0 }
        /^  Package \[/ {
            active=(packages && $0 ~ /^  Package \[com\.google\.android\.mosey\]/)
            if(active) count++
        }
        active && /^[ ]+(pkgFlags|flags)=\[/ {
            if($0 ~ /(^|[ |[])SYSTEM([] |]|$)/) is_system=1
        }
        active && /^[ ]+(pkgPrivateFlags|privateFlags)=\[/ {
            if($0 ~ /(^|[ |[])PRIVILEGED([] |]|$)/) privileged=1
        }
        END { exit !(count==1 && is_system && privileged) }
    ' "$1"
}

registration_shim_success() {
    # Donor and launcher retain the same PID across exec. The shim is silent in
    # the launcher, so each expected donor event must occur exactly once.
    awk -v pid="$2" '
        BEGIN {
            required["loaded"]="schema=1 experiment=registration_only origin_expected=1"
            required["identity"]="ok=1 reason=ok read_errors=0"
            required["intercept"]="target=1 enabled=1 binder_nonnull=1"
            required["binder"]="local=1 descriptor=1"
            required["api"]="source=/system/lib64/libbinder_ndk.so verified=1"
            required["downgrade_begin"]="phase=begin target=1 to=system"
            required["downgrade_returned"]="phase=returned target=1 to=system"
            required["add_result"]="target=1 downgraded=1 called=1 code=0 source=platform"
        }
        $0=="MOSEY_LOG_TRUNCATED=1" {bad=1}
        $1=="MOSEY_REGCOMPAT" && $2=="pid=" pid {
            if($3 !~ /^event=/) {bad=1; next}
            event=substr($3,7)
            if(event=="blocked") {bad=1; next}
            if(event=="downgrade") {
                if($4=="phase=begin") event="downgrade_begin"
                else if($4=="phase=returned") event="downgrade_returned"
                else {bad=1; next}
            }
            if(!(event in required)) {bad=1; next}
            fields=""
            for(i=4;i<=NF;i++) fields=fields (i==4 ? "" : " ") $i
            seen[event]++
            if(fields!=required[event]) bad=1
        }
        END {
            for(event in required) if(seen[event]!=1) bad=1
            exit bad
        }
    ' "$1"
}

registration_shim_failure() {
    # Diagnostic classification only; registration_shim_success is the gate.
    if grep -qx 'MOSEY_LOG_TRUNCATED=1' "$1"; then echo SHIM_LOG_TRUNCATED; return; fi
    awk -v pid="$2" '
        $1=="MOSEY_REGCOMPAT" && $2=="pid=" pid {
            if($3=="event=loaded") loaded=1
            if($3=="event=intercept") intercept=1
            if($3=="event=blocked") blocked=1
            if($3=="event=add_result") {
                returned=1
                for(i=4;i<=NF;i++) if($i ~ /^code=/ && $i!="code=0") failed=1
            }
        }
        END {
            if(blocked) print "SHIM_BLOCKED"
            else if(failed) print "SHIM_ADD_SERVICE_FAILED"
            else if(!loaded) print "SHIM_NOT_OBSERVED"
            else if(!intercept) print "SHIM_INTERCEPT_NOT_OBSERVED"
            else if(!returned) print "SHIM_ADD_RESULT_NOT_OBSERVED"
            else print "SHIM_REGISTRATION_UNCONFIRMED"
        }
    ' "$1"
}
