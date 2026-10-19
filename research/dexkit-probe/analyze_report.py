#!/usr/bin/env python3
"""Join DexKit discovery with a bounded, host-only supplier expression check.

This reads DEX bytes, never loads GMS classes, and never approves a hook profile.
Namespace reachability and getter opcode shape remain unproved input assumptions.
Only supplier control flow/register use is checked by supplier_semantics.py.
"""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from project_paths import ASSETS, ROOT  # noqa: E402
from supplier_semantics import BOX, FIELD, METHOD, verify_supplier  # noqa: E402

NAMESPACE = "com.google.android.gms.nearby"
SERVICE = "Lcom/google/android/gms/nearby/sharing/NearbySharingChimeraService;"
KEY_A, KEY_B = "45704091", "45830365"
GETTER_OPS = ["invoke-static", "move-result-object", "invoke-interface",
              "move-result-object", "check-cast", "invoke-virtual",
              "move-result", "return"]
UNBOX = "Ljava/lang/Boolean;->booleanValue()Z"
DEX_ENTRY = re.compile(r"classes(?:[2-9][0-9]*|1[0-9]+)?\.dex$")
LIMITS = [
    "Report only: no GMS class loading/execution, hooks, phone operations or profile approval.",
    "Namespace graph reachability is a filter, not namespace constructor-argument dataflow proof.",
    "The eight-opcode getter shape and call identities do not prove its register dataflow or flag semantics.",
    "Receiver accessors, receiver fields, getter contracts and service initialization reads are explicit assumptions; their implementation/dispatch is not proved.",
    "Only a local successful-return supplier expression is checked, under those assumptions; exceptions and side effects of callees are not modelled.",
    "Constructor consumers are call-graph evidence only; memoized field assignment and lifecycle consumption are not proved.",
    "APK hashes identify host inputs; they do not establish runtime Chimera/classloader identity, ART hookability or compatibility of a future build.",
    "Discovery completeness and getter/namespace descriptions depend on the supplied DexKit report; only the selected supplier DEX method is independently decoded.",
]


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def display_path(path):
    path = Path(path).resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def method_parts(descriptor):
    match = METHOD.fullmatch(re.sub(r"\s+", "", descriptor))
    if not match:
        raise ValueError("invalid method descriptor in discovery report")
    return match.groups()


def getter_shape(getter, literal):
    """Syntactic filter only; no register/argument flow claim is made here."""
    method = getter["method"]
    _, name, parameters, returns = method_parts(method["descriptor"])
    opcodes = [op.removesuffix("/range") for op in method["opcodes"]]
    reason = "eight-opcode shape and expected call identities match; dataflow not proved"
    matched = False
    calls = method["invokes"]
    if parameters or returns != "Z" or method["modifiers"] & 8:
        reason = "getter is not an instance no-argument Boolean method"
    elif opcodes != GETTER_OPS or method["fields"]:
        reason = "getter differs from the narrow eight-opcode shape"
    elif len(calls) != 3 or calls[0] != literal["descriptor"] or calls[2] != UNBOX:
        reason = "getter call identities differ from builder / reader / Boolean unboxing"
    else:
        _, _, factory_params, factory_return = method_parts(calls[0])
        read_owner, _, read_params, read_return = method_parts(calls[1])
        contracts = getter["contracts"]
        if (factory_params or factory_return != read_owner or read_params
                or read_return != "Ljava/lang/Object;" or not literal["modifiers"] & 8):
            reason = "builder / reader signatures do not form the expected call chain"
        elif method["descriptor"] not in contracts or any(
                method_parts(c)[1:] != (name, "", "Z") for c in contracts):
            reason = "getter contracts have incompatible signatures"
        else:
            matched = True
    return {"matched": matched, "dataflow_proved": False, "reason": reason}


def select_getter(discovery, key):
    records = [entry for entry in discovery["keys"] if entry["key"] == key]
    if len(records) != 1:
        raise ValueError(f"expected exactly one discovery key record for {key}")
    entry = records[0]
    candidates = {}
    raw = set()
    for match in entry["matches"]:
        literal = match["literal_method"]
        if key not in literal["strings"]:
            raise ValueError("literal discovery record does not contain the requested string key")
        anchors = sorted({item["descriptor"] for item in match["namespace_graph_evidence"]
                          if NAMESPACE in item["strings"]})
        for getter in match["getters"]:
            descriptor = getter["method"]["descriptor"]
            raw.add(descriptor)
            if not anchors:
                continue
            # Distinct origins for one getter are also ambiguous: a getter can
            # call more than one key-bearing factory. Never silently keep first.
            identity = (literal["descriptor"], descriptor)
            candidate = {"literal_method": literal["descriptor"], "getter": descriptor,
                         "contracts": sorted(set(getter["contracts"])),
                         "namespace_graph_anchors": anchors,
                         "getter_shape": getter_shape(getter, literal),
                         "service_on_create_consumer": getter["service_on_create_consumer"]}
            if identity in candidates:
                raise ValueError("duplicate getter origin in discovery report")
            candidates[identity] = (candidate, getter)
    ordered = [candidates[key] for key in sorted(candidates)]
    result = {"key": key, "literal_match_count": entry["literal_match_count"],
              "raw_getter_count": len(raw), "namespace_candidate_count": len(ordered),
              "namespace_is_filter_only": True,
              "candidates": [item[0] for item in ordered], "selected": None,
              "status": "absent" if not ordered else "ambiguous"}
    if len(ordered) != 1:
        return result, None
    summary, getter = ordered[0]
    result["selected"] = summary["getter"]
    result["status"] = "unique_shape_match" if summary["getter_shape"]["matched"] else "unsupported_getter_shape"
    return result, getter if summary["getter_shape"]["matched"] else None


def candidate_assumptions(candidate, a_contracts, b_contracts):
    """Derive narrow input roles, not endorsements of the referenced methods."""
    getter_owners = {method_parts(item)[0] for item in a_contracts + b_contracts}
    accessors = set()
    for descriptor in candidate["invokes"]:
        _, _, parameters, returns = method_parts(descriptor)
        if not parameters and returns in getter_owners:
            accessors.add(descriptor)
    accessor_owners = {method_parts(item)[0] for item in accessors}
    roots, initialization = set(), set()
    for field in candidate["fields"]:
        match = FIELD.fullmatch(field["descriptor"])
        if not match:
            raise ValueError("invalid field descriptor in discovery report")
        owner, name, field_type = match.groups()
        descriptor = f"{owner}->{name}:{field_type}"
        if field["use"] != "Read":
            continue
        if owner == SERVICE and field_type == "I":
            initialization.add(descriptor)
        elif field_type in accessor_owners:
            roots.add(descriptor)
    return {"a_getters": sorted(a_contracts), "b_getters": sorted(b_contracts),
            "receiver_accessors": sorted(accessors),
            "receiver_fields": sorted(roots), "service_init_fields": sorted(initialization)}


def dex_target_counts(data, targets):
    """Read class_def/type/string tables only; no full DEX parser is used here."""
    if len(data) < 0x70 or data[:8] not in {
            b"dex\n035\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0", b"dex\n040\0"}:
        raise ValueError("unsupported or truncated DEX header")

    def u32(offset):
        if offset < 0 or offset + 4 > len(data):
            raise ValueError("DEX index is outside file bounds")
        return struct.unpack_from("<I", data, offset)[0]

    if u32(0x20) != len(data) or u32(0x24) != 0x70 or u32(0x28) != 0x12345678:
        raise ValueError("unsupported DEX size/header/endianness")
    strings, string_off = u32(0x38), u32(0x3C)
    types, type_off = u32(0x40), u32(0x44)
    classes, class_off = u32(0x60), u32(0x64)
    if any(offset + count * stride > len(data) for count, offset, stride in
           ((strings, string_off, 4), (types, type_off, 4), (classes, class_off, 32))):
        raise ValueError("DEX index table is outside file bounds")
    wanted = {descriptor.encode("ascii"): descriptor for descriptor in targets}
    counts = {descriptor: 0 for descriptor in targets}
    for index in range(classes):
        class_type = u32(class_off + 32 * index)
        if class_type >= types:
            raise ValueError("class_def references an invalid type")
        string_index = u32(type_off + 4 * class_type)
        if string_index >= strings:
            raise ValueError("class type references an invalid string")
        cursor = u32(string_off + 4 * string_index)
        for _ in range(5):
            if cursor >= len(data):
                raise ValueError("truncated class descriptor string")
            byte = data[cursor]
            cursor += 1
            if not byte & 0x80:
                break
        else:
            raise ValueError("invalid DEX string length")
        end = data.find(b"\0", cursor)
        if end < 0:
            raise ValueError("unterminated DEX class descriptor")
        descriptor = wanted.get(data[cursor:end])
        if descriptor is not None:
            counts[descriptor] += 1
    return counts


def locate_supplier_dex(apk, targets):
    """Index all APK DEX entries so cross-DEX duplicate target classes reject."""
    locations = {target: [] for target in targets}
    selected_bytes, index = {}, []
    with zipfile.ZipFile(apk) as archive:
        entries = [item for item in archive.infolist() if DEX_ENTRY.fullmatch(item.filename)]
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError("duplicate DEX ZIP entry name")
        if not entries:
            raise ValueError("APK/ZIP contains no supported root classes*.dex entries")
        for entry in entries:
            data = archive.read(entry)
            counts = dex_target_counts(data, targets)
            index.append({"entry": entry.filename, "bytes": len(data),
                          "target_class_counts": {k: v for k, v in counts.items() if v}})
            for target, count in counts.items():
                locations[target].extend([entry.filename] * count)
            if any(counts.values()):
                selected_bytes[entry.filename] = data
    return locations, selected_bytes, index


def method_identity(method):
    return method.get_class_name() + "->" + method.get_name() + re.sub(r"\s+", "", method.get_descriptor())


def check_supplier_description(method, candidate):
    """Reject a discovery supplier description that differs from supplied DEX."""
    if method.get_access_flags() & 8:
        return "supplier is static"
    instructions = list(method.get_instructions())
    if [item.get_name() for item in instructions] != candidate["opcodes"]:
        return "supplier opcode description does not match APK"
    actual_calls = []
    for instruction in instructions:
        if instruction.get_name().startswith("invoke-"):
            references = [item[2] for item in instruction.get_operands()
                          if len(item) > 2 and isinstance(item[2], str)]
            if len(references) != 1:
                return "supplier invocation has ambiguous references"
            actual_calls.append(re.sub(r"\s+", "", references[0]))
    if actual_calls != candidate["invokes"]:
        return "supplier call description does not match APK"
    return None


def analyze(apk, discovery_path):
    apk, discovery_path = Path(apk).resolve(), Path(discovery_path).resolve()
    discovery_bytes = discovery_path.read_bytes()
    discovery = json.loads(discovery_bytes)
    if discovery.get("schema") != 1 or discovery.get("report_only") is not True:
        raise ValueError("requires schema 1 report-only DexKit discovery")
    apk_digest = sha256(apk)
    declared_digest = discovery.get("input", {}).get("sha256")
    if declared_digest is not None and declared_digest != apk_digest:
        raise ValueError("discovery APK hash does not match --apk")
    sources = {display_path(path): sha256(path) for path in (
        Path(__file__), Path(__file__).with_name("supplier_semantics.py"),
        Path(__file__).with_name("GmsDexProbe.java"))}
    report = {
        "schema": 1, "report_only": True, "hook_profile_approved": False,
        "device_tested": False, "phone_operations": [], "gms_code_executed": False,
        "input": {"apk": {"path": display_path(apk), "sha256": apk_digest,
                            "bytes": apk.stat().st_size},
                  "discovery": {"path": display_path(discovery_path),
                                "sha256": hashlib.sha256(discovery_bytes).hexdigest()},
                  "discovery_declared_apk_hash_matches": True if declared_digest else None,
                  "discovery_source_sha256": discovery.get("source_sha256"),
                  "source_sha256": sources},
        "host": {"androguard_version": version("androguard")},
        "classification": "unsupported", "local_expression_accepted": False,
        "reason": "", "getters": {}, "suppliers": [],
        "dex": {"class_index": [], "fully_parsed_entries": []}, "limitations": LIMITS,
    }
    a_summary, a_getter = select_getter(discovery, KEY_A)
    b_summary, b_getter = select_getter(discovery, KEY_B)
    report["getters"] = {"A": a_summary, "B": b_summary}
    if a_getter is None:
        report["reason"] = "A getter selection rejected: " + a_summary["status"]
        return report
    if b_summary["status"] not in {"absent", "unique_shape_match"}:
        report["reason"] = "B getter selection rejected: " + b_summary["status"]
        return report
    a_contracts = sorted(set(a_getter["contracts"]))
    b_contracts = sorted(set(b_getter["contracts"])) if b_getter else []
    candidates = a_getter["supplier_candidates"]
    identities = [candidate["descriptor"] for candidate in candidates]
    report["supplier_candidate_descriptors"] = identities
    if len(candidates) != 1:
        report["reason"] = "supplier candidate count is not one; refusing absent/ambiguous selection"
        return report
    candidate = candidates[0]
    owner, _, parameters, returns = method_parts(candidate["descriptor"])
    if parameters or returns != "Ljava/lang/Object;" or candidate["modifiers"] & 8:
        report["reason"] = "supplier has an unsupported declared signature"
        return report
    locations, data, index = locate_supplier_dex(apk, {owner})
    report["dex"]["class_index"] = index
    report["dex"]["supplier_class_locations"] = locations
    if len(locations[owner]) != 1:
        report["reason"] = "supplier class definition is absent or ambiguous across APK DEX entries"
        return report
    entry = locations[owner][0]
    from loguru import logger
    from androguard.core.dex import DEX
    logger.disable("androguard")
    dex = DEX(data[entry])
    report["dex"]["fully_parsed_entries"] = [entry]
    report["dex"]["parsed_entry_sha256"] = hashlib.sha256(data[entry]).hexdigest()
    methods = [method for cls in dex.get_classes() if cls.get_name() == owner
               for method in cls.get_methods() if method_identity(method) == candidate["descriptor"]]
    if len(methods) != 1:
        report["reason"] = "supplier method definition is absent or ambiguous"
        return report
    mismatch = check_supplier_description(methods[0], candidate)
    if mismatch:
        report["reason"] = mismatch
        return report
    assumptions = candidate_assumptions(candidate, a_contracts, b_contracts)
    semantics = verify_supplier(methods[0], **assumptions)
    report["suppliers"] = [{"descriptor": candidate["descriptor"], "dex_entry": entry,
                            "assumptions_derived_from_candidate_evidence": True,
                            "assumptions_independently_proved": False,
                            "service_constructor_call_graph_consumers": candidate["service_constructor_consumers"],
                            "constructor_field_dataflow_proved": False, "semantics": semantics}]
    report["classification"] = semantics["classification"]
    report["local_expression_accepted"] = semantics["classification"] in {"PURE_A", "A_OR_B"}
    report["reason"] = semantics["reason"]
    return report


def output_path(value):
    destination = Path(value).resolve()
    if not destination.is_relative_to(ASSETS.resolve()) or destination.suffix != ".json":
        raise ValueError("--output must be a new .json file under moseyPLK-assets")
    if destination.exists():
        raise ValueError("--output already exists; preserve previous reports")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        destination = output_path(args.output)
        report = analyze(args.apk, args.discovery)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        print(f'{display_path(destination)}: {report["classification"]}; hook_profile_approved=false')
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"analysis rejected: {exc}\n")


if __name__ == "__main__":
    main()
