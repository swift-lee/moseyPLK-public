"""Host-only, deliberately narrow DEX supplier verifier.

Input is an Androguard EncodedMethod; no app classes are loaded or invoked.
Approved receiver accessors/fields and the service initialization read are
assumptions supplied by the caller, NOT facts established by this verifier.
This checks a local successful-return expression, not eligibility for a hook.
"""
from dataclasses import dataclass
import re


BOX = "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;"
OBJECT = "()Ljava/lang/Object;"
METHOD = re.compile(r"^(L[^;]+;)->([^()]+)\(([^)]*)\)(.+)$")
FIELD = re.compile(r"^(L[^;]+;)->([^:\s]+)(?::|\s+)(\[*(?:[ZBCSIJFD]|L[^;]+;))$")
MOVES = {"move", "move/16", "move/from16"}
OBJECT_MOVES = {"move-object", "move-object/16", "move-object/from16"}
CONSTS = {"const", "const/4", "const/16", "const/high16"}
CALLS = {"invoke-virtual", "invoke-virtual/range", "invoke-interface",
         "invoke-interface/range", "invoke-static", "invoke-static/range"}
BRANCHES = {"if-eqz", "if-nez", "goto", "goto/16", "goto/32"}
ALLOWED = MOVES | OBJECT_MOVES | CONSTS | CALLS | BRANCHES | {
    "sget", "sget-object", "move-result", "move-result-object", "return-object", "nop"}


class Unsupported(ValueError):
    pass


@dataclass(frozen=True)
class Step:
    offset: int
    length: int
    op: str
    registers: tuple
    reference: str | None = None
    literal: int | None = None
    target: int | None = None


@dataclass(frozen=True)
class Value:
    kind: str
    value: object
    descriptor: str = ""


def _method(value):
    value = re.sub(r"\s+", "", value)
    match = METHOD.fullmatch(value)
    if not match:
        raise Unsupported("invalid method descriptor")
    return value, match.groups()


def _field(value):
    match = FIELD.fullmatch(value.strip())
    if not match:
        raise Unsupported("invalid field descriptor (expected owner->name:type)")
    owner, name, field_type = match.groups()
    return f"{owner}->{name}:{field_type}", field_type


def _items(values):
    return (values,) if isinstance(values, str) else values


def _methods(values, result_kind):
    result = {}
    for value in _items(values):
        canonical, (owner, _, parameters, returns) = _method(value)
        if parameters or (returns != "Z" if result_kind == "bool"
                          else not (returns.startswith("L") and returns.endswith(";"))):
            raise Unsupported("approved calls must be no-argument methods of the required type")
        result[canonical] = (owner, returns)
    return result


def _fields(values, kind):
    result = {}
    for value in _items(values):
        canonical, descriptor = _field(value)
        if (kind == "init" and descriptor != "I") or (
                kind == "root" and not descriptor.startswith("L")):
            raise Unsupported("approved field has an unsupported type")
        result[canonical] = descriptor
    return result


def _decode(method):
    if re.sub(r"\s+", "", method.get_descriptor()) != OBJECT:
        raise Unsupported("requires a no-argument method declared to return java.lang.Object")
    code = method.get_code()
    if code is None:
        raise Unsupported("method has no DEX code")
    if code.get_tries_size():
        raise Unsupported("exception handlers are outside the accepted templates")
    if method.get_access_flags() & (0x20 | 0x20000):
        raise Unsupported("synchronized method is outside the accepted templates")
    register_count = code.get_registers_size()
    incoming = 0 if method.get_access_flags() & 8 else 1
    if code.get_ins_size() != incoming or register_count < incoming:
        raise Unsupported("inconsistent no-argument register frame")
    steps = []
    expected_offset = 0
    for offset, ins in method.get_instructions_idx():
        op = ins.get_name()
        if op not in ALLOWED:
            raise Unsupported(f"unsupported opcode {op} at {offset}")
        if offset != expected_offset or ins.get_length() <= 0:
            raise Unsupported("non-contiguous instruction boundaries")
        operands = ins.get_operands()
        registers = tuple(int(item[1]) for item in operands if int(item[0]) == 0)
        if any(r < 0 or r >= register_count for r in registers):
            raise Unsupported("register outside the method frame")
        refs = [item[2] for item in operands if len(item) > 2 and isinstance(item[2], str)]
        literals = [int(item[1]) for item in operands if int(item[0]) == 1]
        if len(refs) > 1 or len(literals) > 1:
            raise Unsupported("ambiguous instruction operands")
        reference = refs[0] if refs else None
        if op in CALLS:
            if reference is None:
                raise Unsupported("call without a method reference")
            reference = _method(reference)[0]
        elif op in {"sget", "sget-object"}:
            if reference is None:
                raise Unsupported("field read without a reference")
            reference = _field(reference)[0]
        target = offset + 2 * ins.get_ref_off() if op in BRANCHES else None
        steps.append(Step(offset, ins.get_length(), op, registers, reference,
                          literals[0] if literals else None, target))
        expected_offset = offset + ins.get_length()
        if len(steps) > 128:
            raise Unsupported("method exceeds the bounded template size")
    if not steps:
        raise Unsupported("empty method")
    return steps, register_count, incoming


def _graph(steps):
    by_offset = {s.offset: s for s in steps}
    edges = {}
    for s in steps:
        following = s.offset + s.length
        if s.op == "return-object":
            successors = ()
        elif s.op.startswith("goto"):
            successors = (s.target,)
        elif s.op.startswith("if-"):
            successors = (s.target, following)
        else:
            successors = (following,)
        if any(target not in by_offset for target in successors):
            raise Unsupported("branch/fallthrough target is not an instruction boundary")
        edges[s.offset] = successors
    visiting, visited = set(), set()

    def walk(offset):
        if offset in visiting:
            raise Unsupported("control-flow cycle is outside the accepted templates")
        if offset in visited:
            return
        visiting.add(offset)
        for target in edges[offset]:
            walk(target)
        visiting.remove(offset)
        visited.add(offset)
    walk(0)
    if visited != set(by_offset):
        raise Unsupported("unreachable instructions are outside the accepted templates")
    return by_offset


def _execute(steps, register_count, incoming, a, b, rules):
    a_calls, b_calls, accessors, init_fields, roots = rules
    registers = {}
    if incoming:
        registers[register_count - 1] = Value("this", None)
    offset, pending = 0, None
    trace, access_count = [], 0
    steps_taken = 0

    def reg(number):
        if number not in registers:
            raise Unsupported(f"read of undefined register v{number}")
        return registers[number]

    def arity(s, count):
        if len(s.registers) != count:
            raise Unsupported(f"unexpected register arity for {s.op}")

    while True:
        steps_taken += 1
        if steps_taken > 128:
            raise Unsupported("execution step bound exceeded")
        s = steps[offset]
        op, rs = s.op, s.registers
        following = offset + s.length
        if pending is not None and op not in {"move-result", "move-result-object"}:
            raise Unsupported("an invocation result is not consumed immediately")
        if op in {"sget", "sget-object"}:
            arity(s, 1)
            if op == "sget" and s.reference in init_fields:
                registers[rs[0]] = Value("init_read", s.reference, "I")
            elif op == "sget-object" and s.reference in roots:
                registers[rs[0]] = Value("root", s.reference, roots[s.reference])
            else:
                raise Unsupported("unapproved field read")
        elif op in MOVES | OBJECT_MOVES:
            arity(s, 2)
            value = reg(rs[1])
            object_value = value.kind in {"root", "receiver", "boxed", "this"}
            if object_value != (op in OBJECT_MOVES):
                raise Unsupported("move kind does not match the register value")
            registers[rs[0]] = value
        elif op in CONSTS:
            arity(s, 1)
            if s.literal not in (0, 1):
                raise Unsupported("only Boolean integer literals 0 and 1 are supported")
            registers[rs[0]] = Value("bool", bool(s.literal), "Z")
        elif op in {"move-result", "move-result-object"}:
            arity(s, 1)
            if pending is None:
                raise Unsupported("move-result without an immediately preceding invocation")
            if (pending.kind == "bool") != (op == "move-result"):
                raise Unsupported("move-result kind does not match invocation result")
            registers[rs[0]], pending = pending, None
        elif op in CALLS:
            arity(s, 1)
            receiver = reg(rs[0])
            if s.reference == BOX:
                if not op.startswith("invoke-static") or receiver.kind != "bool":
                    raise Unsupported("Boolean.valueOf must box the verified Boolean register")
                pending = Value("boxed", receiver.value, "Ljava/lang/Boolean;")
            elif s.reference in a_calls or s.reference in b_calls or s.reference in accessors:
                if op.startswith("invoke-static"):
                    raise Unsupported("getter/accessor must use an instance invocation")
                definition = (a_calls.get(s.reference) or b_calls.get(s.reference)
                              or accessors[s.reference])
                if receiver.kind not in {"root", "receiver"} or receiver.descriptor != definition[0]:
                    raise Unsupported("receiver does not flow from an approved field/accessor of its owner type")
                if s.reference in accessors:
                    pending = Value("receiver", s.reference, definition[1])
                    access_count += 1
                else:
                    label = "A" if s.reference in a_calls else "B"
                    trace.append(label)
                    pending = Value("bool", a if label == "A" else b, "Z")
            else:
                raise Unsupported(f"unapproved invocation {s.reference}")
        elif op in {"if-eqz", "if-nez"}:
            arity(s, 1)
            condition = reg(rs[0])
            if condition.kind != "bool":
                raise Unsupported("branch condition is not a verified Boolean")
            taken = condition.value if op == "if-nez" else not condition.value
            if taken:
                following = s.target
        elif op.startswith("goto"):
            arity(s, 0)
            following = s.target
        elif op == "return-object":
            arity(s, 1)
            value = reg(rs[0])
            if value.kind != "boxed":
                raise Unsupported("return value is not the verified Boolean.valueOf result")
            if access_count != len(trace):
                raise Unsupported("accessor/getter invocation counts do not match the narrow templates")
            return {"A": a, "B": b, "result": value.value, "getters": trace,
                    "receiver_accessor_calls": access_count}
        elif op == "nop":
            arity(s, 0)
        offset = following


def verify_supplier(method, *, a_getters, b_getters=(), receiver_accessors=(),
                    service_init_fields=(), receiver_fields=()):
    """Return PURE_A, A_OR_B or unsupported plus evidence/explicit assumptions.

    Method refs: ``Lowner;->name()Z`` (spaces are ignored).
    Field refs: ``Lowner;->name:type`` or Androguard's ``Lowner;->name type``.
    Approved getters/accessors must be no-argument instance calls. The caller
    must separately establish their meaning, receiver construction/dispatch,
    namespace, constructor consumers, provenance and runtime applicability.
    """
    assumptions = {
        "getter_A": list(_items(a_getters)), "getter_B": list(_items(b_getters)),
        "receiver_accessors": list(_items(receiver_accessors)),
        "service_initialization_fields": list(_items(service_init_fields)),
        "receiver_fields": list(_items(receiver_fields)),
        "not_proven": ["getter meaning or namespace", "accessor/field semantics or dispatch",
                       "supplier construction, memoization or downstream consumers",
                       "APK/classloader provenance or runtime hook safety",
                       "exception/side-effect equivalence of a result override"]}
    result = {"classification": "unsupported", "reason": "", "cases": [],
              "assumptions": assumptions}
    try:
        a_calls = _methods(assumptions["getter_A"], "bool")
        b_calls = _methods(assumptions["getter_B"], "bool")
        accessors = _methods(assumptions["receiver_accessors"], "ref")
        roots = _fields(assumptions["receiver_fields"], "root")
        init_fields = _fields(assumptions["service_initialization_fields"], "init")
        if not a_calls or set(a_calls) & set(b_calls) or (
                (set(a_calls) | set(b_calls)) & set(accessors)) or BOX in accessors:
            raise Unsupported("missing or overlapping approved call roles")
        decoded, count, incoming = _decode(method)
        for instruction in decoded:
            # Reject extra operations even on a path that the four Boolean
            # assignments happen not to execute (for example a constant guard).
            if instruction.op in CALLS and instruction.reference not in (
                    set(a_calls) | set(b_calls) | set(accessors) | {BOX}):
                raise Unsupported(f"unapproved invocation {instruction.reference}")
            if instruction.op == "sget" and instruction.reference not in init_fields:
                raise Unsupported("unapproved initialization field read")
            if instruction.op == "sget-object" and instruction.reference not in roots:
                raise Unsupported("unapproved receiver field read")
        steps = _graph(decoded)
        rules = a_calls, b_calls, accessors, init_fields, roots
        cases = [_execute(steps, count, incoming, a, b, rules)
                 for a, b in ((False, False), (False, True), (True, False), (True, True))]
        result["cases"] = cases
        if all(c["result"] == c["A"] and c["getters"] == ["A"] for c in cases):
            result.update(classification="PURE_A", reason="all four inputs return boxed A with one A read")
        elif b_calls and all(c["result"] == (c["A"] or c["B"])
                             and c["getters"] == (["A"] if c["A"] else ["A", "B"])
                             for c in cases):
            result.update(classification="A_OR_B", reason="all four inputs implement short-circuit A || B")
        else:
            result["reason"] = "truth table or getter evaluation order differs from PURE_A / short-circuit A_OR_B"
    except (Unsupported, AttributeError, TypeError, ValueError, IndexError) as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"
    return result
