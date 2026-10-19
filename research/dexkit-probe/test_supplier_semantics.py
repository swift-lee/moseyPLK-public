"""Small host fixtures; no APK, Android runtime or device is required."""
from dataclasses import dataclass
import unittest

from supplier_semantics import BOX, verify_supplier


A = "LFlags;->renamedA()Z"
B = "LFlags;->renamedB()Z"
ACCESSOR = "LHolder;->renamedAccessor()LFlags;"
ROOT = "LHolder;->instance LHolder;"
INIT = "LService;->trigger I"
RULES = dict(a_getters={A}, b_getters={B}, receiver_accessors={ACCESSOR},
             receiver_fields={ROOT}, service_init_fields={INIT})


@dataclass
class Instruction:
    name: str
    regs: tuple = ()
    reference: str | None = None
    literal: int | None = None
    target: int | None = None
    offset: int = 0
    target_byte: int | None = None

    def get_name(self): return self.name
    def get_length(self): return 6 if self.name.startswith("invoke-") else 2
    def get_operands(self):
        result = [(0, r) for r in self.regs]
        if self.reference is not None:
            result.append((256 if self.name.startswith("invoke-") else 258, 0, self.reference))
        if self.literal is not None:
            result.append((1, self.literal))
        if self.target is not None:
            result.append((3, self.get_ref_off()))
        return result
    def get_ref_off(self): return (self.target_byte - self.offset) // 2


class Method:
    def __init__(self, instructions, *, tries=0, descriptor="()Ljava/lang/Object;"):
        self.instructions = instructions
        self.tries, self.descriptor = tries, descriptor
        offset = 0
        for instruction in instructions:
            instruction.offset = offset
            offset += instruction.get_length()
        for instruction in instructions:
            if instruction.target is not None:
                instruction.target_byte = (instructions[instruction.target].offset
                                           if 0 <= instruction.target < len(instructions)
                                           else offset + 100)
    def get_descriptor(self): return self.descriptor
    def get_access_flags(self): return 17
    def get_code(self): return self
    def get_tries_size(self): return self.tries
    def get_registers_size(self): return 4
    def get_ins_size(self): return 1
    def get_instructions_idx(self): return [(i.offset, i) for i in self.instructions]


def prefix():
    return [Instruction("sget", (3,), INIT), Instruction("sget-object", (0,), ROOT),
            Instruction("invoke-virtual", (0,), ACCESSOR),
            Instruction("move-result-object", (1,)),
            Instruction("invoke-interface", (1,), A), Instruction("move-result", (1,))]


def pure():
    return prefix() + [Instruction("invoke-static", (1,), BOX),
                       Instruction("move-result-object", (2,)),
                       Instruction("return-object", (2,))]


def disjunction():
    return prefix() + [Instruction("const/4", (2,), literal=1),
                       Instruction("if-nez", (1,), target=15),
                       Instruction("invoke-virtual", (0,), ACCESSOR),
                       Instruction("move-result-object", (1,)),
                       Instruction("invoke-interface", (1,), B),
                       Instruction("move-result", (1,)),
                       Instruction("if-eqz", (1,), target=14),
                       Instruction("goto", target=15),
                       Instruction("const/4", (2,), literal=0),
                       Instruction("invoke-static", (2,), BOX),
                       Instruction("move-result-object", (2,)),
                       Instruction("return-object", (2,))]


class SupplierSemanticsTests(unittest.TestCase):
    def check_kind(self, instructions, expected, **method_args):
        result = verify_supplier(Method(instructions, **method_args), **RULES)
        self.assertEqual(result["classification"], expected, result)
        return result

    def test_pure_a(self):
        result = self.check_kind(pure(), "PURE_A")
        self.assertEqual([c["result"] for c in result["cases"]], [False, False, True, True])
        self.assertTrue(result["assumptions"]["not_proven"])

    def test_short_circuit_or(self):
        result = self.check_kind(disjunction(), "A_OR_B")
        self.assertEqual([c["getters"] for c in result["cases"]],
                         [["A", "B"], ["A", "B"], ["A"], ["A"]])

    def test_and_rejected(self):
        code = disjunction()
        code[7].name, code[7].target = "if-eqz", 14
        result = self.check_kind(code, "unsupported")
        self.assertEqual([c["result"] for c in result["cases"]], [False, False, False, True])

    def test_same_opcodes_different_branch_target_rejected(self):
        code = disjunction()
        code[7].target = 14
        self.assertEqual([i.name for i in code], [i.name for i in disjunction()])
        self.check_kind(code, "unsupported")

    def test_not_a_rejected(self):
        code = prefix() + [Instruction("if-eqz", (1,), target=9),
                           Instruction("const/4", (1,), literal=0),
                           Instruction("goto", target=10),
                           Instruction("const/4", (1,), literal=1),
                           Instruction("invoke-static", (1,), BOX),
                           Instruction("move-result-object", (2,)),
                           Instruction("return-object", (2,))]
        self.check_kind(code, "unsupported")

    def test_constant_with_same_getter_rejected(self):
        code = pure()
        code.insert(6, Instruction("const/4", (1,), literal=1))
        self.check_kind(code, "unsupported")

    def test_boxing_wrong_register_rejected(self):
        code = pure()
        code[6].regs = (0,)
        self.check_kind(code, "unsupported")

    def test_service_init_read_may_not_drive_result(self):
        code = pure()
        code[6].regs = (3,)
        self.check_kind(code, "unsupported")

    def test_wrong_receiver_rejected(self):
        code = pure()
        code[4].regs = (0,)
        self.check_kind(code, "unsupported")

    def test_unknown_invocation_rejected(self):
        code = pure()
        code[4].reference = "LFlags;->unreviewed()Z"
        self.check_kind(code, "unsupported")

    def test_unknown_invocation_in_constant_dead_arm_rejected(self):
        code = prefix() + [Instruction("const/4", (2,), literal=1),
                           Instruction("if-nez", (2,), target=10),
                           Instruction("invoke-interface", (0,), "LHolder;->unreviewed()Z"),
                           Instruction("move-result", (2,)),
                           Instruction("invoke-static", (1,), BOX),
                           Instruction("move-result-object", (2,)),
                           Instruction("return-object", (2,))]
        self.check_kind(code, "unsupported")

    def test_unapproved_field_rejected(self):
        code = pure()
        code[1].reference = "LHolder;->different LHolder;"
        self.check_kind(code, "unsupported")

    def test_field_write_rejected(self):
        code = pure()
        code.insert(6, Instruction("sput", (1,), INIT))
        self.check_kind(code, "unsupported")

    def test_loop_rejected(self):
        code = disjunction()
        code[7].target = 7
        result = self.check_kind(code, "unsupported")
        self.assertIn("cycle", result["reason"])

    def test_target_between_instruction_boundaries_rejected(self):
        method = Method(disjunction())
        method.instructions[7].target_byte = method.instructions[8].offset + 2
        result = verify_supplier(method, **RULES)
        self.assertEqual(result["classification"], "unsupported")
        self.assertIn("instruction boundary", result["reason"])

    def test_exception_handler_rejected(self):
        self.check_kind(pure(), "unsupported", tries=1)

    def test_other_declared_return_rejected(self):
        self.check_kind(pure(), "unsupported", descriptor="()Ljava/lang/Boolean;")

    def test_overlapping_getter_roles_rejected(self):
        result = verify_supplier(Method(pure()), **{**RULES, "b_getters": {A}})
        self.assertEqual(result["classification"], "unsupported")

    def test_move_and_encoding_variants(self):
        code = pure()
        code[2].name = "invoke-virtual/range"
        code[4].name = "invoke-interface/range"
        code[6].name = "invoke-static/range"
        code.insert(6, Instruction("move/from16", (2, 1)))
        code[7].regs = (2,)
        self.check_kind(code, "PURE_A")


if __name__ == "__main__":
    unittest.main(verbosity=2)
