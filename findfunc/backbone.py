import enum
import fnmatch
from typing import List


class InstrWildcardOp(object):
    """
    Custom format to hold information about the operand of an instruction.
    This is used both for dissassembly and Code Rules entered by the user.
    """
    def __init__(self):
        self.basereg = None
        self.indexreg = None
        self.scale = 1
        self.displ = 0
        self.deref = False
        self.size = 0

    def __str__(self):
        string = f"{self.basereg} + {self.indexreg} * {self.scale} + {self.displ} (@{self.size})"
        if self.deref:
            return "[" + string + "]"
        return string


class InstrWildcard(object):
    """
    Custom format to hold information about an instruction.
    This is used both for dissassembly and Code Rules entered by the user.
    """
    def __init__(self):
        self.va = 0
        self.mmn = ""  # can be "any" to match all
        self.ops = []

    def __str__(self):
        r = f"[{hex(self.va)}]: {self.mmn}"
        for op in self.ops:
            r += " " + str(op) + ","
        return r

    def __eq__(self, other):
        """
        Dont compare them directly, as matching is much more complex than that.
        See matcher_ida.py
        """
        raise NotImplementedError("Dont compmare instructions directly.")
        return NotImplemented

    @staticmethod
    def is_int(var) -> bool:
        """
        Check if string is a valid int.
        Can be "imm" or hex value or decimal value.
        :param var: string to check
        :return: integer or "imm"
        """
        return InstrWildcard.parse_int(var) is not None

    @staticmethod
    def parse_int(var):
        """
        Convert string to int.
        Can be "imm" or hex value or decimal value.
        :param var: string to convert
        :return: int or "imm"
        """
        if var == "imm":
            return var
        try:
            if str(var).endswith('h'):
                return int(str(var)[:-1], 16)
            r = int(var)
        except ValueError:
            try:
                r = int(var, 16)
            except ValueError:
                return None
        return r

    @staticmethod
    def parse_from_str(ins: str):
        """
        Parse a user-entered Instruction string (as part of a Code Rule).
        May throw exceptions on parsing error!
        :param ins: instruction string
        :return: converted instruction
        """
        result = InstrWildcard()
        idx = ins.find(' ')
        if idx == -1:  # no args
            result.mmn = ins
            return result
        result.mmn = ins[0:idx]  # doesnt support prefixes
        result.mmn = "".join(result.mmn.split())  # remove all whitespace
        ins = ins[idx:]
        ins = "".join(ins.split())  # remove all whitespace
        # [reg + imm], [reg], [imm], [reg + reg * 1 + 555]
        for o in ins.split(','):
            op = InstrWildcardOp()
            if '[' in o:
                if "qword" in o:
                    op.size = 8
                    o = o.replace("qwordptr", "").replace("qword", "")
                elif "dword" in o:
                    op.size = 4
                    o = o.replace("dwordptr", "").replace("dword", "")
                elif "word" in o:
                    op.size = 2
                    o = o.replace("wordptr", "").replace("word", "")
                elif "byte" in o:
                    op.size = 1
                    o = o.replace("byteptr", "").replace("byte", "")
                else:
                    op.size = None  # determining right size is very complex (movzx, etc.)
                op.deref = True
                o = o.replace('[', '').replace(']', '')
            isneg = o.find('-') != -1
            opdata = o.replace('+', ' ').replace('-', ' ').replace('*', ' ')
            opdata = opdata.split()
            if len(opdata) == 0:
                pass
            elif len(opdata) == 1:  # reg,c,[reg],[c]
                if InstrWildcard.is_int(opdata[0]):
                    op.displ = InstrWildcard.parse_int(opdata[0])
                else:
                    op.basereg = opdata[0]
            elif len(opdata) == 2:  # [reg+reg],[reg+c]
                op.basereg = opdata[0]  # always reg
                if InstrWildcard.is_int(opdata[1]):
                    op.displ = InstrWildcard.parse_int(opdata[1])
                else:
                    op.indexreg = opdata[1]
            elif len(opdata) == 3:  # [reg+reg*c]
                op.basereg = opdata[0]  # always reg
                op.indexreg = opdata[1]  # always reg
                op.scale = InstrWildcard.parse_int(opdata[2])  # always scale
            elif len(opdata) == 4:  # [reg+reg*c+c]
                op.basereg = opdata[0]  # always reg
                op.indexreg = opdata[1]  # always reg
                op.scale = InstrWildcard.parse_int(opdata[2])  # always scale
                op.displ = InstrWildcard.parse_int(opdata[3])  # always displ
            if isneg:
                op.displ = op.displ * -1
                # we may need to extend some value here if we are not neg... todo alighn with ida.decode
            result.ops.append(op)
        return result


class RuleType(enum.Enum):
    unk = "Invalid"
    imm = "Immediate"
    str = "StringRef"
    name = "NameRef"
    pattern = "BytePattern"
    code = "CodePattern"
    fsize = "FunctionSize"


class Rule(object):
    """
    Base class for Rules.
    """
    def __init__(self, typ: RuleType):
        self.typ = typ
        self.enabled = True
        self.inverted = False

    def __str__(self):
        return f"Rule<{self.typ}>"

    def get_data(self):
        pass

    def set_data(self, data):
        pass

    def is_editable(self) -> bool:
        return True


class RuleFuncSize(Rule):
    """
    Rule for filtering by function size.
    examples:
    0,999  ->  functions smaller than 999 bytes
    500,1000 -> functions 500 bytes or larger and smaller than 1000 bytes
    """
    maxmax = 999999

    def __init__(self):
        super().__init__(RuleType.fsize)
        self.min = 0
        self.max = self.maxmax

    def __repr__(self):
        return f"RuleFuncSize({self.min},{self.max})"

    def get_data(self):
        return f"{self.min} <= x <= {self.max}"

    def set_data(self, data: str):
        """
        Parse user data in form "x,y" where x is minimum function size and
        y maximum.
        The rule will match any function whose size is x <= size <= y.
        :param data: input data
        :return: Nothing
        """
        if data.endswith(","):
            data += str(self.maxmax)
        data = data.replace(",", " ")
        data = data.split()
        if len(data) == 2:
            mmin = InstrWildcard.parse_int(data[0])
            mmax = InstrWildcard.parse_int(data[1])
            self.min = mmin
            self.max = mmax

    def checksize(self, size: int) -> bool:
        """
        Perform function size check
        :param size: size of functio to check
        :return: True if satisfied, False otherwise
        """
        return self.min <= size <= self.max


class RuleImmediate(Rule):
    """
    Rule for filtering function based on them referencing a given immediate value.
    The value may be referenced anywhere in the function.
    """
    def __init__(self, imm):
        super().__init__(RuleType.imm)
        self.imm = InstrWildcard.parse_int(imm)

    def __repr__(self):
        return f"RuleImmediate({self.imm})"

    def get_data(self):
        return hex(self.imm)

    def set_data(self, data):
        if isinstance(data, int):
            self.imm = data
        else:
            self.imm = InstrWildcard.parse_int(data)


class RuleStrRef(Rule):
    """
    Rule for filtering function based on them referencing a given string.
    The string may be referenced anywhere in the function.
    Supports wildcard matching by fnmatch. See fnmatch for details.
    examples:
    Success
    Succ*
    """
    def __init__(self, targetstr: str):
        super().__init__(RuleType.str)
        self.str = targetstr
        self.refs = []

    def __repr__(self):
        return f"RuleStrRef(\"{self.str}\")"

    def matches(self, s: str) -> bool:
        return fnmatch.fnmatch(s, self.str)

    def get_data(self):
        return self.str

    def set_data(self, data):
        self.str = str(data)


class RuleNameRef(Rule):
    """
    Rule for filtering function based on them referencing a given name/label.
    The name/label may be referenced anywhere in the function.
    Supports wildcard matching by fnmatch. See fnmatch for details.
    examples:
    sub_123456
    sub_123*
    """
    def __init__(self, name):
        super().__init__(RuleType.name)
        self.name = name
        self.refs = []

    def __repr__(self):
        return f"RuleNameRef(\"{self.name}\")"

    def matches(self, s: str) -> bool:
        return fnmatch.fnmatch(s, self.name)

    def get_data(self):
        return self.name

    def set_data(self, data):
        self.name = str(data)


class RuleBytePattern(Rule):
    """
    Rule for filtering function based on them containing a given byte pattern.
    Supports wildcard matching by IDAs binary search. See IDA for details.
    examples:
    11 22 ff cc
    11 ?? ?? cc
    """
    def __init__(self, pattern):
        super().__init__(RuleType.pattern)
        self.pattern = pattern
        self.patterncompiled = None

    def __repr__(self):
        return f"RuleBytePattern(\"{self.pattern}\")"

    @staticmethod
    def is_raw_pattern(pattern: str) -> bool:
        try:
            pattern = pattern.replace(" ", "").replace("??", "")
            return len(bytes.fromhex(pattern)) > 1 and len(pattern) > 2
        except ValueError:
            return False

    def get_data(self):
        return self.pattern

    def set_data(self, data):
        self.pattern = str(data)


class RuleCode(Rule):
    """
    Rule for filtering function based on them containing a given code snippet.
    Supports special wildlcard matching:

    "pass" -> matches any instruction with any operands
    "mov* any,any" -> matches instructions with mmn "mov*" (e.g. mov, movzx, ...)
                        and any two arguments.
    "mov eax, r32" -> matches any instruction with mmn "mov", first operand register eax
                        and second operand any 32-bit register.
                        Analogue: r for any register, r8/r16/r32/r64
    "mov r64, imm"   -> matches any move of a constant to a 64bit register
    more examples:
    mov r64, [r32 * 8 + 0x100]
    mov r64, [r32 * 8 - 0x100]
    mov r64, [r32 * 8 + imm]
    mov r, [r32 + r32 * 8 - 0x100]
    push imm
    push r
    """
    def __init__(self, instrlist):
        super().__init__(RuleType.code)
        self.instr_string = []
        self.instr = []
        self.set_data(instrlist)
        self.current = 0

    def __repr__(self):
        return f"RuleCode({repr(self.instr_string)})"

    def get_data(self):
        return str(self.instr_string)

    def set_data(self, data):
        if not data:
            return
        if type(data) != list:
            data = [data]
        data = [x.strip() for x in data if x.strip()]
        instr = [InstrWildcard.parse_from_str(x) for x in data]
        self.instr = instr
        self.instr_string = data
        self.clearcurrent()

    def is_editable(self) -> bool:
        return False

    def advance(self):
        self.current = self.current + 1

    def clearcurrent(self):
        self.current = 0

    def curinstr(self) -> InstrWildcard:
        return self.instr[self.current]

    def is_satisfied(self) -> bool:
        return len(self.instr) == self.current


def to_clipboard_string(data: List[Rule]) -> str:
    """
    Converts a list of rules to string for copying
    :param data: list of rules
    :return: list of rules as string
    """
    ret = ""
    for r in data:
        if isinstance(r, RuleFuncSize):
            ret += f"RuleFuncSize {r.enabled} {r.inverted} {r.min} {r.max}" + "\n"
        elif isinstance(r, RuleImmediate):
            ret += f"RuleImmediate {r.enabled} {r.inverted} {r.imm}" + "\n"
        elif isinstance(r, RuleStrRef):
            ret += f"RuleStrRef {r.enabled} {r.inverted} {r.str}" + "\n"
        elif isinstance(r, RuleNameRef):
            ret += f"RuleNameRef {r.enabled} {r.inverted} {r.name}" + "\n"
        elif isinstance(r, RuleBytePattern):
            ret += f"RuleBytePattern {r.enabled} {r.inverted} {r.pattern}" + "\n"
        elif isinstance(r, RuleCode):
            ret += f"RuleCode {r.enabled} {r.inverted} {';;'.join(r.instr_string)}" + "\n"
    return ret


def from_clipboard_string(data: str) -> List[Rule]:
    """
    Converts a string to a list of rules
    :param data: list of rules as string
    :return: string as list of rules
    """
    # allow pasting hexstring directly
    if RuleBytePattern.is_raw_pattern(data):
        return [RuleBytePattern(data)]
    ret = []
    for string in data.split("\n"):
        tokens = string.split(" ")[:3]  # 3 -> RuleName enabled inverted
        if len(tokens) != 3:
            continue
        rulename = tokens[0]
        enabled = tokens[1].lower() == "true"
        inverted = tokens[2].lower() == "true"
        string = string[len(" ".join(tokens)) + 1:]
        rule = None
        if rulename == "RuleFuncSize":
            rule = RuleFuncSize()
            rule.set_data(string)
        elif rulename == "RuleImmediate":
            rule = RuleImmediate(string)
        elif rulename == "RuleStrRef":
            rule = RuleStrRef(string)
        elif rulename == "RuleNameRef":
            rule = RuleNameRef(string)
        elif rulename == "RuleBytePattern":
            rule = RuleBytePattern(string)
        elif rulename == "RuleCode":
            instructions = string.split(";;")
            rule = RuleCode(instructions)
        if rule:
            rule.enabled = enabled
            rule.inverted = inverted
            ret.append(rule)
    return ret
