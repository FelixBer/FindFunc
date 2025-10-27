import copy
from typing import Iterable

from findfunc.backbone import *

try:
    from PyQt5.QtWidgets import QApplication
except ImportError:
    QApplication = None

inida = True
try:
    # from idaapi import PluginForm
    import idaapi
    import idautils
    import idc
    import ida_search
    import ida_bytes
    import ida_name
    import ida_allins
    import ida_ua
    import ida_ida #IDA 9
except:
    inida = False

### stuff taken from IDAs intel.hpp
### see intel.hpp for information

# // Intel 80x86 insn_t.auxpref bits
aux_natop = 0x00000800  # // operand size is not overridden by prefix
aux_natad = 0x00001000  # // addressing mode is not overridden by prefix
aux_use32 = 0x00000008  # // segment type is 32-bits
aux_use64 = 0x00000010  # // segment type is 64-bits
# // bits in insn_t.rex:
REX_W = 8  # // 64-bit operand size
REX_R = 4  # // modrm reg field extension
REX_X = 2  # // sib index field extension
REX_B = 1  # // modrm r/m, sib base, or opcode reg fields extension
VEX_L = 0x80  # // 256-bit operation (YMM register)


def ida_is_op_16(insn):
    insn.rex = insn.insnpref
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natop)
    a = p == aux_natop  # // 16-bit segment, no prefixes
    b = p == aux_use32  # // 32-bit segment, 66h
    c = p == aux_use64 and (insn.rex & REX_W) == 0  # // 64-bit segment, 66h, no rex.w
    return a or b or c


def ida_is_op_32(insn):
    insn.rex = insn.insnpref
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natop)
    a = p == 0  # // 16-bit segment, 66h
    b = p == (aux_use32 | aux_natop)  # // 32-bit segment, no prefixes
    c = p == (aux_use64 | aux_natop) and (insn.rex & REX_W) == 0  # // 64-bit segment, 66h, no rex.w
    return a or b or c


def ida_is_op_64(insn):
    insn.rex = insn.insnpref
    a = (insn.auxpref & aux_use64) != 0
    b = (insn.rex & REX_W) != 0
    # // 64-bit segment, rex.w or insns-64
    c = ((insn.auxpref & aux_natop) != 0) and ida_insn_default_opsize_64(insn)
    return (a and b) or c


def ida_insn_default_opsize_64(insn):
    jcc = (ida_allins.NN_pop, ida_allins.NN_popf, ida_allins.NN_popfq, ida_allins.NN_push, ida_allins.NN_pushf,
           ida_allins.NN_pushfq, ida_allins.NN_retn, ida_allins.NN_retf, ida_allins.NN_retnq, ida_allins.NN_retfq,
           ida_allins.NN_call, ida_allins.NN_callfi, ida_allins.NN_callni, ida_allins.NN_enter,
           ida_allins.NN_enterq, ida_allins.NN_leave, ida_allins.NN_leaveq)

    ss = (ida_allins.NN_jcxz, ida_allins.NN_jecxz, ida_allins.NN_jrcxz, ida_allins.NN_jmp, ida_allins.NN_jmpni,
          ida_allins.NN_jmpshort, ida_allins.NN_loop, ida_allins.NN_loopq, ida_allins.NN_loope,
          ida_allins.NN_loopqe, ida_allins.NN_loopne, ida_allins.NN_loopqne)

    nearbranch = {ida_allins.NN_ja, ida_allins.NN_jae, ida_allins.NN_jb, ida_allins.NN_jbe, ida_allins.NN_jc,
                  ida_allins.NN_je,
                  ida_allins.NN_jg, ida_allins.NN_jge, ida_allins.NN_jl, ida_allins.NN_jle, ida_allins.NN_jna,
                  ida_allins.NN_jnae, ida_allins.NN_jnb, ida_allins.NN_jnbe, ida_allins.NN_jnc, ida_allins.NN_jne,
                  ida_allins.NN_jng, ida_allins.NN_jnge, ida_allins.NN_jnl, ida_allins.NN_jnle, ida_allins.NN_jno,
                  ida_allins.NN_jnp, ida_allins.NN_jns, ida_allins.NN_jnz, ida_allins.NN_jo, ida_allins.NN_jp,
                  ida_allins.NN_jpe, ida_allins.NN_jpo, ida_allins.NN_js, ida_allins.NN_jz}

    insnr = insn.itype
    if insnr in jcc or insnr in ss or insnr in nearbranch:
        return True
    return False


def ida_is_ad_16(insn):
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return p == aux_natad or p == aux_use32


def ida_is_ad_64(insn):
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return p == (aux_natad | aux_use64)


def ida_is_ad_32(insn):
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return p == (aux_natad | aux_use32) or p == 0 or p == aux_use64


def ida_get_insn_admode(insn):
    if ida_is_ad_64(insn):
        return 8
    if ida_is_ad_32(insn):
        return 4
    if ida_is_ad_16(insn):
        return 2
    return None


### end ida.hpp

def gui_jump_to_va(va: int):
    """
    jump to given va in IDA and switch to window
    """
    if inida:
        idaapi.jumpto(va)


class Config:
    """
    Contains various information about IDA context, e.g.
    pointersize of current processor, considered string-types,
    or image-range
    """
    def __init__(self):
        self.debug = False
        self.profile = False
        self.warnedfar = False
        if not inida:
            self.strtypes = []
            self.startva = 0
            self.endva = 0
            self.ptrsize = 8
            return
        # types of strings considered by String matching rule
        self.strtypes = [idaapi.STRTYPE_C, idaapi.STRTYPE_C_16]
        # image base
        self.startva = idaapi.get_imagebase()
        # image end
        self.endva = idaapi.get_last_seg().end_ea
        # size of pointer of current proc module
        try:
            # since IDA 9
            is64 = ida_ida.idainfo_is_64bit()
            is32 = ida_ida.idainfo_is_32bit()
        except:
            info = idaapi.get_inf_structure()
            is64 = info.is_64bit()
            is32 = info.is_32bit()
        if is64:
            self.ptrsize = 8
        elif is32:
            self.ptrsize = 4
        else:
            assert "processor must be x64 or x86"

    def __str__(self):
        return f"config: [{hex(self.startva)} - {hex(self.endva)}] @{self.ptrsize} ({str(self.strtypes)})"


class Func:
    """
    Helper class represent a function to be matched.
    """
    def __init__(self):
        self.va = 0
        self.end = 0
        self.size = 0  # size including chunks
        self.lastmatch = 0  # last rule match on this va
        self.name = ""
        self.chunks = []

    def __repr__(self):
        return f"funcs({hex(self.va)} -> {hex(self.end)} = {self.size})"

    def contains_adr(self, adr):
        for chunk in self.chunks:
            if chunk[0] <= adr < chunk[1]:
                return True
        return False

    def get_as_chunks(self):
        """
        get chunks
        this includes the main function body too!
        :return: chunks
        """
        return self.chunks

    @staticmethod
    def _disasm_chunk(start: int, end: int):
        """
        generator to disasm given range
        :param start: start va
        :param end: end va
        :return: yields instructions oen by one
        """
        curva = start
        while curva < end:
            ins = idautils.DecodeInstruction(curva)
            if ins is None:
                # print(f"error disasm at {hex(curva)}")
                curva = curva + 1
                continue
            curva += ins.size
            yield ins

    def disasm(self):
        """
        generator to disasm entire function, incl. chunks
        :return: yields instructions one by one
        """
        for chunk in self.get_as_chunks():
            yield None  # function chunck separator
            for ins in self._disasm_chunk(chunk[0], chunk[1]):
                yield ins

    @staticmethod
    def adresses_to_funcs(refs: Iterable[int]):
        """
        converts list of address that may be anywhere in a function to Func functions.
        filtes against duplicates
        :param refs: list of address in functions or start of functions
        :return: yields generated Func functions one by one
        """
        deduplicate = set()
        for ref in refs:
            func = Func()
            func.va = idc.get_func_attr(ref, idc.FUNCATTR_START)
            if func.va == idaapi.BADADDR or func.va in deduplicate:
                continue
            func.end = idc.get_func_attr(ref, idc.FUNCATTR_END)
            func.chunks = list(idautils.Chunks(func.va))
            func.size = idaapi.calc_func_size(idaapi.get_func(func.va))
            func.lastmatch = ref
            deduplicate.add(func.va)
            yield func

    @staticmethod
    def adress_to_func(adr: int):
        """
        helper to convert a single function from address
        :param adr: va anywhere in function
        :return: Func function
        """
        return list(Func.adresses_to_funcs([adr]))[0]


class MatcherIda:
    """
    Main class responsible for applying rules and filtering functions accordingly.
    This class collects initial matches, refines them and returns resuls in key method
    do_match().
    Internally it converts and compares instructions,strings,names,... against user-supplied rules.
    """
    def __init__(self):
        self.info = Config()
        self.idastrings = None
        self.wascancelled = False

    # user has cancelled the search
    def iscancelled(self) -> bool:
        if QApplication:
            QApplication.processEvents()
        self.wascancelled = idaapi.user_cancelled()
        if self.wascancelled:
            print("Search cancelled...")
        return self.wascancelled

    # these functions obtain initial matches, which are then refined
    # by subsequent rules.
    # Initial matches need to be fast and cut down the input to slower rules.

    @staticmethod
    def match_initial_pos_strings(rules: List[RuleStrRef]):
        for r in rules:
            if r.inverted:
                continue
            for ref in r.refs:
                yield ref

    @staticmethod
    def match_initial_pos_names(rules: List[RuleNameRef]):
        for r in rules:
            if r.inverted:
                continue
            for va in r.refs:
                yield va

    def match_initial_pos_imm(self, rules: List[RuleImmediate]):
        for r in rules:
            if r.inverted:
                continue
            lastva = self.info.startva
            while lastva != idaapi.BADADDR:
                if self.iscancelled():
                    return
                lastva = ida_search.find_imm(lastva, idaapi.SEARCH_DOWN, r.imm)
                lastva = lastva[0]  # ??
                if lastva != idaapi.BADADDR:
                    yield lastva

    def match_initial_pos_bytes(self, rules: List[RuleBytePattern]):
        for r in rules:
            if r.inverted:
                continue
            lastva = self.info.startva
            while lastva != idaapi.BADADDR:
                lastva = ida_bytes.bin_search(lastva + 1, self.info.endva, r.patterncompiled, idaapi.BIN_SEARCH_FORWARD)
                if lastva != idaapi.BADADDR:
                    yield lastva

    @staticmethod
    def match_initial_pos_fsize(rules: List[RuleFuncSize]):
        funcfiter = idautils.Functions()
        for func in funcfiter:
            funcsize = idaapi.calc_func_size(idaapi.get_func(func))
            for rule in rules:
                if rule.inverted:
                    continue
                if rule.checksize(funcsize):
                    yield func

    # These methods refine initial matches
    # As initial matches only considere positive rules (not inverted ones),
    # all rules must be used for refining, except the single one that actually
    # generated initial matches.
    # To keep memoryp ressure low, ideally this all works as a geneartor-pipeline

    @staticmethod
    def refine_match_string(funcs: Iterable[Func], rules: List[RuleStrRef]):
        for func in funcs:
            for r in rules:
                for ref in r.refs:
                    isinfunc = func.contains_adr(ref)
                    if isinfunc:
                        passed = not r.inverted
                        if passed:
                            func.lastmatch = ref
                        break
                else:
                    passed = r.inverted
                if not passed:
                    func = None
                    break
            if func:
                yield func

    @staticmethod
    def refine_match_fsize(funcs: Iterable[Func], rules: List[RuleFuncSize]):
        for fnc in funcs:
            for rule in rules:
                isinfunc = rule.checksize(fnc.size)
                if isinfunc == rule.inverted:
                    break  # one rule mismatch is enough
            else:
                yield fnc

    @staticmethod
    def refine_match_name(funcs: Iterable[Func], rules: List[RuleNameRef]):
        for func in funcs:
            for r in rules:
                for ref in r.refs:
                    isinfunc = func.contains_adr(ref)
                    if isinfunc:
                        passed = not r.inverted
                        if passed:
                            func.lastmatch = ref
                        break
                else:
                    passed = r.inverted
                if not passed:
                    func = None
                    break
            if func:
                yield func

    def refine_match_bytes(self, funcs: Iterable[Func], rules: List[RuleBytePattern]):
        for func in funcs:
            if self.iscancelled():
                return
            for r in rules:
                for chunk in func.get_as_chunks():
                    hit = ida_bytes.bin_search(chunk[0], chunk[1], r.patterncompiled, idaapi.BIN_SEARCH_FORWARD)
                    isinfunc = hit != idaapi.BADADDR
                    if isinfunc:
                        passed = not r.inverted
                        if passed:
                            func.lastmatch = hit
                        break
                else:
                    passed = r.inverted
                if not passed:
                    func = None
                    break
            if func:
                yield func

    # CodeRule matching is the most complicated matching.
    # Some helper methods follow

    @staticmethod
    def _idains_contains_imm(ins, imm: int):
        if ins:
            for op in ins.ops:
                if op.type == idc.o_imm:
                    if op.value == imm:
                        return True
                if op.type == idc.o_displ or op.type == idc.o_mem:
                    if op.addr == imm and imm != 0:
                        return True
        return False

    def _check_op_eq(self, opx: InstrWildcardOp, oprule: InstrWildcardOp) -> bool:
        """
        Compare two instruction operands, disassembly one with one provided by a CodePattern rule.
        :param opx: disassembled operand
        :param oprule: rule operand
        :return: True if opx satisfies oprule
        """
        if oprule.basereg == "any":
            return True
        if opx.deref != oprule.deref or opx.scale != oprule.scale:
            return False
        if opx.deref and opx.size != oprule.size and oprule.size is not None:  # compare size of deref []
            return False
        derefeq = opx.displ == oprule.displ or oprule.displ == "imm"  # displ doesnt have an invalid value - can be 0
        if not derefeq:
            return False
        pointersize = self.info.ptrsize if opx.deref else opx.size
        baseregeq = opx.basereg == oprule.basereg \
                    or (opx.basereg is not None and oprule.basereg == "r") \
                    or (pointersize == 8 and oprule.basereg == "r64") \
                    or (pointersize == 4 and oprule.basereg == "r32") \
                    or (pointersize == 2 and oprule.basereg == "r16") \
                    or (pointersize == 1 and oprule.basereg == "r8")
        if not baseregeq:
            return False
        indexregeq = opx.indexreg == oprule.indexreg \
                     or (opx.indexreg is not None and oprule.indexreg == "r") \
                     or (pointersize == 8 and oprule.indexreg == "r64") \
                     or (pointersize == 4 and oprule.indexreg == "r32") \
                     or (pointersize == 2 and oprule.indexreg == "r16") \
                     or (pointersize == 1 and oprule.indexreg == "r8")
        if not indexregeq:
            return False
        return True

    def _check_instr(self, idains, rules: List[RuleCode]):
        """
        Checks a disassembled instruction against a list of CodeRules
        If the instruction satisfies the current instruction of the Rule,
        the Rules state is advanced to the next instruction to be matched.
        :param idains: the disassembled instruction
        :param rules: a list of CodeRules
        :return: Nothing
        """
        for r in rules:
            self._check_instr_on_rule(idains, r)

    def _check_instr_on_rule(self, idains, rules: RuleCode):
        """
        Checks a disassembled instruction against a list of CodeRules
        If the instruction satisfies the current instruction of the Rule,
        the Rules state is advanced to the next instruction to be matched.
        :param idains: the disassembled instruction
        :param rules: a list of CodeRules
        :return: Nothing
        """
        r = rules
        if r.is_satisfied():
            return
        curins = r.curinstr()
        if curins.mmn == "pass":  # matches any instruction
            r.advance()
            return
        if len(curins.ops) == 0:
            if not fnmatch.fnmatch(idains.mmn, curins.mmn) and curins.mmn != "any":  # match mmn
                r.clearcurrent()
            else:
                r.advance()
            return
        if len(idains.ops) != len(curins.ops):
            r.clearcurrent()
            return
        if not fnmatch.fnmatch(idains.mmn, curins.mmn) and curins.mmn != "any":  # match mmn
            r.clearcurrent()
            return
        if self.info.debug:
            print(f"---\nprep: {idains}    ==    {curins}")
        passed = True
        for opx, opy in zip(idains.ops, curins.ops):  # match operands
            if self.info.debug:
                print(f"{opx}    ==    {opy}    ->  {self._check_op_eq(opx, opy)}")
            if not self._check_op_eq(opx, opy):
                r.clearcurrent()
                passed = False
                break
        if passed:
            r.advance()  # advance rule state to next instruction to be checked

    def _ida_op_t_to_wcop(self, opida, adrsizeoverride) -> InstrWildcardOp:
        """
        Converts an operand of IDA dissassembled instruction to our own format,
        for easier matching.
        :param opida: operand by IDA
        :param adrsizeoverride: Intel instruction prefix can override the addressing size (in bytes)
        (can be None)
        :return: converted operand in our format
        """
        opout = InstrWildcardOp()
        opout.size = ida_ua.get_dtype_size(opida.dtype)
        if opida.type == idc.o_imm:  # simple immediate
            opout.displ = opida.value
        if opida.type == idc.o_reg:  # simple register
            opout.basereg = idaapi.get_reg_name(opida.reg, opout.size)
        # anyting else is more complex...
        hassib = opida.specflag1
        sib = opida.specflag2
        deref_reg_size = adrsizeoverride if adrsizeoverride else self.info.ptrsize
        index = base = breg = ireg = scale = None
        if hassib:
            base = sib & 7
            index = (sib >> 3) & 7
            scale = (sib >> 6) & 3
            breg = idaapi.get_reg_name(base, deref_reg_size)
            ireg = idaapi.get_reg_name(index, deref_reg_size)
            scale = (2 ** scale) if scale else 1
            # print(f"[{breg} + {ireg} * {sc} + {addr}]")
        addr = opida.addr
        if self.info.ptrsize == 8:
            if addr & 0x8000000000000000:
                addr = -0x10000000000000000 + addr
        else:
            if addr & 0x80000000:
                addr = -0x100000000 + addr
        if opida.type == idc.o_mem:  # [c], [ecx*8+64h] ds:0[edx*8] --> always ignore basereg
            opout.deref = True
            if hassib:  # [reg*c+x]
                opout.displ = addr
                # opout.basereg = None #always ignore
                opout.indexreg = ireg
                opout.scale = scale
            else:  # [c]
                opout.displ = addr
        if opida.type == idc.o_phrase:  # [eax+ecx*8] [ecx+edx] [edx]
            opout.deref = True
            if hassib:  # [r+r*c]
                opout.basereg = breg
                opout.indexreg = ireg
                opout.scale = scale
            else:  # [r]
                opout.basereg = idaapi.get_reg_name(opida.reg, deref_reg_size)
        if opida.type == idc.o_displ:  # [eax+ecx*8+64h]  [ebp+ecx*8+64h] [ecx+100h]
            opout.deref = True
            if hassib:  # [r+r*c+c]
                opout.basereg = breg
                opout.indexreg = ireg
                opout.displ = addr
                opout.scale = scale
            else:  # [r+c]
                opout.basereg = idaapi.get_reg_name(opida.reg, deref_reg_size)
                opout.displ = addr

        # for [rsp|esp|sp + ...] IDA sets basereg=indexreg=sp
        # this is probably an IDA bug (since sp cannot be an index)
        if hassib:
            if (index == base == idautils.procregs.sp.reg) and (scale == 1):
                opout.indexreg = None
        return opout

    def _idains_to_myins(self, idains) -> InstrWildcard:
        """
        Converts IDA instruction to our format for easier comparison.
        :param idains: instruction disassembled by IDA
        :return: converted instructoin in our format
        """
        myins = InstrWildcard()
        myins.va = idains.ea
        myins.mmn = idains.get_canon_mnem()  # perf opt: only convert instructions if mmn matches...
        for op in idains.ops:
            if op.type == idaapi.o_void:
                break
            if op.type in (idc.o_far, idc.o_near):
                if not self.info.warnedfar:
                    self.info.warnedfar = True
                    print("near and far operands not supported")
                continue
            # if self.info.debug:
            #     print("is_op", ida_is_op_16(ins), ida_is_op_32(ins), ida_is_op_64(ins))
            #     print("is_add", ida_is_ad_16(ins), ida_is_ad_32(ins), ida_is_ad_64(ins))
            adrsizeoverrideprefix = ida_get_insn_admode(idains)
            o = self._ida_op_t_to_wcop(op, adrsizeoverrideprefix)
            myins.ops.append(o)
        return myins

    def refine_match_code_and_imm(self, funcs: Iterable[Func], rcode: List[RuleCode], rimm: List[RuleImmediate]):
        """
        Refine Imm and Code Rules.
        Do it in one go so we dont have to dissassemble twice. See notes on performance in do_match.
        :param funcs: list of candidate functions
        :param rcode: code rules
        :param rimm: imm rules
        :return: yield functions satisfying all rules
        """
        for func in funcs:
            if self.iscancelled():
                return
            disasm = list(func.disasm())
            for r in rimm:
                for ins in disasm:
                    isinfunc = self._idains_contains_imm(ins, r.imm)
                    if isinfunc:
                        passed = not r.inverted
                        if passed:
                            func.lastmatch = ins.ea
                        break
                else:
                    passed = r.inverted
                if not passed:
                    func = None
                    break
            if not func:  # failed imm check
                continue

            if not rcode:
                yield func  # no code rules and passed imm check
                continue
            if self.info.debug:
                print(f"checking func... at {hex(func.va)} with inscount {len(disasm)}")
            # reset rules
            for r in rcode:
                r.clearcurrent()
            for ins in disasm:
                if ins is None:
                    # reset rules bc we cross over a chunk
                    for r in rcode:
                        if not r.is_satisfied():
                            r.clearcurrent()
                    continue
                myins = self._idains_to_myins(ins)
                for r in [x for x in rcode if not x.is_satisfied()]:
                    self._check_instr_on_rule(myins, r)
                    if r.is_satisfied():
                        func.lastmatch = myins.va
                #self._check_instr(myins, rcode)
            for r in rcode:
                if r.is_satisfied() == r.inverted:
                    break  # one mismatching rule is enough
            else:
                yield func
            # reset rules
            for r in rcode:
                r.clearcurrent()

    def do_match(self, rules: List[Rule], limitto: List[int] = None) -> List[Func]:
        """
        Main function for filtering Functions based on the given Rules.

        Since matching is slow, we have an interest in applying fast rules first.

        A brief word on performance:
        1. name, string, funcsize are almost free in all cases
        2. bytepattern is almost free for byte strings length > 2
        3. immediate is difficult:
            We can use idaapi search, or we can disassemble the entire database and search ourselves -
            we may have to do this anyways if we are looking for code patterns.
            BUT: scanning for code patterns is in fact much cheaper than scanning for an immediate.
            an api-search for all matches is relatively costly - about 1/8 as costly as disassembling
            the entire database.
            So: If we cut down matches with cheap rules first, then we greatly profit from disassembling
            the remaining functions and looking for the immediate ourselves, especially if a code-rule is
            present anyways.
            However: If no cheap options exist and we have to disassemble large parts of the database
            anyways (due to presence of code pattern rules), then using one immediate rule as a pre-filter
            can greatly pay off.
            api-searching ONE immediate is roughly equivalent to 1/8 searching for any number of code-pattern
            rules - although this also depends on many different factors...
        4. code pattern are the most expensive by far, however checking one pattern vs checking many
            is almost identical.
        """
        # rc = RuleCode(None)
        # rc.set_data("mov     cl, [eax+ebx*4+9]")
        # print(rc.instr[0])
        self.wascancelled = False
        activerules = copy.deepcopy([x for x in rules if x.enabled])
        if not activerules:
            return []
        print("Active rules:" + str(activerules))
        coderules = [x for x in activerules if isinstance(x, RuleCode)]

        # positive rules
        pos_byte_rules = [x for x in activerules if isinstance(x, RuleBytePattern) and not x.inverted]
        pos_imm_rules = [x for x in activerules if isinstance(x, RuleImmediate) and not x.inverted]
        pos_name_rules = [x for x in activerules if isinstance(x, RuleNameRef) and not x.inverted]
        pos_str_rules = [x for x in activerules if isinstance(x, RuleStrRef) and not x.inverted]
        pos_fsize_rules = [x for x in activerules if isinstance(x, RuleFuncSize) and not x.inverted]

        # inverted rules
        neg_byte_rules = [x for x in activerules if isinstance(x, RuleBytePattern) and x.inverted]
        neg_imm_rules = [x for x in activerules if isinstance(x, RuleImmediate) and x.inverted]
        neg_name_rules = [x for x in activerules if isinstance(x, RuleNameRef) and x.inverted]
        neg_str_rules = [x for x in activerules if isinstance(x, RuleStrRef) and x.inverted]
        neg_fsize_rules = [x for x in activerules if isinstance(x, RuleFuncSize) and x.inverted]

        # preprocessing

        # cheap
        if pos_str_rules or neg_str_rules:
            if not self.idastrings:
                self.idastrings = idautils.Strings(False)
                self.idastrings.setup(self.info.strtypes)
            # print(f"{hex(i.ea)}: len {i.length}, type {i.strtype}, {str(i)}")
            for string in self.idastrings:
                strval = str(string)
                for rule in pos_str_rules + neg_str_rules:
                    if rule.matches(strval):
                        rule.refs += list(idautils.DataRefsTo(string.ea))
        # almost free
        if pos_name_rules or neg_name_rules:
            for name in idautils.Names():
                va, n = name
                for rule in pos_name_rules + neg_name_rules:
                    if rule.matches(n):
                        rule.refs += list(idautils.CodeRefsTo(va, False))
                        rule.refs += list(idautils.DataRefsTo(va))
        # free
        for rule in pos_byte_rules + neg_byte_rules:
            rule.patterncompiled = ida_bytes.compiled_binpat_vec_t()
            ida_bytes.parse_binpat_str(rule.patterncompiled, self.info.startva, rule.pattern, 16)

        if self.iscancelled():
            return []

        # initial collection
        # pick a positive rule to cut down initial matches as drastically as possible

        if limitto:
            candidatas = limitto
        elif pos_name_rules:
            candidatas = self.match_initial_pos_names([pos_name_rules[0]])
            pos_name_rules = pos_name_rules[1:]
        elif pos_fsize_rules:
            candidatas = self.match_initial_pos_fsize([pos_fsize_rules[0]])
            pos_fsize_rules = pos_fsize_rules[1:]
        elif pos_str_rules:
            candidatas = self.match_initial_pos_strings([pos_str_rules[0]])
            pos_str_rules = pos_str_rules[1:]
        elif pos_byte_rules:
            candidatas = self.match_initial_pos_bytes([pos_byte_rules[0]])
            pos_byte_rules = pos_byte_rules[1:]
        elif pos_imm_rules:
            candidatas = self.match_initial_pos_imm([pos_imm_rules[0]])
            pos_imm_rules = pos_imm_rules[1:]
        else:
            # only option is to disasm the full database -> slow
            print(
                "It seems only code patterns are available for initial matching, which necessitates disassembling the whole database.")
            print(
                "This can be slow. To speed up the process add positiv name > string > function size > bytes > immediate constraints.")
            candidatas = idautils.Functions()

        # refinement
        # refine against all positive and negative functions

        candidatas = Func.adresses_to_funcs(candidatas)
        if pos_fsize_rules or neg_fsize_rules:
            candidatas = self.refine_match_fsize(candidatas, pos_fsize_rules + neg_fsize_rules)
        if pos_str_rules or neg_str_rules:
            candidatas = self.refine_match_string(candidatas, pos_str_rules + neg_str_rules)
        if pos_name_rules or neg_name_rules:
            candidatas = self.refine_match_name(candidatas, pos_name_rules + neg_name_rules)
        if pos_byte_rules or neg_byte_rules:
            candidatas = self.refine_match_bytes(candidatas, pos_byte_rules + neg_byte_rules)
        if coderules or pos_imm_rules or neg_imm_rules:
            candidatas = self.refine_match_code_and_imm(candidatas, coderules, pos_imm_rules + neg_imm_rules)

        candidatas = list(candidatas)

        for c in candidatas:
            c.name = ida_name.get_short_name(c.va)

        # a = b = 0
        # for c in candidatas:
        #    a = a + c.end - c.va
        #    b = b + sum((x[1] - x[0] for x in c.chunks))
        #    if self.info.debug:
        #        print(hex(c.va), [(hex(x[0]), hex(x[1])) for x in c.chunks])
        # print("fsize: ", a, " chunk size: ", b - a)
        return candidatas
