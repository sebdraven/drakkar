//! Décodage d'une instruction AArch64, ARM, Thumb, x86 ou x86_64 en une forme
//! commune : texte, flot de contrôle et micro-opérations sur les registres et la
//! mémoire, que l'évaluateur de `disasm` interprète. Aucune instruction n'est
//! exécutée.
//!
//! Numérotation des registres : AArch64 x0 à x30, 31 = sp ; ARM r0 à r15 ;
//! x86 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8 à r15 (0 à 15).

use iced_x86::{Formatter, Mnemonic, OpKind, Register};
use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{self, Opcode as ArmOp, Operand as ArmOperand};
use yaxpeax_arm::armv8::a64::{self, Opcode as A64Op, Operand as A64Operand};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arch {
    Aarch64,
    Arm,
    X86,
    X86_64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Expr {
    Imm(u64),
    Reg(u8),
    AddImm(u8, i64),
    AddReg(u8, u8),
    MovK(u8, u64, u32),
    MovT(u8, u64),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Addr {
    Base(u8, i64),
    Abs(u64),
    Unknown,
}

/// `Load(registre, adresse, largeur en octets)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Set(u8, Expr),
    Load(u8, Addr, u64),
    Store(Expr, Addr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Via {
    Reg(u8),
    Mem(Addr),
    Unknown,
}

/// Le booléen des cibles directes vaut vrai pour du code Thumb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flow {
    Next,
    Jump(u64, bool),
    Branch(u64, bool),
    Call(u64, bool),
    CallVia(Via),
    JumpVia(Via),
    Return,
    Stop,
}

#[derive(Clone, Debug)]
pub(super) struct Insn {
    pub(super) address: u64,
    pub(super) len: u64,
    pub(super) bytes: String,
    pub(super) mnemonic: String,
    pub(super) operands: String,
    pub(super) flow: Flow,
    pub(super) ops: Vec<Op>,
    pub(super) syscall: bool,
    /// Registre qui reçoit une adresse calculée : candidat `string_refs`.
    pub(super) forms_address: Option<u8>,
}

impl Insn {
    fn new(address: u64, raw: &[u8], mnemonic: String, operands: String) -> Self {
        Insn {
            address,
            len: raw.len() as u64,
            bytes: hex_bytes(raw),
            mnemonic,
            operands,
            flow: Flow::Next,
            ops: Vec::new(),
            syscall: false,
            forms_address: None,
        }
    }

    fn from_text(address: u64, raw: &[u8], text: &str) -> Self {
        match text.split_once(' ') {
            Some((mnemonic, operands)) => {
                let operands = operands.trim().to_string();
                Insn::new(address, raw, mnemonic.to_string(), operands)
            }
            None => Insn::new(address, raw, text.to_string(), String::new()),
        }
    }

    fn set(&mut self, reg: u8, expr: Expr) {
        self.ops.push(Op::Set(reg, expr));
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `code` commence à `address` ; `None` si les octets ne forment pas une
/// instruction valide.
pub(super) fn decode(arch: Arch, code: &[u8], address: u64, thumb: bool) -> Option<Insn> {
    match arch {
        Arch::Aarch64 => decode_a64(code, address),
        Arch::Arm => decode_arm(code, address, thumb),
        Arch::X86 => decode_x86(code, address, 32),
        Arch::X86_64 => decode_x86(code, address, 64),
    }
}

fn sext(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn decode_a64(code: &[u8], address: u64) -> Option<Insn> {
    let mut reader = U8Reader::new(code);
    let inst = a64::InstDecoder::default().decode(&mut reader).ok()?;
    let len = usize::try_from(inst.len().to_const()).ok()?;
    let raw = code.get(..len)?;
    let mut insn = Insn::from_text(address, raw, &inst.to_string());
    a64_semantics(&inst, address, &mut insn);
    Some(insn)
}

/// Registre écrit ; `None` pour xzr / wzr.
fn a64_dst(op: &A64Operand) -> Option<u8> {
    match *op {
        A64Operand::Register(_, r) if r < 31 => Some(r as u8),
        A64Operand::RegisterOrSP(_, r) => Some(r as u8),
        _ => None,
    }
}

fn a64_src(op: &A64Operand) -> Option<Expr> {
    match *op {
        A64Operand::Register(_, 31) => Some(Expr::Imm(0)),
        A64Operand::Register(_, r) | A64Operand::RegisterOrSP(_, r) => Some(Expr::Reg(r as u8)),
        A64Operand::RegShift(a64::ShiftStyle::LSL, 0, _, 31) => Some(Expr::Imm(0)),
        A64Operand::RegShift(a64::ShiftStyle::LSL, 0, _, r) => Some(Expr::Reg(r as u8)),
        _ => None,
    }
}

fn a64_reg_width(op: &A64Operand) -> u64 {
    match *op {
        A64Operand::Register(a64::SizeCode::W, _) => 4,
        _ => 8,
    }
}

fn pc_rel(op: A64Operand, address: u64) -> Option<u64> {
    match op {
        A64Operand::PCOffset(off) => Some(address.wrapping_add(off as u64)),
        _ => None,
    }
}

/// Adresse d'un opérande mémoire, et l'éventuelle réécriture du registre de
/// base (registre, delta).
fn a64_addr(op: A64Operand, address: u64) -> Option<(Addr, Option<(u8, i64)>)> {
    match op {
        A64Operand::PCOffset(off) => Some((Addr::Abs(address.wrapping_add(off as u64)), None)),
        A64Operand::RegPreIndex(n, imm, wback) => {
            let base = n as u8;
            let delta = i64::from(imm);
            Some((Addr::Base(base, delta), wback.then_some((base, delta))))
        }
        A64Operand::RegPostIndex(n, imm) => {
            let base = n as u8;
            Some((Addr::Base(base, 0), Some((base, i64::from(imm)))))
        }
        A64Operand::RegRegOffset(..) | A64Operand::RegPostIndexReg(..) => {
            Some((Addr::Unknown, None))
        }
        _ => None,
    }
}

fn mnemonic_width(mnemonic: &str, reg_width: u64) -> u64 {
    if mnemonic.ends_with("sw") {
        4
    } else if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('h') {
        2
    } else {
        reg_width
    }
}

fn a64_semantics(inst: &a64::Instruction, address: u64, insn: &mut Insn) {
    let ops = inst.operands;
    let dst = a64_dst(&ops[0]);
    match inst.opcode {
        A64Op::ADRP => {
            if let (Some(rd), A64Operand::PCOffset(off)) = (dst, ops[1]) {
                let page = address & !0xfff;
                insn.set(rd, Expr::Imm(page.wrapping_add(off as u64)));
            }
        }
        A64Op::ADR => {
            if let (Some(rd), A64Operand::PCOffset(off)) = (dst, ops[1]) {
                insn.set(rd, Expr::Imm(address.wrapping_add(off as u64)));
                insn.forms_address = Some(rd);
            }
        }
        A64Op::ADD | A64Op::SUB => a64_add(inst, insn),
        A64Op::ORR => {
            if let (Some(rd), Some(Expr::Imm(0))) = (dst, a64_src(&ops[1])) {
                let src = a64_src(&ops[2]).unwrap_or(Expr::Unknown);
                insn.set(rd, src);
            } else if let Some(rd) = dst {
                insn.set(rd, Expr::Unknown);
            }
        }
        A64Op::MOVZ | A64Op::MOVN | A64Op::MOVK => {
            if let (Some(rd), A64Operand::ImmShift(imm, shift)) = (dst, ops[1]) {
                let value = u64::from(imm) << shift;
                let mask = if a64_reg_width(&ops[0]) == 4 {
                    0xffff_ffff
                } else {
                    u64::MAX
                };
                let expr = match inst.opcode {
                    A64Op::MOVZ => Expr::Imm(value),
                    A64Op::MOVN => Expr::Imm(!value & mask),
                    _ => Expr::MovK(rd, u64::from(imm), u32::from(shift)),
                };
                insn.set(rd, expr);
            }
        }
        A64Op::B => {
            if let Some(target) = pc_rel(ops[0], address) {
                insn.flow = Flow::Jump(target, false);
            }
        }
        A64Op::BL => {
            if let Some(target) = pc_rel(ops[0], address) {
                insn.flow = Flow::Call(target, false);
            }
        }
        A64Op::Bcc(_) | A64Op::BCcc(_) => a64_branch(ops[0], address, insn),
        A64Op::CBZ | A64Op::CBNZ => a64_branch(ops[1], address, insn),
        A64Op::TBZ | A64Op::TBNZ => a64_branch(ops[2], address, insn),
        A64Op::BLR | A64Op::BLRAA | A64Op::BLRAAZ | A64Op::BLRAB | A64Op::BLRABZ => {
            if let Some(Expr::Reg(rn)) = a64_src(&ops[0]) {
                insn.flow = Flow::CallVia(Via::Reg(rn));
            }
        }
        A64Op::BR | A64Op::BRAA | A64Op::BRAAZ | A64Op::BRAB | A64Op::BRABZ => {
            insn.flow = match a64_src(&ops[0]) {
                Some(Expr::Reg(rn)) => Flow::JumpVia(Via::Reg(rn)),
                _ => Flow::JumpVia(Via::Unknown),
            };
        }
        A64Op::RET | A64Op::RETAA | A64Op::RETAB => insn.flow = Flow::Return,
        A64Op::SVC => insn.syscall = true,
        A64Op::BRK | A64Op::HLT | A64Op::UDF => insn.flow = Flow::Stop,
        _ => a64_other(inst, address, insn),
    }
}

fn a64_branch(op: A64Operand, address: u64, insn: &mut Insn) {
    if let Some(target) = pc_rel(op, address) {
        insn.flow = Flow::Branch(target, false);
    }
}

fn a64_add(inst: &a64::Instruction, insn: &mut Insn) {
    let ops = inst.operands;
    let Some(rd) = a64_dst(&ops[0]) else {
        return;
    };
    let sub = inst.opcode == A64Op::SUB;
    let Some(Expr::Reg(rn)) = a64_src(&ops[1]) else {
        insn.set(rd, Expr::Unknown);
        return;
    };
    let delta = match ops[2] {
        A64Operand::Immediate(imm) => Some(i64::from(imm)),
        A64Operand::ImmShift(imm, shift) => Some(i64::from(imm) << shift),
        _ => None,
    };
    let expr = match (delta, sub) {
        (Some(delta), false) => Expr::AddImm(rn, delta),
        (Some(delta), true) => Expr::AddImm(rn, -delta),
        (None, false) => match a64_src(&ops[2]) {
            Some(Expr::Reg(rm)) => Expr::AddReg(rn, rm),
            _ => Expr::Unknown,
        },
        (None, true) => Expr::Unknown,
    };
    if delta.is_some() {
        insn.forms_address = Some(rd);
    }
    insn.set(rd, expr);
}

/// Chargements et rangements reconnus à leur mnémonique ; toute autre
/// instruction qui écrit un registre général le rend inconnu.
fn a64_other(inst: &a64::Instruction, address: u64, insn: &mut Insn) {
    let ops = inst.operands;
    let mnemonic = insn.mnemonic.clone();
    let width = mnemonic_width(&mnemonic, a64_reg_width(&ops[0]));
    if mnemonic.starts_with("ld") {
        if let Some((addr, wback)) = a64_addr(ops[1], address) {
            if let Some(rt) = a64_dst(&ops[0]) {
                insn.ops.push(Op::Load(rt, addr, width));
                if matches!(addr, Addr::Abs(_)) {
                    insn.forms_address = Some(rt);
                }
            }
            a64_writeback(wback, insn);
            return;
        }
        if let Some((addr, wback)) = a64_addr(ops[2], address) {
            for (slot, op) in [(0, ops[0]), (1, ops[1])] {
                if let Some(rt) = a64_dst(&op) {
                    insn.ops.push(Op::Load(rt, shifted(addr, slot * width), width));
                }
            }
            a64_writeback(wback, insn);
            return;
        }
    }
    if mnemonic.starts_with("st") {
        let single = matches!(mnemonic.as_str(), "str" | "strb" | "strh" | "stur");
        let pair = matches!(mnemonic.as_str(), "stp" | "stnp");
        if single {
            let src = a64_src(&ops[0]);
            if let (Some(src), Some((addr, wback))) = (src, a64_addr(ops[1], address)) {
                insn.ops.push(Op::Store(src, addr));
                a64_writeback(wback, insn);
            }
        } else if pair {
            if let Some((addr, wback)) = a64_addr(ops[2], address) {
                for (slot, op) in [(0, ops[0]), (1, ops[1])] {
                    let src = a64_src(&op).unwrap_or(Expr::Unknown);
                    insn.ops.push(Op::Store(src, shifted(addr, slot * width)));
                }
                a64_writeback(wback, insn);
            }
        }
        return;
    }
    if mnemonic.starts_with("cc") || mnemonic.starts_with("prfm") {
        return;
    }
    if let Some(rd) = a64_dst(&ops[0]) {
        insn.set(rd, Expr::Unknown);
    }
}

fn shifted(addr: Addr, by: u64) -> Addr {
    match addr {
        Addr::Base(reg, off) => Addr::Base(reg, off.wrapping_add(by as i64)),
        Addr::Abs(at) => Addr::Abs(at.wrapping_add(by)),
        Addr::Unknown => Addr::Unknown,
    }
}

fn a64_writeback(wback: Option<(u8, i64)>, insn: &mut Insn) {
    if let Some((reg, delta)) = wback {
        insn.set(reg, Expr::AddImm(reg, delta));
    }
}

#[derive(Clone, Copy)]
struct Site<'c> {
    code: &'c [u8],
    address: u64,
    thumb: bool,
}

impl Site<'_> {
    /// Valeur lue dans pc par l'instruction.
    fn pc(&self) -> u64 {
        if self.thumb {
            self.address.wrapping_add(4)
        } else {
            self.address.wrapping_add(8)
        }
    }

    /// Base des accès littéraux et d'ADR : pc aligné sur 4.
    fn literal_base(&self) -> u64 {
        self.pc() & !3
    }

    fn halfword(&self, at: usize) -> Option<u64> {
        let bytes = self.code.get(at..at + 2)?;
        Some(u64::from(u16::from_le_bytes([bytes[0], bytes[1]])))
    }

    fn word(&self) -> Option<u64> {
        let bytes = self.code.get(..4)?;
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Some(u64::from(word))
    }

    /// Cible d'un B, BL, BLX immédiat, CBZ ou CBNZ, relue dans l'encodage (ARM
    /// Architecture Reference Manual, ARMv7-A, A8.8.18 à A8.8.29), et le mode de
    /// la cible.
    fn branch_target(&self, len: u64) -> Option<(u64, bool)> {
        if !self.thumb {
            let word = self.word()?;
            let offset = sext((word & 0x00ff_ffff) << 2, 26) as u64;
            let target = self.pc().wrapping_add(offset);
            if word >> 28 == 0xf {
                let half = ((word >> 24) & 1) << 1;
                return Some((target.wrapping_add(half), true));
            }
            return Some((target, false));
        }
        let hw1 = self.halfword(0)?;
        let pc = self.pc();
        if len == 2 {
            let offset = if hw1 >> 12 == 0xd {
                sext((hw1 & 0xff) << 1, 9)
            } else if hw1 >> 11 == 0b11100 {
                sext((hw1 & 0x7ff) << 1, 12)
            } else if hw1 & 0xf500 == 0xb100 {
                ((((hw1 >> 9) & 1) << 6) | (((hw1 >> 3) & 0x1f) << 1)) as i64
            } else {
                return None;
            };
            return Some((pc.wrapping_add(offset as u64), true));
        }
        let hw2 = self.halfword(2)?;
        let s = (hw1 >> 10) & 1;
        let j1 = (hw2 >> 13) & 1;
        let j2 = (hw2 >> 11) & 1;
        let imm11 = hw2 & 0x7ff;
        let link = hw2 & 0x4000 != 0;
        let t4 = hw2 & 0x1000 != 0;
        if !link && !t4 {
            let imm6 = hw1 & 0x3f;
            let high = (s << 20) | (j2 << 19) | (j1 << 18);
            let raw = high | (imm6 << 12) | (imm11 << 1);
            return Some((pc.wrapping_add(sext(raw, 21) as u64), true));
        }
        let i1 = (j1 ^ s) ^ 1;
        let i2 = (j2 ^ s) ^ 1;
        let high = (s << 24) | (i1 << 23) | (i2 << 22);
        let raw = high | ((hw1 & 0x3ff) << 12) | (imm11 << 1);
        let offset = sext(raw, 25) as u64;
        if link && !t4 {
            return Some(((pc & !3).wrapping_add(offset), false));
        }
        Some((pc.wrapping_add(offset), true))
    }
}

fn decode_arm(code: &[u8], address: u64, thumb: bool) -> Option<Insn> {
    let mut decoder = armv7::InstDecoder::default();
    decoder.set_thumb_mode(thumb);
    let mut reader = U8Reader::new(code);
    let inst = decoder.decode(&mut reader).ok()?;
    let len = usize::try_from(inst.len().to_const()).ok()?;
    let raw = code.get(..len)?;
    let mut insn = Insn::from_text(address, raw, &inst.to_string());
    let site = Site {
        code: raw,
        address,
        thumb,
    };
    arm_semantics(&inst, site, &mut insn);
    if inst.condition != armv7::ConditionCode::AL {
        conditional(&mut insn);
    }
    Some(insn)
}

/// Une instruction conditionnelle peut ne pas s'exécuter : ses écritures
/// deviennent inconnues et elle ne termine pas le chemin.
fn conditional(insn: &mut Insn) {
    let mut ops = Vec::new();
    for op in &insn.ops {
        match *op {
            Op::Set(reg, _) | Op::Load(reg, _, _) => ops.push(Op::Set(reg, Expr::Unknown)),
            Op::Store(..) => {}
        }
    }
    insn.ops = ops;
    insn.flow = match insn.flow {
        Flow::Jump(target, thumb) => Flow::Branch(target, thumb),
        Flow::JumpVia(_) | Flow::Return | Flow::Stop => Flow::Next,
        other => other,
    };
}

fn arm_reg(op: &ArmOperand) -> Option<u8> {
    match *op {
        ArmOperand::Reg(r) => Some(r.number()),
        ArmOperand::RegShift(shift) => plain_shift(shift),
        _ => None,
    }
}

/// Registre décalé de `lsl #0`, c'est-à-dire le registre lui-même.
fn plain_shift(shift: armv7::RegShift) -> Option<u8> {
    match shift.into_shift() {
        armv7::RegShiftStyle::RegImm(s) => {
            if s.stype() == armv7::ShiftStyle::LSL && s.imm() == 0 {
                Some(s.shiftee().number())
            } else {
                None
            }
        }
        armv7::RegShiftStyle::RegReg(_) => None,
    }
}

fn arm_imm(op: &ArmOperand) -> Option<u64> {
    match *op {
        ArmOperand::Imm32(imm) => Some(u64::from(imm)),
        ArmOperand::Imm12(imm) => Some(u64::from(imm)),
        _ => None,
    }
}

fn arm_semantics(inst: &armv7::Instruction, site: Site, insn: &mut Insn) {
    let ops = inst.operands;
    match inst.opcode {
        ArmOp::MOV => arm_mov(&ops, site, insn),
        ArmOp::MOVT => {
            if let (ArmOperand::Reg(rd), Some(imm)) = (ops[0], arm_imm(&ops[1])) {
                let rd = rd.number();
                insn.set(rd, Expr::MovT(rd, imm));
            }
        }
        ArmOp::ADD | ArmOp::SUB => arm_add(inst, site, insn),
        ArmOp::ADR => arm_adr(&ops, site, insn),
        ArmOp::LDR => arm_load(&ops, site, 4, insn),
        ArmOp::LDRB | ArmOp::LDRSB => arm_load(&ops, site, 1, insn),
        ArmOp::LDRH | ArmOp::LDRSH => arm_load(&ops, site, 2, insn),
        ArmOp::STR | ArmOp::STRB | ArmOp::STRH => arm_store(&ops, site, insn),
        ArmOp::PUSH => {
            if let ArmOperand::RegList(list) = ops[0] {
                arm_push(list, insn);
            }
        }
        ArmOp::POP => {
            if let ArmOperand::RegList(list) = ops[0] {
                arm_pop(list, insn);
            }
        }
        ArmOp::LDM(add, ..) => arm_ldm(&ops, add, insn),
        ArmOp::STM(add, ..) => {
            if let (ArmOperand::RegWBack(rn, true), ArmOperand::RegList(list)) = (ops[0], ops[1]) {
                if rn.number() == 13 && !add {
                    arm_push(list, insn);
                }
            }
        }
        ArmOp::B => {
            if let Some((target, thumb)) = site.branch_target(insn.len) {
                insn.flow = Flow::Jump(target, thumb);
            }
        }
        ArmOp::BL => {
            if let Some((target, thumb)) = site.branch_target(insn.len) {
                insn.flow = Flow::Call(target, thumb);
            }
        }
        ArmOp::BLX => {
            insn.flow = match arm_reg(&ops[0]) {
                Some(rm) => Flow::CallVia(Via::Reg(rm)),
                None => match site.branch_target(insn.len) {
                    Some((target, thumb)) => Flow::Call(target, thumb),
                    None => Flow::CallVia(Via::Unknown),
                },
            };
        }
        ArmOp::BX => {
            insn.flow = match arm_reg(&ops[0]) {
                Some(14) => Flow::Return,
                Some(15) => Flow::Jump(site.literal_base(), false),
                Some(rm) => Flow::JumpVia(Via::Reg(rm)),
                None => Flow::JumpVia(Via::Unknown),
            };
        }
        ArmOp::CBZ | ArmOp::CBNZ => {
            if let Some((target, thumb)) = site.branch_target(insn.len) {
                insn.flow = Flow::Branch(target, thumb);
            }
        }
        ArmOp::TBB | ArmOp::TBH => insn.flow = Flow::JumpVia(Via::Unknown),
        ArmOp::SVC => insn.syscall = true,
        ArmOp::UDF | ArmOp::BKPT => insn.flow = Flow::Stop,
        ArmOp::CMP | ArmOp::CMN | ArmOp::TST | ArmOp::TEQ | ArmOp::IT | ArmOp::NOP => {}
        _ => {
            if insn.mnemonic.starts_with("st") || insn.mnemonic.starts_with("pl") {
                return;
            }
            if let ArmOperand::Reg(rd) = ops[0] {
                arm_write(rd.number(), Expr::Unknown, insn);
            }
        }
    }
}

/// Une écriture dans pc est un saut dont la cible n'est pas suivie.
fn arm_write(rd: u8, expr: Expr, insn: &mut Insn) {
    if rd == 15 {
        insn.flow = Flow::JumpVia(Via::Unknown);
    } else {
        insn.set(rd, expr);
    }
}

fn arm_mov(ops: &[ArmOperand; 4], site: Site, insn: &mut Insn) {
    let ArmOperand::Reg(rd) = ops[0] else {
        return;
    };
    let rd = rd.number();
    if rd == 15 {
        insn.flow = match arm_reg(&ops[1]) {
            Some(14) => Flow::Return,
            Some(rm) => Flow::JumpVia(Via::Reg(rm)),
            None => Flow::JumpVia(Via::Unknown),
        };
        return;
    }
    let expr = match (arm_imm(&ops[1]), arm_reg(&ops[1])) {
        (Some(imm), _) => Expr::Imm(imm),
        (None, Some(15)) => Expr::Imm(site.pc()),
        (None, Some(rm)) => Expr::Reg(rm),
        (None, None) => Expr::Unknown,
    };
    insn.set(rd, expr);
}

fn arm_add(inst: &armv7::Instruction, site: Site, insn: &mut Insn) {
    let ops = inst.operands;
    let ArmOperand::Reg(rd) = ops[0] else {
        return;
    };
    let rd = rd.number();
    let sub = inst.opcode == ArmOp::SUB;
    let (rn, src) = match ops[2] {
        ArmOperand::Nothing => (Some(rd), ops[1]),
        other => (arm_reg(&ops[1]), other),
    };
    let expr = match (rn, arm_imm(&src), arm_reg(&src)) {
        (Some(15), Some(imm), _) => {
            let base = site.literal_base();
            insn.forms_address = Some(rd);
            match sub {
                true => Expr::Imm(base.wrapping_sub(imm)),
                false => Expr::Imm(base.wrapping_add(imm)),
            }
        }
        (Some(rn), Some(imm), _) => match sub {
            true => Expr::AddImm(rn, -(imm as i64)),
            false => Expr::AddImm(rn, imm as i64),
        },
        (Some(15), None, Some(rm)) | (Some(rm), None, Some(15)) if !sub => {
            insn.forms_address = Some(rd);
            Expr::AddImm(rm, site.pc() as i64)
        }
        (Some(rn), None, Some(rm)) if !sub => Expr::AddReg(rn, rm),
        _ => Expr::Unknown,
    };
    arm_write(rd, expr, insn);
}

/// ADR : Thumb `adr rd, #imm` ; ARM `add|sub rd, pc, #imm`, dont le signe ne
/// survit que dans l'encodage.
fn arm_adr(ops: &[ArmOperand; 4], site: Site, insn: &mut Insn) {
    let ArmOperand::Reg(rd) = ops[0] else {
        return;
    };
    let rd = rd.number();
    let imm = arm_imm(&ops[1]).or_else(|| arm_imm(&ops[2])).unwrap_or(0);
    let base = site.literal_base();
    let sub = !site.thumb && site.word().is_some_and(|w| (w >> 21) & 0xf == 0b0010);
    let target = if sub {
        base.wrapping_sub(imm)
    } else {
        base.wrapping_add(imm)
    };
    insn.forms_address = Some(rd);
    arm_write(rd, Expr::Imm(target), insn);
}

fn signed(off: u16, add: bool) -> i64 {
    if add {
        i64::from(off)
    } else {
        -i64::from(off)
    }
}

fn arm_addr(op: ArmOperand, site: Site) -> Option<(Addr, Option<(u8, i64)>)> {
    match op {
        ArmOperand::RegDeref(rn) => match rn.number() {
            15 => Some((Addr::Abs(site.literal_base()), None)),
            rn => Some((Addr::Base(rn, 0), None)),
        },
        ArmOperand::RegDerefPreindexOffset(rn, off, add, wback) => {
            let delta = signed(off, add);
            if rn.number() == 15 {
                let at = site.literal_base().wrapping_add(delta as u64);
                return Some((Addr::Abs(at), None));
            }
            let rn = rn.number();
            Some((Addr::Base(rn, delta), wback.then_some((rn, delta))))
        }
        ArmOperand::RegDerefPostindexOffset(rn, off, add, _) => {
            let rn = rn.number();
            Some((Addr::Base(rn, 0), Some((rn, signed(off, add)))))
        }
        ArmOperand::RegDerefPreindexReg(..)
        | ArmOperand::RegDerefPostindexReg(..)
        | ArmOperand::RegDerefPreindexRegShift(..)
        | ArmOperand::RegDerefPostindexRegShift(..) => Some((Addr::Unknown, None)),
        _ => None,
    }
}

fn arm_load(ops: &[ArmOperand; 4], site: Site, width: u64, insn: &mut Insn) {
    let (ArmOperand::Reg(rt), Some((addr, wback))) = (ops[0], arm_addr(ops[1], site)) else {
        return;
    };
    let rt = rt.number();
    if rt == 15 {
        insn.flow = match (addr, wback) {
            (Addr::Base(13, 0), Some((13, _))) => Flow::Return,
            _ => Flow::JumpVia(Via::Mem(addr)),
        };
    } else {
        insn.ops.push(Op::Load(rt, addr, width));
        if matches!(addr, Addr::Abs(_)) {
            insn.forms_address = Some(rt);
        }
    }
    if let Some((reg, delta)) = wback {
        insn.set(reg, Expr::AddImm(reg, delta));
    }
}

fn arm_store(ops: &[ArmOperand; 4], site: Site, insn: &mut Insn) {
    let (ArmOperand::Reg(rt), Some((addr, wback))) = (ops[0], arm_addr(ops[1], site)) else {
        return;
    };
    insn.ops.push(Op::Store(Expr::Reg(rt.number()), addr));
    if let Some((reg, delta)) = wback {
        insn.set(reg, Expr::AddImm(reg, delta));
    }
}

fn arm_push(list: u16, insn: &mut Insn) {
    let count = i64::from(list.count_ones());
    insn.set(13, Expr::AddImm(13, -4 * count));
    let mut slot = 0;
    for reg in 0..16u8 {
        if list & (1 << reg) != 0 {
            insn.ops.push(Op::Store(Expr::Reg(reg), Addr::Base(13, slot)));
            slot += 4;
        }
    }
}

fn arm_pop(list: u16, insn: &mut Insn) {
    let mut slot = 0;
    for reg in 0..15u8 {
        if list & (1 << reg) != 0 {
            insn.ops.push(Op::Load(reg, Addr::Base(13, slot), 4));
            slot += 4;
        }
    }
    if list & 0x8000 != 0 {
        slot += 4;
        insn.flow = Flow::Return;
    }
    insn.set(13, Expr::AddImm(13, slot));
}

fn arm_ldm(ops: &[ArmOperand; 4], add: bool, insn: &mut Insn) {
    let (ArmOperand::RegWBack(rn, wback), ArmOperand::RegList(list)) = (ops[0], ops[1]) else {
        return;
    };
    let rn = rn.number();
    if rn == 13 && wback && add {
        arm_pop(list, insn);
        return;
    }
    for reg in 0..15u8 {
        if list & (1 << reg) != 0 {
            insn.set(reg, Expr::Unknown);
        }
    }
    if list & 0x8000 != 0 {
        insn.flow = Flow::JumpVia(Via::Unknown);
    }
}

#[derive(Clone, Copy, Debug)]
enum X86Op {
    Reg(u8, u64),
    Imm(u64),
    Mem(Addr),
    Branch(u64),
    Other,
}

fn decode_x86(code: &[u8], address: u64, bitness: u32) -> Option<Insn> {
    let options = iced_x86::DecoderOptions::NONE;
    let mut decoder = iced_x86::Decoder::with_ip(bitness, code, address, options);
    if !decoder.can_decode() {
        return None;
    }
    let inst = decoder.decode();
    if inst.is_invalid() {
        return None;
    }
    let raw = code.get(..inst.len())?;
    let mut formatter = iced_x86::IntelFormatter::new();
    let mut mnemonic = String::new();
    formatter.format_mnemonic(&inst, &mut mnemonic);
    let mut operands = String::new();
    formatter.format_all_operands(&inst, &mut operands);
    let mut insn = Insn::new(address, raw, mnemonic, operands);
    let ptr = u64::from(bitness / 8);
    x86_semantics(&inst, ptr, &mut insn);
    Some(insn)
}

/// Registre général et largeur en octets. Repose sur l'ordre des variantes de
/// `iced_x86::Register` (EAX = 37 … R15D = 52, RAX = 53 … R15 = 68).
fn x86_reg(reg: Register) -> Option<(u8, u64)> {
    let n = reg as u32;
    match n {
        37..=52 => Some(((n - 37) as u8, 4)),
        53..=68 => Some(((n - 53) as u8, 8)),
        _ => None,
    }
}

fn x86_addr(inst: &iced_x86::Instruction, ptr: u64) -> Addr {
    if inst.is_ip_rel_memory_operand() {
        return Addr::Abs(inst.ip_rel_memory_address());
    }
    if inst.memory_index() != Register::None {
        return Addr::Unknown;
    }
    let disp = if ptr == 4 {
        i64::from(inst.memory_displacement32() as i32)
    } else {
        inst.memory_displacement64() as i64
    };
    match inst.memory_base() {
        Register::None => Addr::Abs(disp as u64 & ptr_mask(ptr)),
        base => match x86_reg(base) {
            Some((reg, _)) => Addr::Base(reg, disp),
            None => Addr::Unknown,
        },
    }
}

fn ptr_mask(ptr: u64) -> u64 {
    if ptr == 4 {
        0xffff_ffff
    } else {
        u64::MAX
    }
}

fn x86_op(inst: &iced_x86::Instruction, index: u32, ptr: u64) -> X86Op {
    if index >= inst.op_count() {
        return X86Op::Other;
    }
    match inst.op_kind(index) {
        OpKind::Register => match x86_reg(inst.op_register(index)) {
            Some((reg, width)) => X86Op::Reg(reg, width),
            None => X86Op::Other,
        },
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            X86Op::Branch(inst.near_branch_target())
        }
        OpKind::Memory => X86Op::Mem(x86_addr(inst, ptr)),
        _ => match inst.try_immediate(index) {
            Ok(imm) => X86Op::Imm(imm & ptr_mask(ptr)),
            Err(_) => X86Op::Other,
        },
    }
}

/// Immédiat signé, à la largeur d'un pointeur.
fn x86_delta(imm: u64, ptr: u64) -> i64 {
    if ptr == 4 {
        i64::from(imm as u32 as i32)
    } else {
        imm as i64
    }
}

fn x86_mov(op0: X86Op, op1: X86Op, insn: &mut Insn) {
    match (op0, op1) {
        (X86Op::Reg(rd, _), X86Op::Reg(rs, _)) => insn.set(rd, Expr::Reg(rs)),
        (X86Op::Reg(rd, _), X86Op::Imm(imm)) => {
            insn.set(rd, Expr::Imm(imm));
            insn.forms_address = Some(rd);
        }
        (X86Op::Reg(rd, width), X86Op::Mem(addr)) => insn.ops.push(Op::Load(rd, addr, width)),
        (X86Op::Mem(addr), X86Op::Reg(rs, _)) => insn.ops.push(Op::Store(Expr::Reg(rs), addr)),
        (X86Op::Mem(addr), X86Op::Imm(imm)) => insn.ops.push(Op::Store(Expr::Imm(imm), addr)),
        (X86Op::Reg(rd, _), _) => insn.set(rd, Expr::Unknown),
        _ => {}
    }
}

fn x86_add(op0: X86Op, op1: X86Op, sub: bool, ptr: u64, insn: &mut Insn) {
    let X86Op::Reg(rd, _) = op0 else {
        return;
    };
    let expr = match op1 {
        X86Op::Imm(imm) if sub => Expr::AddImm(rd, -x86_delta(imm, ptr)),
        X86Op::Imm(imm) => Expr::AddImm(rd, x86_delta(imm, ptr)),
        X86Op::Reg(rs, _) if !sub => Expr::AddReg(rd, rs),
        _ => Expr::Unknown,
    };
    insn.set(rd, expr);
}

fn x86_semantics(inst: &iced_x86::Instruction, ptr: u64, insn: &mut Insn) {
    let op0 = x86_op(inst, 0, ptr);
    let op1 = x86_op(inst, 1, ptr);
    let sp = 4;
    let mnemonic = inst.mnemonic();
    let sub = mnemonic == Mnemonic::Sub;
    match mnemonic {
        Mnemonic::Mov => x86_mov(op0, op1, insn),
        Mnemonic::Lea => {
            if let (X86Op::Reg(rd, _), X86Op::Mem(addr)) = (op0, op1) {
                let expr = match addr {
                    Addr::Abs(at) => Expr::Imm(at),
                    Addr::Base(reg, off) => Expr::AddImm(reg, off),
                    Addr::Unknown => Expr::Unknown,
                };
                insn.set(rd, expr);
                insn.forms_address = Some(rd);
            }
        }
        Mnemonic::Push => {
            let value = match op0 {
                X86Op::Reg(rs, _) => Expr::Reg(rs),
                X86Op::Imm(imm) => Expr::Imm(imm),
                _ => Expr::Unknown,
            };
            insn.set(sp, Expr::AddImm(sp, -(ptr as i64)));
            insn.ops.push(Op::Store(value, Addr::Base(sp, 0)));
        }
        Mnemonic::Pop => {
            if let X86Op::Reg(rd, _) = op0 {
                insn.ops.push(Op::Load(rd, Addr::Base(sp, 0), ptr));
            }
            insn.set(sp, Expr::AddImm(sp, ptr as i64));
        }
        Mnemonic::Leave => {
            insn.set(sp, Expr::Reg(5));
            insn.ops.push(Op::Load(5, Addr::Base(sp, 0), ptr));
            insn.set(sp, Expr::AddImm(sp, ptr as i64));
        }
        Mnemonic::Add | Mnemonic::Sub => x86_add(op0, op1, sub, ptr, insn),
        Mnemonic::Xor => {
            if let (X86Op::Reg(rd, _), X86Op::Reg(rs, _)) = (op0, op1) {
                if rd == rs {
                    insn.set(rd, Expr::Imm(0));
                } else {
                    insn.set(rd, Expr::Unknown);
                }
            }
        }
        Mnemonic::Call => {
            insn.flow = match op0 {
                X86Op::Branch(target) => Flow::Call(target, false),
                X86Op::Reg(reg, _) => Flow::CallVia(Via::Reg(reg)),
                X86Op::Mem(addr) => Flow::CallVia(Via::Mem(addr)),
                _ => Flow::CallVia(Via::Unknown),
            };
        }
        Mnemonic::Jmp => {
            insn.flow = match op0 {
                X86Op::Branch(target) => Flow::Jump(target, false),
                X86Op::Reg(reg, _) => Flow::JumpVia(Via::Reg(reg)),
                X86Op::Mem(addr) => Flow::JumpVia(Via::Mem(addr)),
                _ => Flow::JumpVia(Via::Unknown),
            };
        }
        Mnemonic::Ret | Mnemonic::Retf => insn.flow = Flow::Return,
        Mnemonic::Syscall | Mnemonic::Sysenter => insn.syscall = true,
        Mnemonic::Int => insn.syscall = matches!(op0, X86Op::Imm(0x80)),
        Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt => insn.flow = Flow::Stop,
        Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt => {}
        _ => match op0 {
            X86Op::Branch(target) => insn.flow = Flow::Branch(target, false),
            X86Op::Reg(rd, _) => insn.set(rd, Expr::Unknown),
            _ => {}
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_register_numbers_follow_the_hardware_encoding() {
        assert_eq!(x86_reg(Register::RAX), Some((0, 8)));
        assert_eq!(x86_reg(Register::RSP), Some((4, 8)));
        assert_eq!(x86_reg(Register::RDI), Some((7, 8)));
        assert_eq!(x86_reg(Register::R15), Some((15, 8)));
        assert_eq!(x86_reg(Register::EBX), Some((3, 4)));
        assert_eq!(x86_reg(Register::R15D), Some((15, 4)));
        assert_eq!(x86_reg(Register::RIP), None);
    }

    #[test]
    fn thumb_branch_targets_are_read_from_the_encoding() {
        // 0x1000: bl 0x2000 = f000 f800 + offset 0xffc
        //   imm32 = 0xffc = S 0, I1 1, I2 1, imm10 0x000, imm11 0x7fe -> J1 = J2 = 1
        let code = [0x00, 0xf0, 0xfe, 0xff];
        let site = Site {
            code: &code,
            address: 0x1000,
            thumb: true,
        };
        assert_eq!(site.branch_target(4), Some((0x2000, true)));
        // 0x1000: cbz r1, 0x1008 = b111
        let code = [0x11, 0xb1];
        let site = Site {
            code: &code,
            address: 0x1000,
            thumb: true,
        };
        assert_eq!(site.branch_target(2), Some((0x1008, true)));
    }

    #[test]
    fn arm_branch_targets_are_read_from_the_encoding() {
        // 0x1000: bl 0x1100 = eb00003e (offset 0xf8 depuis pc = 0x1008)
        let code = 0xeb00_003eu32.to_le_bytes();
        let site = Site {
            code: &code,
            address: 0x1000,
            thumb: false,
        };
        assert_eq!(site.branch_target(4), Some((0x1100, false)));
    }
}
