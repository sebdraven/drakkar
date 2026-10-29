//! Décodage d'une instruction AArch64, ARM, Thumb, x86 ou x86_64 en une forme
//! commune : texte, flot de contrôle et micro-opérations sur les registres et la
//! mémoire, que l'évaluateur de `disasm` interprète. Aucune instruction n'est
//! exécutée.
//!
//! Numérotation des registres : AArch64 x0 à x30, 31 = sp ; ARM r0 à r15 ;
//! x86 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8 à r15 (0 à 15).

use iced_x86::{Formatter, Mnemonic, OpKind, Register};
use std::panic::AssertUnwindSafe;
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
    /// `[base, index]`.
    Index(u8, u8),
    /// `[pc, index]` : pc tel que l'instruction le lit.
    PcIndex(u64, u8),
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

/// Mnémonique d'une instruction coprocesseur, VFP ou Advanced SIMD que
/// yaxpeax-arm ne décode pas : seule sa longueur est connue.
pub(super) const COPROCESSOR: &str = "coproc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Invalid,
    /// Le décodeur a paniqué sur ces octets.
    Panic,
}

/// `code` commence à `address`. Une panique du décodeur est rattrapée ici,
/// instruction par instruction.
pub(super) fn decode(arch: Arch, code: &[u8], address: u64, thumb: bool) -> Result<Insn, Failure> {
    let job = AssertUnwindSafe(|| decode_one(arch, code, address, thumb));
    match std::panic::catch_unwind(job) {
        Ok(Some(insn)) => Ok(insn),
        Ok(None) => Err(Failure::Invalid),
        Err(_) => Err(Failure::Panic),
    }
}

fn decode_one(arch: Arch, code: &[u8], address: u64, thumb: bool) -> Option<Insn> {
    match arch {
        Arch::Aarch64 => decode_a64(code, address),
        Arch::Arm => decode_arm(code, address, thumb),
        Arch::X86 => decode_x86(code, address, 32),
        Arch::X86_64 => decode_x86(code, address, 64),
    }
}

/// Octets à rapporter pour une instruction refusée : sa longueur en Thumb, un
/// mot ailleurs (sur x86, la longueur réelle est inconnue).
pub(super) fn undecoded_len(arch: Arch, code: &[u8], thumb: bool) -> usize {
    let narrow = arch == Arch::Arm && thumb && code.get(1).is_some_and(|&b| b < 0xe8);
    let len = if narrow { 2 } else { 4 };
    len.min(code.len())
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
                    insn.ops
                        .push(Op::Load(rt, shifted(addr, slot * width), width));
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
        Addr::PcIndex(pc, index) => Addr::PcIndex(pc.wrapping_add(by), index),
        Addr::Index(..) | Addr::Unknown => Addr::Unknown,
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
    // Strict : sinon un ldrd/strd ARM avec Rt = 15 atteint Reg::from_u8(16) et
    // panique (yaxpeax-arm 0.5.0, armv7.rs:585).
    decoder.set_allow_nonconforming(false);
    let mut reader = U8Reader::new(code);
    let Ok(inst) = decoder.decode(&mut reader) else {
        if !thumb {
            if let Some(insn) = arm_media(code, address) {
                return Some(insn);
            }
        }
        return coprocessor(code, address, thumb);
    };
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

/// Espace coprocesseur, VFP et Advanced SIMD (ARMv7-A, A5.7, A6.3 et A7) :
/// instruction sans effet suivi, de longueur 4.
fn coprocessor(code: &[u8], address: u64, thumb: bool) -> Option<Insn> {
    let raw = code.get(..4)?;
    let found = if thumb {
        let hw1 = u16::from_le_bytes([raw[0], raw[1]]);
        (hw1 & 0xec00) == 0xec00 || (hw1 & 0xff10) == 0xf900
    } else {
        arm_coprocessor(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    if !found {
        return None;
    }
    Some(Insn::new(
        address,
        raw,
        COPROCESSOR.to_string(),
        String::new(),
    ))
}

fn arm_coprocessor(word: u32) -> bool {
    if word >> 28 == 0xf {
        return word >> 25 == 0x79 || (word >> 24 == 0xf4 && word & 0x0010_0000 == 0);
    }
    (word >> 26) & 0b11 == 0b11 && (word >> 24) & 0xf != 0xf
}

const ARM_CONDITIONS: [&str; 15] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "",
];

/// Noms de yaxpeax-arm (armv7/display.rs, REG_NAMES).
fn arm_reg_name(reg: u32) -> String {
    match reg & 0xf {
        9 => "sb".to_string(),
        11 => "fp".to_string(),
        12 => "ip".to_string(),
        13 => "sp".to_string(),
        14 => "lr".to_string(),
        15 => "pc".to_string(),
        n => format!("r{n}"),
    }
}

/// Instructions media A32 (ARMv7-A, A5.4) : yaxpeax-arm 0.5.0 refuse tout cet
/// espace (bits 27:25 = 011 et bit 4 = 1, `DecodeError::Incomplete`). Seules
/// l'écriture de Rd et sa condition sont suivies ; Rd = pc termine le bloc.
fn arm_media(code: &[u8], address: u64) -> Option<Insn> {
    let raw = code.get(..4)?;
    let word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let cond = word >> 28;
    if cond == 0xf || (word >> 25) & 0b111 != 0b011 || word & 0x10 == 0 {
        return None;
    }
    let (name, operands, rd) = arm_media_form(word)?;
    let mnemonic = format!("{name}{}", ARM_CONDITIONS[cond as usize]);
    let mut insn = Insn::new(address, raw, mnemonic, operands);
    arm_write(rd as u8, Expr::Unknown, &mut insn);
    if cond != 0xe {
        conditional(&mut insn);
    }
    Some(insn)
}

/// Mnémonique, opérandes et registre écrit (ARMv7-A, A5.4.1 à A5.4.4).
fn arm_media_form(word: u32) -> Option<(&'static str, String, u32)> {
    let op1 = (word >> 20) & 0x1f;
    let op2 = (word >> 5) & 0b111;
    let rd = (word >> 12) & 0xf;
    let rn = (word >> 16) & 0xf;
    let low = word & 0xf;
    let lsb = (word >> 7) & 0x1f;
    let high = (word >> 16) & 0x1f;
    let r = arm_reg_name;
    match op1 >> 3 {
        0b01 => arm_packing(word, op1 & 0b111, op2),
        0b11 => match op1 {
            0b11000 if op2 == 0 => {
                let (rd, ra, rm) = (rn, rd, (word >> 8) & 0xf);
                if ra == 0xf {
                    Some(("usad8", format!("{}, {}, {}", r(rd), r(low), r(rm)), rd))
                } else {
                    let text = format!("{}, {}, {}, {}", r(rd), r(low), r(rm), r(ra));
                    Some(("usada8", text, rd))
                }
            }
            0b11010 | 0b11011 | 0b11110 | 0b11111 if op2 & 0b11 == 0b10 => {
                let name = if op1 & 0b00100 != 0 { "ubfx" } else { "sbfx" };
                let width = high + 1;
                let text = format!("{}, {}, #{lsb:#x}, #{width:#x}", r(rd), r(low));
                Some((name, text, rd))
            }
            0b11100 | 0b11101 if op2 & 0b11 == 0 => {
                let width = high.checked_sub(lsb)? + 1;
                if low == 0xf {
                    Some(("bfc", format!("{}, #{lsb:#x}, #{width:#x}", r(rd)), rd))
                } else {
                    let text = format!("{}, {}, #{lsb:#x}, #{width:#x}", r(rd), r(low));
                    Some(("bfi", text, rd))
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Packing, unpacking, saturation et reversal (A5.4.3) : `op1` = bits 22:20.
fn arm_packing(word: u32, op1: u32, op2: u32) -> Option<(&'static str, String, u32)> {
    let rd = (word >> 12) & 0xf;
    let rn = (word >> 16) & 0xf;
    let rm = word & 0xf;
    let imm5 = (word >> 7) & 0x1f;
    let fixed = |mask: u32| (word >> 8) & mask == mask;
    let r = arm_reg_name;
    let extend = |plain: &'static str, accumulate: &'static str| {
        if (word >> 8) & 0b11 != 0 {
            return None;
        }
        let rotation = ((word >> 10) & 0b11) * 8;
        let ror = match rotation {
            0 => String::new(),
            n => format!(", ror #{n}"),
        };
        if rn == 0xf {
            Some((plain, format!("{}, {}{ror}", r(rd), r(rm)), rd))
        } else {
            let text = format!("{}, {}, {}{ror}", r(rd), r(rn), r(rm));
            Some((accumulate, text, rd))
        }
    };
    let reverse = |name: &'static str| {
        if rn != 0xf || !fixed(0xf) {
            return None;
        }
        Some((name, format!("{}, {}", r(rd), r(rm)), rd))
    };
    let shifted = |arithmetic: bool| match (arithmetic, imm5) {
        (false, 0) => String::new(),
        (false, n) => format!(", lsl #{n}"),
        (true, 0) => ", asr #32".to_string(),
        (true, n) => format!(", asr #{n}"),
    };
    let arithmetic = word & 0x40 != 0;
    match (op1, op2) {
        (0b000, o) if o & 1 == 0 => {
            let name = if arithmetic { "pkhtb" } else { "pkhbt" };
            let text = format!("{}, {}, {}{}", r(rd), r(rn), r(rm), shifted(arithmetic));
            Some((name, text, rd))
        }
        (0b000, 0b011) => extend("sxtb16", "sxtab16"),
        (0b000, 0b101) => {
            if !fixed(0xf) {
                return None;
            }
            Some(("sel", format!("{}, {}, {}", r(rd), r(rn), r(rm)), rd))
        }
        (0b010 | 0b011, o) if o & 1 == 0 => {
            let saturate = ((word >> 16) & 0x1f) + 1;
            let text = format!("{}, #{saturate}, {}{}", r(rd), r(rm), shifted(arithmetic));
            Some(("ssat", text, rd))
        }
        (0b010, 0b011) => extend("sxtb", "sxtab"),
        (0b011, 0b001) => reverse("rev"),
        (0b011, 0b011) => extend("sxth", "sxtah"),
        (0b011, 0b101) => reverse("rev16"),
        (0b100, 0b011) => extend("uxtb16", "uxtab16"),
        (0b110 | 0b111, o) if o & 1 == 0 => {
            let saturate = (word >> 16) & 0x1f;
            let text = format!("{}, #{saturate}, {}{}", r(rd), r(rm), shifted(arithmetic));
            Some(("usat", text, rd))
        }
        (0b110, 0b011) => extend("uxtb", "uxtab"),
        (0b111, 0b001) => reverse("rbit"),
        (0b111, 0b011) => extend("uxth", "uxtah"),
        (0b111, 0b101) => reverse("revsh"),
        _ => None,
    }
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
        ArmOperand::RegDerefPreindexReg(rn, rm, true, false) => {
            Some((indexed(rn.number(), rm.number(), site), None))
        }
        ArmOperand::RegDerefPreindexRegShift(rn, shift, true, false) => {
            let addr = match plain_shift(shift) {
                Some(rm) => indexed(rn.number(), rm, site),
                None => Addr::Unknown,
            };
            Some((addr, None))
        }
        ArmOperand::RegDerefPreindexReg(..)
        | ArmOperand::RegDerefPostindexReg(..)
        | ArmOperand::RegDerefPreindexRegShift(..)
        | ArmOperand::RegDerefPostindexRegShift(..) => Some((Addr::Unknown, None)),
        _ => None,
    }
}

/// `[rn, rm]` sans décalage ni réécriture : GOT indexée du code PIC
/// (`ldr r2, [pc, r2]`, `ldr r3, [r4, r3]`).
fn indexed(rn: u8, rm: u8, site: Site) -> Addr {
    if rn == 15 {
        Addr::PcIndex(site.pc(), rm)
    } else {
        Addr::Index(rn, rm)
    }
}

fn arm_load(ops: &[ArmOperand; 4], site: Site, width: u64, insn: &mut Insn) {
    let (ArmOperand::Reg(rt), Some((addr, wback))) = (ops[0], arm_addr(ops[1], site)) else {
        return;
    };
    let rt = rt.number();
    if rt == 15 {
        // La réécriture de la base est appliquée avant la lecture de la cible.
        let target = match (addr, wback) {
            (Addr::Base(base, off), Some((reg, delta))) if base == reg => {
                Addr::Base(base, off.wrapping_sub(delta))
            }
            _ => addr,
        };
        insn.flow = match (addr, wback) {
            (Addr::Base(13, 0), Some((13, _))) => Flow::Return,
            _ => Flow::JumpVia(Via::Mem(target)),
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
            insn.ops
                .push(Op::Store(Expr::Reg(reg), Addr::Base(13, slot)));
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
                    Addr::Index(..) | Addr::PcIndex(..) | Addr::Unknown => Expr::Unknown,
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
        // 0x1000: bl 0x2000 = f000 fffe
        //   imm32 = 0xffc = S 0, I1 0, I2 0, imm10 0x000, imm11 0x7fe -> J1 = J2 = 1
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

    /// Flot d'une instruction Thumb décodée à 0x1000 (yaxpeax, puis cible relue
    /// dans l'encodage, pc = 0x1004).
    fn thumb_flow(code: &[u8]) -> Flow {
        decode(Arch::Arm, code, 0x1000, true).unwrap().flow
    }

    #[test]
    fn thumb2_branches_decode_with_their_targets() {
        // b.w 0x1100 : f000 b87e (T4, imm32 = 0xfc)
        let b_w = [0x00, 0xf0, 0x7e, 0xb8];
        assert_eq!(thumb_flow(&b_w), Flow::Jump(0x1100, true));
        // beq.w 0x1100 : f000 807e (T3)
        let beq_w = [0x00, 0xf0, 0x7e, 0x80];
        assert_eq!(thumb_flow(&beq_w), Flow::Branch(0x1100, true));
        // bl 0x2000 : f000 fffe
        let bl = [0x00, 0xf0, 0xfe, 0xff];
        assert_eq!(thumb_flow(&bl), Flow::Call(0x2000, true));
        // blx 0x1800 : f000 ebfe, cible ARM = Align(0x1004, 4) + 0x7fc
        let blx = [0x00, 0xf0, 0xfe, 0xeb];
        assert_eq!(thumb_flow(&blx), Flow::Call(0x1800, false));
        // cbz r1, 0x1008 : b111
        assert_eq!(thumb_flow(&[0x11, 0xb1]), Flow::Branch(0x1008, true));
    }

    #[test]
    fn arm_ldrd_into_pc_is_invalid_not_a_panic() {
        // ldrd pc, [r0, r1] : e180f0d1. Avec Rt = 15, un décodeur non strict
        // atteint Reg::from_u8(16) (yaxpeax-arm 0.5.0, armv7.rs:2034 puis 585).
        let code = 0xe180_f0d1u32.to_le_bytes();
        let decoded = decode(Arch::Arm, &code, 0x1000, false);
        assert_eq!(decoded.err(), Some(Failure::Invalid));
    }

    fn arm_insn(word: u32) -> Insn {
        decode(Arch::Arm, &word.to_le_bytes(), 0x1000, false).unwrap()
    }

    #[test]
    fn arm_media_instructions_refused_by_yaxpeax_are_decoded() {
        // ubfx r0, r0, #1, #1 : e7e000d0 (A8.8.246, lsb 1, widthm1 0)
        let ubfx = arm_insn(0xe7e0_00d0);
        assert_eq!(
            (ubfx.mnemonic.as_str(), ubfx.operands.as_str()),
            ("ubfx", "r0, r0, #0x1, #0x1")
        );
        assert_eq!((ubfx.len, ubfx.flow), (4, Flow::Next));
        assert_eq!(ubfx.ops, [Op::Set(0, Expr::Unknown)]);
        // uxtb r2, r8 : e6ef2078 (A8.8.274, Rn = 1111, rotation 0)
        let uxtb = arm_insn(0xe6ef_2078);
        assert_eq!(
            (uxtb.mnemonic.as_str(), uxtb.operands.as_str()),
            ("uxtb", "r2, r8")
        );
        assert_eq!(uxtb.ops, [Op::Set(2, Expr::Unknown)]);
        // rev r0, r1 : e6bf0f31 ; sxth r3, r4, ror #8 : e6bf3474
        assert_eq!(arm_insn(0xe6bf_0f31).mnemonic, "rev");
        assert_eq!(arm_insn(0xe6bf_3474).operands, "r3, r4, ror #8");
        // uxtbne pc, r0 : 16eff070, conditionnelle : le chemin continue.
        let to_pc = arm_insn(0x16ef_f070);
        assert_eq!(
            (to_pc.mnemonic.as_str(), to_pc.flow),
            ("uxtbne", Flow::Next)
        );
        // uxtb pc, r0 : e6eff070 écrit pc : fin de bloc.
        assert_eq!(arm_insn(0xe6ef_f070).flow, Flow::JumpVia(Via::Unknown));
    }

    #[test]
    fn arm_udf_is_not_taken_for_a_media_instruction() {
        // udf #0 : e7f000f0, permanently undefined (A8.8.247).
        let decoded = decode(Arch::Arm, &0xe7f0_00f0u32.to_le_bytes(), 0x1000, false);
        assert_eq!(decoded.err(), Some(Failure::Invalid));
    }

    #[test]
    fn vfp_and_simd_are_skipped_by_length() {
        // vpush {d8-d9} : ed2d 8b04 (Thumb-2), absent de yaxpeax-arm 0.5.0.
        let vpush = [0x2d, 0xed, 0x04, 0x8b];
        let insn = decode(Arch::Arm, &vpush, 0x1000, true).unwrap();
        assert_eq!((insn.mnemonic.as_str(), insn.len), (COPROCESSOR, 4));
        assert_eq!(insn.flow, Flow::Next);
        assert!(insn.ops.is_empty());
    }
}
