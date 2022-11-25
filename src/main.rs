use goblin::pe::PE;
use iced_x86::Register::EAX;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter};
use std::ffi::c_void;
fn main() {
    let func = std::env::args()
        .nth(1)
        .expect("syscall-finder.exe <func-name>");
    let file_buf = include_bytes!(r"..\ntdll.dll");
    let file = &file_buf[..];
    let pe = PE::parse(file).unwrap();
    if pe.header.coff_header.machine != 0x14c {
        // panic!("Is not a .Net executable");
    }
    let mut rva = 0;
    for export in pe.exports {
        if export.name.unwrap() == func {
            // println!("{:?}", export);
            rva = export.rva;
        }
    }
    if rva == 0 {
        println!("func name({}) not found!", func);
        return;
    }
    for i in 0..pe.sections.len() {
        if pe.sections[i].name().unwrap() == ".text" {
            let text = pe.sections[i].pointer_to_raw_data as *mut c_void;
            break;
        }
    }
    let candidate = &file_buf[rva..rva + 0x20];
    // 0f05: syscall
    if candidate
        .windows(2)
        .position(|x| x == [0x0f, 0x05])
        .is_some()
    {
        let mut decoder = Decoder::new(
            EXAMPLE_CODE_BITNESS,
            &file_buf[rva..rva + 0x20],
            DecoderOptions::NONE,
        );
        let mut instruction = Instruction::default();
        let mut i = 0;
        while decoder.can_decode() {
            i += 1;
            if i > 10 {
                println!("....\n");
                break;
            }
            decoder.decode_out(&mut instruction);
            if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_register() == EAX {
                println!(
                    "syscall code: {:?}(0x{:02x})",
                    instruction.immediate(1),
                    instruction.immediate(1)
                );
            }
        }
    } else {
        println!("could not found syscall ...");
    }
}

pub fn show_disassemble(bytes: &[u8], max_line: u32) {
    let mut decoder = Decoder::new(EXAMPLE_CODE_BITNESS, bytes, DecoderOptions::NONE);
    decoder.set_ip(EXAMPLE_CODE_RIP);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut i = 0;
    while decoder.can_decode() {
        i += 1;
        if i > max_line {
            println!("....\n");
            break;
        }
        decoder.decode_out(&mut instruction);
        output.clear();
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_register() == EAX {
            println!(
                "syscall code: {:?}(0x{:02x})",
                instruction.immediate(1),
                instruction.immediate(1)
            );
        }
        formatter.format(&instruction, &mut output);
        // print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - EXAMPLE_CODE_RIP) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 0x0000_0001_4000_1000; // 0000 0001 4000 1000
