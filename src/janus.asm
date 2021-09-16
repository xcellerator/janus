; JANUS: A Polyglot Binary
; Author: @TheXcellerator
; github.com/xcellerator/janus

    org 0x7c00
    bits 16

; ELF Header                    ; Offset +0x0
;       We can't avoid executing the first instruction (jg 0x47).
;       Therefore, at offset 0x47 into the file, we need to have a
;       jmp to bootloader to kick things off.
;
    db 0x7f, 0x45               ; jg 0x47
    db 0x4c                     ; dec sp
    db 0x46                     ; inc si


; C64 BASIC Entrypoint          ; Offset +0x04
;       C64 PRG files are loaded into BASIC RAM ($0800 - $A000) for
;       execution.
;
;       First comes a 2-byte address of where in memory we're loaded.
;       As we don't add the extra ",1" to the "LOAD" command, these
;       bytes are ignored (the 7F 45 at offset +0x00). (Otherwise, they
;       represent the memory location this file would be loaded at).
;
;       Next comes a 2-byte pointer to the line of BASIC which follows
;       this one (calculating string length is too costly). We don't
;       care about this as we've only got a single line. (4C 46 at
;       offset +0x02).
;
;       Now comes the BASIC bytecode. Starting with a line number (can
;       be any 16-bit number), then the BASIC bytecode (or "token code")
;       and finally arguments. We use "SYS" (token $9e) with an argument
;       of "(2491)", which is the memory address (in decimal!) on the
;       C64 of our 6502 assembly. Lastly a null-byte indicates the end
;       of the line.
;
;       Following this, should be a pointer to the third line of basic,
;       then a line number, and another BASIC instruction. The pointer
;       is taken up by "02 00" at offset +0x10 (e_type in the ELF Header)
;       and the line number by "3E 00" at offset +0x12 (e_machine in the
;       ELF Header). However, what follows are 4 null bytes, so both
;       the line is terminated and the entire BASIC program.
;       (This can be seen via the "LIST" command on the C64, the second
;       line number is "15872", or 0x3e00 in hexadecimal).
;
c64_basic:
    db 0x0a, 0x00               ; BASIC Line 10
    db 0x9e                     ; BASIC "SYS" Token Code
    db 0x20, "(2491)", 0x00     ; Argument: " (2491)" = $9bb
    db 0x00                     ; Null Byte terminates instruction

; Elf64_Ehdr Remainder          ; Offset +0x10
;       We can't get around these bytes being present and exact in
;       the ELF header if we want to satisfy the loader.
;
;       Elf64_Ehdr:
;       * e_type
;       * e_machine
;       * e_version     (Not Required)
;       * e_entry
;       * e_phoff
;
    db 0x02, 0x00               ; Elf64_Ehdr->e_type    (0x02 = ET_EXEC)
    db 0x3e, 0x00               ; Elf64_Ehdr->e_machine (0x3e = EM_X86_64)
    db 0x00, 0x00, 0x00, 0x00   ; Elf64_Ehdr->e_version (Required by C64)

    db 0xaa, 0x00, 0x40, 0x00
    db 0x00, 0x00, 0x00, 0x00   ; Elf64_Ehdr->e_entry

    db 0x4a, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00   ; Elf64_Ehdr->e_phoff


; Bootloader printChar          ; Offset +0x28
;       Prints the character in al to the screen via BIOS interrupt 0x10
;       These 12 bytes occupy the following fields in the ELF header:
;       * Elf64_Ehdr->e_shoff   ( 8 bytes )
;       * Elf64_Ehdr->e_flags   ( 4 bytes )
;
printChar:
    mov ah, 0xe                 ; "Display Character (TTY Output)"
    mov bh, 0x0                 ; Write to Page 0
    mov bl, 0x0                 ; Foreground Colour
    int 0x10                    ; Graphics Interrupt (No Return Value)
    times 3 db 0x90             ; 3 Bytes of Padding (NOPs)
    ret


; Compulsory Elf64_Ehdr Fields  ; Offset +0x34
;       These fields are compulsory, otherwise the ELF loader will
;       refuse to load/execute the binary.
;
    db 0x40, 0x00               ; Elf64_Ehdr->e_ehsize
    db 0x38, 0x00               ; Elf64_Ehdr->e_phentsize
    db 0x01, 0x00               ; Elf64_Ehdr->e_phnum


; Bootloader setCursor          ; Offset +0x3b
;       Moves the cursor to a nice position to start printing characters
;       These 13 bytes take us all the way up to offset +0x47 where the
;       jmp to bootloader has to be.
;
setCursor:
    pusha
    mov ah, 0x2                 ; "Set Cursor Position"
    mov bh, 0x0                 ; Page Number
    mov dh, 0x2                 ; Row Number
    mov dl, 0x0                 ; Column Number
    int 0x10                    ; Graphics Interrupt (No Return Value)
    popa
    ret


; The ELF header has to start with "7F 45", which is "jg 0x47" in 16-bit
; assembly. Here at offset +0x47, we jump to the bootloader entry point.
;
    call bootloader             ; Offset +0x47


; Start of ELF Program Header   ; Offset +0x4a
;
    db 0x01, 0x00, 0x00, 0x00   ; Elf64_Phdr->p_type
    db 0x05, 0x00, 0x00, 0x00   ; Elf64_Phdr->p_flags
    times 8 db 0x00             ; Elf64_Phdr->p_offset

    db 0x00, 0x00, 0x40, 0x00
    times 4 db 0x00             ; Elf64_Phdr->p_vaddr

    times 8 db 0x58             ; Elf64_Phdr->p_paddr (Not Checked)

    db 0x2b                     ; Shellcode + Strlen
    times 7 db 0x00             ; Elf64_Phdr->p_filesz

    db 0x2b                     ; Shellcode + Strlen
    times 7 db 0x00             ; Elf64_Phdr->p_memsz

; The last field is Elf64_Phdr->p_align, but it isn't checked by the ELF
; loader, so we just go straight into clearScreen.


; Bootloader clearScreen        ; Offset +0x7a
;       Clears any text on the screen (if running under QEMU, SeaBIOS
;       leaves behind some loading information).
;
clearScreen:
    pusha
    mov ah, 0x6                 ; "Scroll Up Window"
    xor al, al                  ; Number of Lines to Scroll (0x00 = Full)
    mov bh, 0x3                 ; Colour Attribute
    xor cx, cx                  ; (CH,CL) = Coords of Upper Left Corner
    mov dx, 0x184f              ; (DH,DL) = Coords of Lower Right Corner
    int 0x10                    ; Graphics Interrupt (No Return Value)
    popa
    ret


; Bootloader/DOS printString    ; Offset +0x8a
;       We start with the DOS print string routine because it uses
;       interrupt 0x21 (unmapped for a BIOS). This way, the bootloader
;       can execute these instructions and they'll have essentially
;       no effect. DOS executables use "$"-terminated strings.
;
;       Then, we loop over the string pointed to by SI and call the
;       bootloader printChar function until it hits a null-byte.
;
printString:
    ; DOS Version
    ;
    db 0x0e                     ; push cs         ; Set CS=DS
    db 0x1f                     ; pop ds
    db 0xba, 0x11, 0x02         ; mov dx, 0x111   ; Offset to string
    db 0xb4, 0x09               ; mov ah, 0x9     ; Write string to stdout
    db 0xcd, 0x21               ; int 0x21        ; DOS Interrupt
    db 0xb8, 0x02, 0x4c         ; mov ax, 0x4c02  ; 0x4c=Exit, 0x02=Ret Val
    db 0xcd, 0x21               ; int 0x21        ; DOS Interrupt

    ; Non-DOS Version
    ;
    pusha
    .loop:
        lodsb                   ; Load char in (SI) to AL
        test al, al             ; Check for null-byte
        jz .end
        call printChar          ; Print the char
        call delay              ; Cheap animation effect
    jmp .loop
    .end:
        popa
        jmp waitForKeypress     ; Go wait for a keypress


; 64-Bit Shellcode              ; Offset +0xaa
;       Standard Linux shellcode for printing a string.
;       Note that the string pointer in ESI and string length in DL are
;       both hardcoded to 0x400111 and 0x32 respectively.
;
    db 0xb0, 0x01                       ; mov al, 0x1           ; WRITE
    db 0x66, 0x89, 0xc7                 ; mov di, ax            ; STDOUT
    db 0xbe, 0x11, 0x01, 0x40, 0x00     ; mov esi, 0x400111     ; buffer
    db 0xb2, 0x32                       ; mov dl, 0x32          ; strlen
    db 0x0f, 0x05                       ; syscall
    db 0xb0, 0x3c                       ; mov al, 0x3c          ; EXIT
    db 0x66, 0xff, 0xc7                 ; inc di                ; ret 2
    db 0x0f, 0x05                       ; syscall


; RAR: Magic                    ; Offset +0xbf
;
    db 'Rar!', 0x1a, 0x07, 0x00


; RAR: Main Header              ; Offset +0xc6
;
    db 0xcf, 0x90               ; CRC32(Main Header) & 0xffff = 0x90cf
    db 0x73                     ; Block Type (0x73 = HEAD_MAIN)
    times 2 db 0x00             ; Padding
    db 0x0d, 0x00, 0x00, 0x00   ; Block Size (0xd)
    times 4 db 0x00             ; Padding


; RAR: File Header              ; Offset +0xd3
;
    db 0x4a, 0x92               ; CRC32(File Header) & 0xffff = 0x924a
    db 0x74                     ; Block Type (0x74 = HEAD_FILE)
    db 0x20, 0x80               ; Flags (LHD_WINDOW128, LONG_BLOCK)
    db 0x3e, 0x00               ; Block Size = 0x33 (62)
    db 0x33, 0x00, 0x00, 0x00   ; Compressed Size = 51
    db 0x33, 0x00, 0x00, 0x00   ; Uncompressed Size = 51
    db 0x02                     ; Host OS (0x2 = HOST_WIN32)
    db 0xb1, 0x9c, 0xc4, 0x8a   ; CRC32(Data) = 0x8ac49cb1
    db 0xa0, 0x6c, 0x28, 0x0c   ; Timestamp (0x0c286ca0)
    db 0x14                     ; Version (0x14 = VERSION_2_0)
    db 0x30                     ; Compressed Method (0x30 = UNCOMPRESSED)
    db 0x1e, 0x00               ; Filename Length = 29
    db 0x20, 0x00, 0x00, 0x00   ; Attributes (0x20 = ARCHIVE)


; RAR: Filename
; PKZIP: Compressed File        ; Offset +0xf3
;
    db 0x50, 0x4b, 0x03, 0x04   ; Signature
    db 0x0a, 0x00               ; Version (10)
    dw 0x00
    db 0x00, 0x00               ; Compression Method (None)
    times 4 db 0x58             ; Padding (Not Checked)
    db 0x60, 0xa6, 0xd1, 0x2c   ; CRC32(Contents)
    db 0x30, 0x00, 0x00, 0x00   ; Compressed size
    db 0x30, 0x00, 0x00, 0x00   ; Uncompressed Size
    times 4 db 0x00


; String                        ; Offset +0x111
;       This is the string printed by the various executable and
;       compressed formats this file appears to be.
;       * Bootloader prints until the null-byte
;       * ELF prints until the CR (0xa)
;       * COM prints until the "$"
;       * C64 prints until the null-byte
;       * ZIP contains until the LF (0xd)
;       * RAR contains the entire string (up to and including "$")
;
    msg db 'BGGP 2021 GOT ME THINKING STRANGE - xcellerator', 0xa, 0xd, 0x0, '$'


; RAR: Archive End              ; Offset +0x144
;
    db 0xc4, 0x3d               ; CRC32(Archive End) & 0xffff = 0x3dc4
    db 0x7b                     ; Block Type (0x7b = HEAD_ENDARC)
    db 0x00, 0x40               ; Flags
    db 0x07, 0x00               ; Block Size

; PKZIP: Start of Central Directory     ; Offset +0x14b
;
    db 0x50, 0x4b, 0x01, 0x02   ; Signature
    dw 0x00
    db 0x0a, 0x00               ; Version (10)
    dd 0x00
    times 4 db 0x58             ; Unused (Not Checked)
    db 0x60, 0xa6, 0xd1, 0x2c   ; CRC32(Contents) (Repeat)
    db 0x30, 0x00, 0x00, 0x00   ; Compressed Size
    db 0x30, 0x00, 0x00, 0x00   ; Uncompressed Size
    db 0x0f, 0x00               ; Filename Size (15)
    dd 0x00
    times 8 db 0x58             ; Unused (Not Checked)
    db 0xf3, 0x00, 0x00, 0x00   ; Offset to Compressed File Header (0xf3)
;   The filename should follow, but can replace it with a BIOS function


; Bootloader delay              ; Offset +0x179
; PKZIP: Start of Central Directory: Filename
;       Waits a set number of seconds/milliseconds
;
delay:
    pusha
    mov ah, 0x86                ; "BIOS Wait"
    mov al, 0                   ; Unused
    mov cx, 0x1                 ; Seconds
    mov dx, 0                   ; Milliseconds
    int 0x15                    ; Memory Interrupt (Status Returned in AH)
    popa
    ret


; PKZIP: End of Central Directory       ; Offset +0x188
;
    db 0x50, 0x4b, 0x05, 0x06   ; Signature
    dw 0x00
    times 4 db 0x58             ; Unused (Not Checked)
    db 0x01, 0x00               ; Number of Entries (0x01)
    db 0x3d, 0x00, 0x00, 0x00   ; Size of Central Directory (0x3d)
    db 0x4b, 0x01, 0x00, 0x00   ; Offset to SCD (0x14b)


; GNU Multiboot 2.02            ; Offset +0x19c
;
    times 4 db 0x58             ; 64-bit aligned!

    db 0xd6, 0x50, 0x52, 0xe8   ; Magic (0xe85250d6)
    dd 0x00                     ; Architecture (0x00 = i386)
    db 0x00, 0x01, 0x00, 0x00   ; Header Length
    db 0x2a, 0xae, 0xad, 0x17   ; Checksum (Magic + Arch + Length + Checksum == 0x00)

; 16-bit Entrypoint             ; Offset +0x1b0
;       We jump here from offset +0x47 and call the other BIOS/COM
;       routines in this file.
;
bootloader:
    call clearScreen
    call setCursor
    mov si, msg
    call printString

; C64 6502 Assembly             ; Offset +0x1bc
;       When the C64 soft resets following the "SYS" BASIC instruction,
;       PC will point here.
;
;       Load full character set so we can use lower-case
;
        db 0xa9, 0x0e           ; lda #0x0e     ; Full Character Set
        db 0x20, 0xd2, 0xff     ; jsr 0xffd2    ; C64 CHROUT

;       C64 is 8-bit, so we have to load the low and high bytes of the 
;       string address one at a time. We load them into an address in 
;       the "zero-page" ($0020) so that we can use the Y register to
;       easily deference the bytes in the string.
;
        db 0xa9, 0x09           ; lda #>msg ($09)
        db 0x85, 0x21           ; sta $21              ; High Byte
        db 0xa9, 0x10           ; lda #<msg ($10)
        db 0x85, 0x20           ; sta $20              ; Low Byte

;       Print the string, and return to BASIC
;
        db 0x20, 0xcc, 0x09     ; jsr $09cc            ; Call printStr
        db 0x60                 ; rts                  ; Return to BASIC

;       Print String Routine    ; C64 Addr: $09cc
;
        db 0xa0, 0x00           ; ldy #0x0             ; Reset Y
;       LOOP
            db 0xb1, 0x20       ; lda ($20),y          ; Read in a character
            db 0xc0, 0x21       ; cpy #$21             ; After 33 chars
            db 0xf0, 0x0b       ; beq +$b              ; Jump to EXTRACR
            db 0xc9, 0x00       ; cmp #$00             ; $00-terminated string
            db 0xf0, 0x0d       ; beq +$d              ; Jump to END
            db 0x20, 0xeb, 0x09 ; jsr $09eb            ; Jump to printChar
            db 0xc8             ; iny                  ; Increment Y
            db 0x4c, 0xce, 0x09 ; jmp $09ce            ; Jump to LOOP
;       EXTRACR
            db 0x20, 0xe6, 0x09 ; jsr $09e6            ; Print a CR
            db 0x4c, 0xd4, 0x09 ; jmp $09d4            ; Jump back into LOOP
;       DONE
            db 0x60             ; rts                  ; Return

;       Print CR Routine        ; C64 Addr: $09e6
;
        db 0xa9, 0x0d           ; lda #13               ; Carriage Return
        db 0x4c, 0xeb, 0x09     ; jmp $09eb             ; Jump to printChar

;       Print Character Routine ; C64 Addr: $09eb
;       The C64 uses PETSCII, not ASCII. For alpha-numeric characters,
;       we can just flip the 6th most significant bit to convert.
;       Anything above 64 ("@"), can be left alone.
;
        db 0xc9, 0x40           ; cmp #64
        db 0x90, 0x02           ; bcc +$2               ; Jump to DONE
        db 0x49, 0x20           ; eor #0b00100000       ; Convert Char
;       DONE
            db 0x4c, 0xd2, 0xff ; jmp $ffd2             ; C64 CHROUT

; Bootloader: waitForKeypress   ; Offset +0x1f5
;       The "Get Keystroke" BIOS function from interrupt 0x16 waits
;       for a keypress. Once a key is hit, the scancode is returned
;       in AH and the ASCII character in AL. Here, we just use it as
;       a cheap way to re-run the program.
;
waitForKeypress:
    nop                         ; Single Byte Padding (NOP)
    pusha
    mov ah, 0x0                 ; Get Keystroke
    int 0x16                    ; Keyboard Interrupt
    popa
    jmp bootloader

; MBR Signature                 ; Offset +0x1fe
;       Every x86 BIOS bootloader has to end with "55 AA"
;
    db 0x55, 0xaa
