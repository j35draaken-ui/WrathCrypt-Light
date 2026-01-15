import binascii
import sys
import re

# Dictionary representing the morse code chart
MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}


def wrap_with_length(octstr, nbytes):
    if not octstr.startswith('0o'):
        octstr = '0o' + octstr
    return f"L{nbytes}:{octstr}"


def unwrap_with_length(wrapped):
    m = re.match(r'^L(\d+):(.+)$', wrapped)
    if m:
        return int(m.group(1)), m.group(2)
    return None, wrapped


def obfuscate_morse(morse):
    return morse.replace('.', '0').replace('-', '1')


def deobfuscate_morse(obf):
    return obf.replace('0', '.').replace('1', '-')


def init_from_text(txt):
    """Prepare representations from plaintext and print hex/binary/oct."""
    global text, hexi, b, c
    text = txt
    print('Plaintext:', text)
    hexi = binascii.hexlify(text.encode('utf-8'))
    print('Hex:', hexi)
    b = bin(int(hexi, 16))[2:].zfill(8 * len(text))
    print('Binary:', b)
    c = oct(int(b, 2))
    print('Octal:', c)


def encrypt(message):
    cipher = ''
    for letter in message:
        if letter != ' ':
            cipher += MORSE_CODE_DICT.get(letter, '?') + ' '
        else:
            cipher += ' '
    return cipher


def decrypt(messaged):
    messaged += ' '
    decipher = ''
    citext = ''
    i = 0
    for letter in messaged:
        if letter != ' ':
            citext += letter
            i = 0
        else:
            i += 1
            if i == 2:
                decipher += ' '
            else:
                if citext:
                    try:
                        decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
                    except ValueError:
                        decipher += '?'
                    citext = ''
    return decipher


def process_decrypt(edf, flags):
    """Handle deobfuscation, morse->text and numeric recovery."""
    # If flags force morse-obf, treat as morse; otherwise detect numeric inputs
    if '--morse-obf' in flags:
        messaged = deobfuscate_morse(edf)
        result = decrypt(messaged)
        print(result)
        # fall through to numeric recovery attempt from the morse-decoded text
        numeric_source = result
    else:
        # Heuristic: if input contains '.' or '-' or spaces, treat as morse
        if any(ch in edf for ch in '.- '):
            result = decrypt(edf)
            print(result)
            numeric_source = result
        else:
            # If input looks like a wrapped numeric or numeric literal, skip morse-decoding
            if re.match(r'^L\d+:', edf) or re.match(r'^(0[oO][0-7]+|0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)$', edf):
                numeric_source = edf
            else:
                # ambiguous: fallback to morse-decode
                result = decrypt(edf)
                print(result)
                numeric_source = result

    # numeric recovery: support wrapped length L{n}:<num>
    nbytes, maybe_num = unwrap_with_length(numeric_source)
    maybe_num = maybe_num.strip()
    if not maybe_num:
        return

    # detect prefix and base
    if maybe_num.lower().startswith('0o'):
        num_body = maybe_num[2:]
        base = 8
    elif maybe_num.lower().startswith('0x'):
        num_body = maybe_num[2:]
        base = 16
    elif maybe_num.lower().startswith('0b'):
        num_body = maybe_num[2:]
        base = 2
    else:
        if re.fullmatch(r'[0-7]+', maybe_num):
            num_body = maybe_num
            base = 8
        else:
            # try generic int parsing
            try:
                intval = int(maybe_num, 0)
            except Exception:
                return
            binstr = bin(intval)[2:]
            pad = (8 - len(binstr) % 8) % 8
            binstr = binstr.zfill(len(binstr) + pad)
            nbytes_calc = len(binstr) // 8
            bts = int(binstr, 2).to_bytes(nbytes_calc, byteorder='big')
            try:
                text_out = bts.decode('utf-8')
                print('Recovered text:', text_out)
            except Exception:
                print('Recovered bytes (hex):', bts.hex())
            return

    try:
        intval = int(num_body, base)
    except Exception:
        return

    if nbytes is not None:
        bitlen = nbytes * 8
    else:
        bitlen = ((intval.bit_length() + 7) // 8) * 8

    binstr = bin(intval)[2:].zfill(bitlen)
    nbytes_final = len(binstr) // 8
    bts = int(binstr, 2).to_bytes(nbytes_final, byteorder='big')
    try:
        text_out = bts.decode('utf-8')
        print('Recovered text:', text_out)
    except Exception:
        print('Recovered bytes (hex):', bts.hex())


def main():
    # assume init_from_text(...) was called and globals `text` and `c` exist
    message = c
    result = encrypt(message.upper())
    if '--morse-obf' in sys.argv:
        print('encrypted:', obfuscate_morse(result))
    else:
        print('encrypted:', result)

    if '--wrap' in sys.argv:
        nbytes = len(text.encode('utf-8'))
        print(wrap_with_length(c, nbytes))

    try:
        print('roundtrip:', decrypt(result))
    except Exception:
        print('roundtrip: <error>')

    if len(sys.argv) > 2:
        edf = sys.argv[2]
    else:
        edf = input('to be decrypted: ')

    process_decrypt(edf, sys.argv)


def print_manual():
    print('Encrypt.py manual:')
    print(' - Encrypt text -> prints hex, binary, oct, and morse')
    print('   Options: --morse-obf to obfuscate morse (0/1), --wrap to print L{n}:<oct>')
    print(' - Decrypt morse/wrapped -> accepts "."/"-" or obfuscated 0/1 (use --morse-obf)')
    print(' - USB deployment: Copy script to USB, run from terminal: python Encrypt.py [args] (requires Python on PC)')


def interactive_menu():
    while True:
        print('\nMenu:')
        print(' 1) Encrypt text')
        print(' 2) Decrypt morse/wrapped')
        print(' 3) Manual')
        print(' 4) Exit')
        choice = input('Choose an option: ').strip()
        if choice == '1':
            pt = input('input text: ')
            init_from_text(pt)
            main()
        elif choice == '2':
            ed = input('to be decrypted: ')
            obf = input('was this obfuscated? (y/N): ').strip().lower()
            flags = ['--morse-obf'] if obf == 'y' else []
            process_decrypt(ed, flags)
        elif choice == '3':
            print_manual()
        elif choice == '4':
            print('bye')
            break
        else:
            print('unknown option')


if __name__ == '__main__':
    # non-interactive (backwards compatible): first arg is plaintext unless --menu/-m
    # decrypt-only mode: skip encrypt step and run numeric/morse recovery directly
    if '--decrypt-only' in sys.argv:
        # find first non-flag argument after program name
        args = [a for a in sys.argv[1:] if not a.startswith('-')]
        if args:
            target = args[0]
        else:
            target = input('to be decrypted: ')
        process_decrypt(target, sys.argv)
    elif len(sys.argv) > 1 and not any(a in ('--menu', '-m') for a in sys.argv[1:]):
        init_from_text(sys.argv[1])
        main()
    else:
        print('Running interactive menu (use --menu or no args)')
        interactive_menu()


