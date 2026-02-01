# -*- coding: utf-8 -*-
"""
Morse binary framing (Python 2 + 3 compatible)

Frame:
  STX (0x02)  ...payload...  ETX (0x03)

Within payload:
  Each character is encoded as a "binary Morse" string using '1' and '0'
  Characters are separated by GS (0x1D)

Binary Morse timing (classic units):
  dot  = "1"
  dash = "111"
  intra-element gap (between dots/dashes within a character) = "0"

Word separation:
  If you include spaces in plaintext, this code uses RS (0x1E) between words.
  (You can remove that if you don't want word support.)
"""

from __future__ import print_function
import io

STX = b"\x02"
ETX = b"\x03"
GS  = b"\x1D"   # Group Separator: between characters
RS  = b"\x1E"   # Record Separator: between words (optional)

# International Morse (basic set). Add more punctuation if you want.
_TEXT_TO_MORSE = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",   "E": ".",
    "F": "..-.",  "G": "--.",   "H": "....",  "I": "..",    "J": ".---",
    "K": "-.-",   "L": ".-..",  "M": "--",    "N": "-.",    "O": "---",
    "P": ".--.",  "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",   "X": "-..-",  "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.",  "(": "-.--.",  ")": "-.--.-",
    "&": ".-...",  ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.",  "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "$": "...-..-", "@": ".--.-."
}

_MORSE_TO_TEXT = {v: k for (k, v) in _TEXT_TO_MORSE.items()}


def _to_bytes(s):
    """Accepts str/bytes in Py2/3; returns bytes."""
    if isinstance(s, bytes):
        return s
    # Python 2: unicode, Python 3: str
    return s.encode("utf-8")


def _to_text(s):
    """Accepts str/bytes in Py2/3; returns text (unicode in Py2, str in Py3)."""
    if isinstance(s, bytes):
        return s.decode("utf-8", "strict")
    return s


def _morse_to_binary(morse):
    """
    Convert ".-" to binary using:
      dot="1", dash="111", intra-element gap="0"
    Example: ".-" -> "1" + "0" + "111" = "10111"
    """
    parts = []
    for i, sym in enumerate(morse):
        if sym == ".":
            parts.append("1")
        elif sym == "-":
            parts.append("111")
        else:
            raise ValueError("Invalid Morse symbol: %r" % sym)
        if i != len(morse) - 1:
            parts.append("0")
    return "".join(parts)


def _binary_to_morse(bits):
    """
    Convert binary back to ".-" by reading runs of 1s separated by 0s:
      "1"   => dot
      "111" => dash
    """
    if not bits:
        raise ValueError("Empty character payload")

    # Validate characters
    for ch in bits:
        if ch not in ("0", "1"):
            raise ValueError("Non-binary character in payload: %r" % ch)

    # Split into runs of 1s (elements) by 0 gaps
    elems = [run for run in bits.split("0") if run != ""]
    morse = []
    for run in elems:
        if run == "1":
            morse.append(".")
        elif run == "111":
            morse.append("-")
        else:
            raise ValueError("Invalid 1-run length %d in %r (expected 1 or 3)" %
                             (len(run), bits))
    return "".join(morse)


def encode_text_to_morse_binary(text, use_word_sep=True):
    """
    Encode plaintext to framed bytes:
      STX + (charbits joined by GS, words by RS) + ETX

    Returns: bytes
    """
    t = _to_text(text).upper()

    words = t.split(" ") if use_word_sep else [t.replace(" ", "")]
    encoded_words = []

    for w in words:
        char_chunks = []
        for ch in w:
            if ch not in _TEXT_TO_MORSE:
                raise ValueError("Unsupported character: %r" % ch)
            morse = _TEXT_TO_MORSE[ch]
            bits = _morse_to_binary(morse)
            char_chunks.append(bits)
        # Join characters with GS
        encoded_words.append(GS.join(_to_bytes(c) for c in char_chunks))

    payload = (RS.join(encoded_words) if use_word_sep else encoded_words[0])
    return STX + payload + ETX


def decode_morse_binary_to_text(data, use_word_sep=True):
    """
    Decode framed bytes back to plaintext.
    Expects:
      STX ... ETX
      characters separated by GS
      words separated by RS (if use_word_sep=True)

    Returns: text (unicode in Py2, str in Py3)
    """
    b = _to_bytes(data)

    # Find first STX and the next ETX after it
    stx_i = b.find(STX)
    if stx_i < 0:
        raise ValueError("Missing STX framing byte")
    etx_i = b.find(ETX, stx_i + 1)
    if etx_i < 0:
        raise ValueError("Missing ETX framing byte")

    payload = b[stx_i + 1:etx_i]

    if payload == b"":
        return _to_text(b"")

    word_blobs = payload.split(RS) if use_word_sep else [payload]
    out_words = []

    for wb in word_blobs:
        if wb == b"":
            out_words.append("")
            continue

        char_blobs = [x for x in wb.split(GS) if x != b""]
        chars = []
        for cb in char_blobs:
            bits = _to_text(cb)
            morse = _binary_to_morse(bits)
            if morse not in _MORSE_TO_TEXT:
                raise ValueError("Unknown Morse sequence: %r (from bits %r)" % (morse, bits))
            chars.append(_MORSE_TO_TEXT[morse])
        out_words.append("".join(chars))

    return " ".join(out_words) if use_word_sep else "".join(out_words)

def send_morse_code(url, text, use_word_sep=True):
    outfile = io.BytesIO(encode_text_to_morse_binary(text, use_word_sep))
    outfile.seek(0)
    return pywwwget.upload_file_to_internet_file(outfile, url)

def recv_morse_code(url, use_word_sep=True):
    infile = pywwwget.download_file_from_internet_file(url)
    infile.seek(0)
    return decode_morse_binary_to_text(infile.read(), use_word_sep)
    

# --- Optional helpers for debugging/printing ---
def pretty_show(encoded_bytes):
    """
    Make control characters visible:
      STX -> <STX>, ETX -> <ETX>, GS -> <GS>, RS -> <RS>
    """
    b = _to_bytes(encoded_bytes)
    s = b.replace(STX, b"<STX>").replace(ETX, b"<ETX>").replace(GS, b"<GS>").replace(RS, b"<RS>")
    return _to_text(s)


if __name__ == "__main__":
    msg = "SOS HELP"
    enc = encode_text_to_morse_binary(msg, use_word_sep=True)
    print("Encoded:", pretty_show(enc))
    dec = decode_morse_binary_to_text(enc, use_word_sep=True)
    print("Decoded:", dec)
