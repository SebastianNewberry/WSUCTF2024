#!/usr/bin/python3

from pwn import *
import sys

# from pwn import *

morse_code = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "10": "-----"}

context.log_level = "DEBUG"

def get_process():
    host, port = sys.argv[1].split(":")

    return remote(host, port)

def generateMorseCode(string):
    words = string.split(" ")

    morseCode = []

    letterCombination = []

    for word in words:
        for letter in word:
            letter = letter.upper()
            letterCombination.append(morse_code[letter])
        morseCode.append(letterCombination)
        letterCombination = []

    stringMorseCode = "/".join([" ".join(x) for x in morseCode])

    return stringMorseCode

def generatePlainText(morseCode):
    words = morseCode.split("/")

    plaintext = ""

    for word in words:
        for letter in word.split(" "):
            for char in morse_code:
                if (morse_code[char] == letter):
                    plaintext += char
        plaintext += " "
    
    return plaintext.strip()

def main():
    p = get_process()

    numberOfPrompts = 0

    p.recvuntil(b"prompts:")

    strippedNumber = p.recvline().strip().split(b",")[0]

    numberOfPrompts = int(strippedNumber.decode())

    for x in range(numberOfPrompts):
        p.recvuntil(b"Convert")
        textToConvert = p.recvline().split(b":")[1].strip().decode()

        morseCode = generateMorseCode(textToConvert)

        p.sendlineafter(b"> ", morseCode.encode())
    
    i = 1

    listOfPlainText = []

    while(True):

        p.recvline()
        
        if(b"Wow! Great job with converting" in p.recvline()):
            break

        p.recvuntil(b"Convert")

        morseCodeToConvert = p.recvline().split(b":")[1].strip().decode()

        plaintext = generatePlainText(morseCodeToConvert)

        listOfPlainText.append((i, plaintext))

        i+= 1

        p.sendlineafter(b"> ", plaintext.encode())
    
    for lineNumber, line in listOfPlainText:
        print(lineNumber, line)

    p.interactive()

if __name__ == "__main__":
    main()