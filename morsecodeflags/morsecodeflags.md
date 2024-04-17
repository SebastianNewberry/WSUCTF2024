In this challenge, we are given a netcat port along with a url to visit.

We can visit it by typing this in the command line:

```
nc 0.cloud.chals.io 15069
```

# Pwntools

There is a powerful library in python that makes it easy to interact with programs that accept user input as bytes.
This library is called pwntools.
The purpose of this challenge was to have users practice scripting a solution to a problem using this library.

So lets get started with it. Here is the first step:

```
pip install pwntools
```

Then at the top of our script we will write:

```
from pwn import *
```

Ok now we are ready to start the challenge.

Ok so first lets start with a minimal setup for our solve script. This is typically how it is done in pwntools:

```
#!/usr/bin/python3
from pwn import *
import sys


def get_process():
    host, port = sys.argv[1].split(":")

    port = int(port)
    
    return remote(host, port)

def main():
    p = get_process()
    

    p.interactive()

if __name__ == "__main__":
    main()

```

What this statement does is it calls a get_process function, which will return a connection to a remote host and port.

so if we run our script like this

```
python3 solve.py 0.cloud.chals.io:15069
```

sys.argv will read the additional arguments placed into the python3 command.
sys.argv[1] will be '0.cloud.chals.io:15069' part of the command, then from this we split it on the ":"
Afterwards, we assign the host to 0.cloud.chals.io and the port to 15069 and we return this so we can
use it in the main function.

Now inside of the main function, we run "p.interactive()" which gives us an interactive shell when we connect to the remote instance.

Once we connect, we see this: (some of this gets cutout, if you use netcat to reach the port, you will see it)

```
The purpose of this challenge is to convert plaintext to morse code, and morse code to plaintext.
First, you will have to convert text to morse code, then convert morse code to plain text.
Here are the guidelines for morse code:
{"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "10": "-----" "Space": "/"}
Make sure you use forward slashes for spaces between words in your answer.
it is important to use ' ' (empty spaces) in between letters or else your answer won't be understood correctly (Ex. -.- could be either "TA" or "K" without spaces. If you are trying to use the string "TA", then you need to write "- .-" with a space in between characters)
That's it. You are ready to start writing morse code.
After this number of prompts: 64, you will stop writing morse code, and instead you will be given prompts to convert from morse code to plaintext.
Eventually, one of these might lead to the flag.

Convert this plaintext to morse code: Online lectures asynchronous learning
>
```

So the basic idea of this challenge is just to convert back and forth from plaintext to morsecode and morsecode to plaintext.


# Creating the Script

In my approach, I started by copying the dictionary of characters into my own script and removing the "Space" key. We can handle that character later on.

```
morse_code = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "10": "-----"}
```

Now we have to start receiving some bytes from the server. We can use some functions like p.recvline() to receive one whole line of bytes, p.recv() to receive a specified number of bytes, or p.recvuntil() to receive all
bytes until we reach a certain byte. Then we stop.

So the first thing we need to figure out is how many times we have to convert to morsecode before this program will flip to converting to plaintext.

Lets do this:

```
p.recvuntil(b"prompts:")
strippedNumber = p.recvline().strip().split(b",")[0]
numberOfPrompts = int(strippedNumber.decode())
```

this will receive all of the bytes until we reach the byte sequence b"prompts", then it will receive the next line of bytes, then strip the comma away from the number 64.

This will result in us successfully obtaining the number: 64.

Now we can do a loop for sending prompts 64 times in morse code.

Here are the lines we use to receive plaintext that we need to turn into morse code:

```
p.recvuntil(b"Convert")
textToConvert = p.recvline().split(b":")[1].strip().decode()
```

It is important to use the decode() function to turn strings into bytes and use the encode() function to turn bytes into string format. In this case we want to receive bytes and turn them into a string.

In order to send bytes in pwntools, we usually typically use p.sendline() or p.sendlineafter(). Usually p.sendlineafter() is more useful because we can specify a specific byte to send
a line of bytes after, so the script will receive all of the bytes until it reaches a certain byte, then it will send our payload after that byte.

So in our case, we can use, so that we receieve everything until the ">" character, then send our payload:

```
p.sendlineafter(b">", payload)
```

So now lets make a function that can turn plaintext into morsecode, then send 64 lines of morsecode. That should get us to the second part of the challenge.

Here is a function to convert plaintext to morsecode:

```
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
```

This function takes a string of plaintext, and converts it to morsecode. It splits the string into words first, then it iterates over all letters of that word.
I decided to use a 2d array where the outer array was the words, and the inner array represented the different letters in the word.
Then I used " ".join() to join the letters (because different letters in morse code have to be separated by a space), then I used "/'.join()
to join the words, because spaces are represented by forward slashes in morse code.

So this code will solve this first part of this challenge. Lets try it:

```
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
    
    p.interactive()
```

Now we see this message:

```
Convert this morse code into plaintext: .. -./- .... ./.... . .- .-. -/--- ..-./.-- .- -.-- -. ./... - .- - .
```

So we pretty much have to do the same thing but in reverse.

But we have one problem. We don't know what will happen once we finish this next part of the challenge.

Here is the next part:

```
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
    ...

    while(True):

        p.recvuntil(b"Convert")

        morseCodeToConvert = p.recvline().split(b":")[1].strip().decode()

        plaintext = generatePlainText(morseCodeToConvert)

        p.sendlineafter(b"> ", plaintext.encode())
    
    p.interactive()
    


```
    
But we have one problem. We don't know what will happen once we finish this next part of the challenge. For now, let's just use a while(true) loop to continue sending plaintext.

If we run it with this code, it will hang, because it is trying to receive bytes until it finds the bytes b"Convert", but it never finds this.

a very useful technique when using pwntools is to set

```
context.log_level = "DEBUG"
```

When we do this, pwntools will print all of the bytes we send and receive from the program. Now lets try running the script again:

if we scroll down to the end of the debugging output, we will see this:

```
[DEBUG] Received 0xa9 bytes:
    b"That's right!\n"
    b'Wow! Great job with converting all of this text. One last question and you will have your flag.\r\n'
    b'What does the text on the seventh line of the poem say?\n'
    b'> '
```
So it looks like we found the last part of the challenge.

in order to do this last part, we can either look at the debugging statements, and count seven lines into converted plaintext, then use p.sendlineafter(b">", plaintext).
Or we can include these steps as part of the script.


I just created a list of plaintext, then printed out the entire poem along with the line numbers, and I found the bytes "Wow! great job with converting" in the received line,
then I just broke out of the loop that sends the plaintext.

To finish this challenge, all we have to do is enter the seventh line, of the poem, then use p.interactive() to get an interactive shell and we will have the flag.

(The full solver script is in solve.py)

flag:

```
WSUCTF{C4mpus_L1fe_1z_AW3some}
```
