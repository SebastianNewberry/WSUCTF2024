#!/usr/bin/python3

import random
import os
import threading
import socketserver
import time
import sys

totalRuns = random.randint(50, 70)

morse_code = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "10": "-----"}

phrases = [
    "Late nights in library",
    "Coffee fuels study sessions",
    "Exams looming stress rising",
    "Friends bond over textbooks",
    "Pizza for dinner again",
    "Lecture hall crowded always",
    "Parties after final exams",
    "Dorm life noisy neighbors",
    "Professors office hours invaluable",
    "Group projects endless coordination",
    "Campus squirrels steal attention",
    "Weekend trips for relaxation",
    "Graduation day dreams realized",
    "Scholarship applications endless essays",
    "Student discounts budget friendly",
    "Research papers sleepless nights",
    "Summer internships career building",
    "Joining clubs finding community",
    "Studying abroad global adventures",
    "Thesis defense nerves high",
    "Tutoring sessions extra help",
    "Campus traditions cherished memories",
    "Student protests making change",
    "Library quiet zones sanctuary",
    "Student loans looming burden",
    "Campus tour first impressions",
    "Final project presentations nerves wrecked",
    "Homecoming game school spirit",
    "All nighters before midterms",
    "Peer mentoring guiding newcomers",
    "Lab experiments hypotheses tested",
    "Sweatshirts branded with university",
    "Networking events career connections",
    "Dorm room decorations personal touches",
    "Coffee shop study sessions",
    "Graduation cap and gown",
    "Textbook buyback minimal returns",
    "Syllabus week easing in",
    "Student government elections campaigning",
    "Online courses flexible schedules",
    "Campus map navigation aid",
    "Athletic events cheering wildly",
    "Cramming for finals last minute panic",
    "Frat parties music blasting",
    "Picking classes scheduling puzzle",
    "Midterm grades anxiety spikes",
    "Hitting snooze button repeatedly",
    "Academic advisor meetings course planning",
    "Job fairs career opportunities",
    "Campus cafeteria culinary adventures",
    "GPA goals striving for excellence",
    "Student discounts saving money",
    "Group study sessions collaborative learning",
    "Student lounge hangout spot",
    "Sweatpants as daily attire",
    "Campus art installations creative inspiration",
    "Thesis research scholarly pursuit",
    "Dormitory curfews rules enforced",
    "Class discussions diverse perspectives",
    "Online lectures asynchronous learning",
    "Campus security ensuring safety",
    "Study breaks Netflix binge watching",
    "Freshman orientation making friends",
    "Student newspaper campus news",
    "Textbook rentals cost effective option",
    "Graduation cap decoration personal flair",
    "Campus bookstore expensive textbooks",
    "Dorm room essentials checklist",
    "Internship interviews professional attire",
    "Student ID card access pass",
    "Graduation ceremony rehearsal practice run",
    "Campus traditions passed down",
    "Student loans financial aid",
    "Toga party college classic",
    "Club meetings shared interests",
    "Midnight pizza delivery study fuel",
    "College radio station indie tunes",
    "Extracurricular activities well rounded resume",
    "Roommate conflicts communication essential",
    "Laptop as constant companion",
    "Graduation countdown bittersweet anticipation",
    "Study abroad application adventure awaits",
    "Campus bookstore merchandise galore",
    "Dorm room move in day",
    "Commencement speech words inspire",
    "Campus security escort late night walks",
    "Class registration race against time",
    "Library fines forgetful moments",
    "Sorority rush sisterhood bonds",
    "Dormitory fire drill inconvenience endured",
    "Coffee shop barista knows order",
    "Campus gym fitness goals",
    "Mandatory orientation sessions information overload",
    "Group project dynamics teamwork challenges",
    "Finals week survival guide",
    "Fall semester fresh start",
    "Graduation cap toss symbolic gesture",
    "Campus shuttle convenient transport",
    "Student activism voicing concerns",
    "Winter break travels homecoming joy",
    "Dormitory roommate assignments luck of draw",
    "Campus events calendar always full",
    "College town adventures local charm",
    "Graduation photoshoot memories captured",
    "Campus mailroom package pickup",
    "Study abroad blog documenting experiences",
    "Orientation leader guiding newcomers",
    "Student discounts perks of enrollment",
    "Dormitory laundry room chore duty",
    "Graduation gown fitting anticipation builds",
    "Campus Wi Fi connectivity essential",
    "Student health center care resources",
    "Textbook edition confusion costly mistake",
    "Senior thesis defense culmination of years",
    "Campus tour guide history enthusiast",
    "College mascot symbol of pride",
    "Graduation party invitations celebrations planned",
    "Campus security escort safety measure",
    "Student government meetings policy discussions",
    "Spring break getaway relaxation needed",
    "Dormitory potluck dinners community bonding",
    "Graduation cap decorating party",
    "Campus traditions passed through generations",
    "Student life fair club sign ups",
    "College rivalry games intense competition",
    "Graduation gown rental fitting appointment",
    "Campus library scholarly sanctuary",
    "Summer internship search resume building",
    "Dormitory room inspection cleanliness check",
    "Graduation speech rehearsal nerves overcome",
    "Campus bookstore expensive textbooks",
    "Summer classes accelerated learning",
    "Dormitory move out day bittersweet farewell",
    "Graduation day attire dressed to impress",
    "Campus coffee shop study hotspot",
    "Summer job applications professional experience",
    "Dormitory noise complaints walls thin",
    "Graduation day ceremony milestone achieved",
    "Campus orientation new beginnings",
    "Summer research project academic exploration",
    "Dormitory roommate agreement ground rules set",
    "Graduation day cap toss celebration ensues",
    "Campus library resource hub",
    "Study abroad application paperwork completed",
    "Dormitory roommate agreement compromises reached",
    "Graduation day cap toss joyous tradition",
    "Campus bookstore textbook purchases",
    "Study abroad experience life changing adventure",
    "Dormitory evacuation drill safety exercise",
    "Graduation ceremony rehearsal pomp and circumstance",
    "Campus dining hall culinary variety",
    "Study abroad application paperwork completed",
    "Dormitory roommate agreement compromises reached",
    "Graduation day cap toss joyous tradition",
    "Campus bookstore textbook purchases",
    "Study abroad experience life changing adventure",
    "Dormitory evacuation drill safety exercise",
    "Graduation ceremony rehearsal pomp and circumstance",
    "Campus dining hall culinary"
]

poem_lines = [
    "In the heart of Wayne State",
    "Where knowledge and dreams entwine",
    "Lies a treasure in the form of a flag",
    "A symbol of pride divine",
    "Amidst the bustling campus halls",
    "Where scholars footsteps tread",
    "A fluttering beacon catches the eye",
    "In hues of green and white",
    "Oh the flag of Wayne State flies high",
    "In the breeze of possibility",
    "A testament to the journeys embarked",
    "In pursuit of higher decree",
    "It whispers tales of resilience",
    "Of triumphs and struggles shared",
    "A banner for unity and strength",
    "In the tapestry of minds bared",
    "In the shadow of academic towers",
    "Where minds and spirits ignite",
    "The discovery of this emblematic emblem",
    "Ignites a spark pure and bright",
    "So let us gather neath its folds",
    "In homage and in cheer",
    "For in finding this flag at Wayne State",
    "We find our purpose clear",
    "For in its colors we find our kinship",
    "In its waves our stories told",
    "The flag of Wayne State forever unfurled",
    "A symbol of wisdoms stronghold"
]

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
        


class Service(socketserver.BaseRequestHandler):

    def handle(self):

        print("Received Connection")

        self.send(f'''The purpose of this challenge is to convert plaintext to morse code, and morse code to plaintext.\r\nFirst, you will have to convert text to morse code, then convert morse code to plain text.\r\nHere are the guidelines for morse code:\r\n{{"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "10": "-----" "Space": "/"}}\r\nMake sure you use forward slashes for spaces between words in your answer.\r\nit is important to use ' ' (empty spaces) in between letters or else your answer won't be understood correctly (Ex. -.- could be either "TA" or "K" without spaces. If you are trying to use the string "TA", then you need to write "- .-" with a space in between characters)\r\nThat's it. You are ready to start writing morse code.\r\nAfter this number of prompts: {totalRuns}, you will stop writing morse code, and instead you will be given prompts to convert from morse code to plaintext.\r\nEventually, one of these might lead to the flag.''')


        for i in range(totalRuns):
            randomPhrase = random.randint(0, 158)

            testPhrase = phrases[randomPhrase]

            self.send("", newline=True)
            self.send("Convert this plaintext to morse code: ", False)
            self.send(testPhrase)

            if(self.receive(generateMorseCode(testPhrase))):
                self.send("That's right!", True)
                i+= 1
            else:
                self.send("Sorry, Incorrect.", True)
                return
        
        for line in poem_lines:
            self.send("", newline=True)
            self.send("Convert this morse code into plaintext: ", False)
            self.send(generateMorseCode(line))

            if(self.receive(line)):
                self.send("That's right!", True)
            else:
                self.send("Sorry, Incorrect", True)
                return
        
        self.send("Wow! Great job with converting all of this text. One last question and you will have your flag.\r\nWhat does the text on the seventh line of the poem say?")
        if(self.receive("A fluttering beacon catches the eye")):
            self.send("That's right! Here is your flag " + str("WSUCTF{C4mpus_L1fe_1z_AW3some}"))
        else:
            self.send("Sorry, Incorrect.")



    
    def send(self, string, newline = True):

        if newline:
            string += "\n"
        
        string = string.encode()

        self.request.sendall(string)
    
    def receive(self, expectedResponse, prompt = "> "):
        self.send(prompt, newline = False)
        response = self.request.recv(4096).strip()

        return response.decode().lower() == expectedResponse.lower()


class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass

def main():

    port = int(sys.argv[2])
    host = str(sys.argv[1])

    server = ThreadedService((host, port), Service)

    server_thread = threading.Thread(target = server.serve_forever)

    server_thread.daemon = True

    server_thread.start()

    print("Server started on port", port)

    while(True):
        time.sleep(60)



if __name__ == "__main__":
    main()

