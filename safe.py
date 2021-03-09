#!/usr/bin/env python3

# -*- Mode: Python; coding: utf-8; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-

#

#PasswordSafe V0.1

# (c)2016 by Eduard Kelmann @ >>www.eduardkelmann.de<< >>www.kelmann.net<<
#
import csv
import random
import string
import hashlib
import getpass
import base64
import simplecrypt

SAVE_FILENAME = 'safe.csv'
PASSWORD_LENGTH = 16
LOGIN = False

def gen(length):
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    return ''.join([random.choice(chars) for i in range(length)])

def save(site, user, password):
    with open(SAVE_FILENAME, 'a') as save:
        w = csv.writer(save, delimiter=';')
        w.writerow([site, user, password])

def read(): #nicht fertig. Gibt Leerzeilen zwischen Datensätzen an
    with open(SAVE_FILENAME, 'r') as read:
        r = csv.reader(read, delimiter=';')
        for line in read:
            print(line)

def sha256(pw):
    sha256_password = hashlib.sha256(pw.encode()).hexdigest()
    return sha256_password

def encrypt(masterpassword, plainpassword):
    base64_password = base64.b64encode(simplecrypt.encrypt(masterpassword, plainpassword)).decode('utf-8')
    return base64_password

def decrypt(masterpassword, encrypted_password):
    b64decrypted_password = base64.b64decode(encrypted_password.encode('utf-8'))
    decrypted_password = simplecrypt.decrypt(masterpassword, b64decrypted_password).decode('utf-8')
    return decrypted_password

while LOGIN == False:
    masterpassword = getpass.getpass(prompt='Bitte gebe das Masterpasswort ein:')
    masterpassword_repeat = getpass.getpass(prompt='Bitte gebe das Masterpasswort erneut ein:')
    if masterpassword != masterpassword_repeat or masterpassword == '':
        print ("Passwörter stimmen nicht überein.")
    else:
        masterpassword = sha256(masterpassword)
        break


while True:
    print("Welchen Befehl möchtest du ausführen?")
    print("generate(Passwort generieren), new(Neuen Eintrag), newpw(Neuer Eintrag inkl. generiertem Passwort),\n"
            "read(Datenbank abfragen), decrypt(Passwort entschlüsseln), exit(Programm beenden)")
    command = input("Befehl: ")

    if command == "generate":
        try:
            length = int(input("Passwortlänge: "))
        except ValueError:
            length = PASSWORD_LENGTH
            print("Keine oder falsche Eingbe. Der Standardwert wird benutzt. \n")
        print("#"*30+"\n"+
        "Das generierte Passwort lautet:\n" +
        gen(length)+"\n"+
        "#"*30+"\n"+
        "Kehre zum Hauptmenü zurück.\n")

    elif command == 'new':
        site = input("Webseitenname: ")
        user = input("Username: ")
        plainpassword = getpass.getpass(prompt = 'Passwort:', stream = None)
        encrypted_password = encrypt(masterpassword, plainpassword)
        save(site, user, encrypted_password)
        print("Erfolgreich gespeichert. Kehre zum Hauptmenü zurück\n")

    elif command == "newpw":
        site = input("Webseitenname: ")
        user = input("Username: ")
        try:
            length = int(input("Passwortlänge: "))
        except ValueError:
            length = PASSWORD_LENGTH
            print("Falsche oder keine Angabe. Standardwert wird benutzt")
        genpw = gen(length)
        print("#"*30+"\n"+
        "Das Passwort lautet:\n"+
        genpw+"\n"+
        "#"*30)
        crypted_password = encrypt(masterpassword, genpw)
        save(site, user, crypted_password)
        print("Erfolgreich gespeichert. Kehre zum Hauptmenü zurück\n")

    elif command == "read":
        print("Webseite ; User ; verschlüsseltes Passwort")
        print(read())

    elif command == "decrypt":
        try:
            crypted_password = input("Gebe das zu entschlüsselnde Passwort ein:")
            print("#"*30+"\n"+
            "Das Passwort lautet: \n"+
            decrypt(masterpassword, crypted_password)+"\n"+
            "#"*30)
        except simplecrypt.DecryptionException:
            print("Fehler: Bitte überprüfe das Masterpasswort und das zu entschlüsselnde Passwort auf Richtigkeit\n")


    elif command == "exit" or command == "quit":
        break

    else:
        print("Leider hab ich dich nicht verstanden!. Kehre zum Hauptmenü zurück.")