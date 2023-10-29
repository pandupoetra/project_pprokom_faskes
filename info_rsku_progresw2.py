import getpass
import hashlib
import sqlite3
import os
# init new db
try:
    os.mkdir("./saves")
except FileExistsError: pass
con = sqlite3.connect('saves/db.sqlite')
cur = con.cursor()
try:
    cur.execute('''CREATE TABLE auth
        (username text, password text, salt text)''')
except: pass
con.commit()
con.close()

# static Password Salt: appendet to each password before hashing, from os.urandom(64)
static_passwd_salt = b'%\x89\x08-\x82\xb9\xdf\x07\xbd\xbb\x88]\xa2q\x08\x90\xfb\x97\xa7R\xd5\xfc\xfda\x8b\xdd\xcb\x1c\x00\x84\x0e\xdc\xc4\xc0|1\x02-\xb0y\xff`0!gn\xa7\xdf)=\xba.w\x9f\x0b\x9a\xe6n\x9c\xa6\xc5S\xa0\xa0'

# return user or not found
def Query_user(user):
    con = sqlite3.connect('saves/db.sqlite')
    cur = con.cursor()
    db = [i for i in cur.execute("SELECT * FROM auth")]
    dbpasswd_hash = None
    for i in range(len(db)):
        if db[i][0] == user:
            return db[i]
    return "nf"
    
# Initialising peppers against bruteforce attacks
peppers = []
for i in range(256):
    peppers.append(chr(i))
# generate a random pepper for new user
def rand_pepper():
    bits = bin(ord(os.urandom(1))).replace("0b", "")
    while len(bits) <= 7:
        bits += "0"
    return peppers[int(bits, 2)]
    
# Check password of user
def check_passwd(user, raw_passwd):     
    uq = Query_user(user)
    if uq == "nf":
        return "nf"
    dbpasswd_hash = uq[1]
    usersalt = uq[2]
    for i in peppers:
        passwd = raw_passwd + i
        if hashlib.scrypt(password=passwd.encode("UTF-8"), salt=static_passwd_salt+usersalt, n=16, r=16, p=16).hex() == dbpasswd_hash:
            return True
    return False
#Function to add new users
def signUp():
    print("\nUntuk melakukan Sign UP masukan username dan password terlebih dahulu")
    cont = True
    while cont:    
        newUsername = str(input("Masukan usernamemu : "))
        newPassword = getpass.getpass(prompt = "Masukan kata sandi : ", stream = None)
        passConfirm = getpass.getpass(prompt = "Konfirmasi kata sandi : ", stream = None)

        if passConfirm == newPassword:
            print("Selamat data anda sudah tersimpan anda dapat login sekarang\n")
            con = sqlite3.connect('saves/db.sqlite')
            otsalt = os.urandom(63)
            passwd = newPassword + rand_pepper()
            cur = con.cursor()
            if Query_user(newUsername) == "nf":
                cur.execute("INSERT INTO auth VALUES (:user, :passwd, :salt)", {"user":newUsername, "passwd":hashlib.scrypt(password=passwd.encode("UTF-8"), salt=static_passwd_salt + otsalt, n=16, r=16, p=16).hex(), "salt":otsalt})
            else:
                print("Data pengguna telah ditambahkan\n")
            con.commit()
            con.close()
            cont = False
        else:
            print("Terdapat kesalahan, ulangi kata sandi anda")  
            
# log the user in            
def LogIn():
    Username = str(input("\nMasukan username:"))
    if Query_user(Username) == "nf":
        print("That User doesn't exist")
    else:
        Password = getpass.getpass(prompt = "Masukan kata sandi: ", stream = None)
        if check_passwd(Username, Password) == True:
            print("kamu sudah login")
        else:
            print("Terdapat kesalahan kata sandi, masukan kembali kata sandi anda")

while True:
    print("\nSingle Sign On ")
    print("a) Sign Up")
    print("b) login")
    pilihan = input("masukan apa yang ingin kamu lakukan: ")
    if pilihan == "a":
        signUp()
    if pilihan == "b":
        LogIn()
        break

def tambah_pasien():
    # deklarasi array daftar pasien sebagai database penyimpan data pasien
    daftar_pasien = []
    # inisilasi nilai awal perulangan
    i=0
    while True:
        print("\nPilihan fasilitas yang ingin anda pilih:")
        print("1. Poli Umum")
        print("2. Poli Gigi")
        print("3. Poli anak")
        print("4. UGD")
        print("5. keluar")
        pilihan = input("Pilih menu (1/2/3/4/5): ")
        if pilihan=="5":
            break
        elif pilihan=="1":
            print("\n-- Tambah Data Pasien --")
            while True: 
                nama = input("Masukkan nama pasien: ")
                umur = input("Masukkan umur pasien: ")
                alamat = input("Masukkan alamat pasien: ")
                tanggal=input("Masukkan tanggal pemeriksaan pasien: ")
                keluhan = input("Masukkan keluhan pasien: ")
            #pembuatan kode nomor urut pasien sesuai poli
                num=0
                num+=1
                kode=str(num).zfill(3)
                kode="PU"+kode
            # mendeklarasikan variabel yang menyimpan data yang diinput oleh pasien
                pasien = {
                    "nama": nama, 
                    "umur": umur, 
                    "alamat": alamat,
                    "tanggal":tanggal,
                    "keluhan": keluhan,
                    "nomor urutan": kode}
            # menambahkan variabel pasien ke variabel array daftar passien
                daftar_pasien.append(pasien)
            #pemberian informasi kepada user jika proses penambahan berhasil dilakukan
                print(" ")
                print(f"Data pasien {nama} telah ditambahkan.")
                print(f"nomor urutan pasien {nama}:",kode)
                print(" ")
            #Pengecekan ulang apakah mau menambahkan pasien lagi atau tidak
                cek_ulang = input("Tambahkan data pasien lainnya? (ya/tidak): ")
                if cek_ulang.lower() != "ya":
                    break

        elif pilihan=="2":
            print("\n-- Tambah Data Pasien --")
            while True: 
                nama = input("Masukkan nama pasien: ")
                umur = input("Masukkan umur pasien: ")
                alamat = input("Masukkan alamat pasien: ")
                tanggal=input("Masukkan tanggal pemeriksaan pasien: ")
                keluhan = input("Masukkan keluhan pasien: ")
            #pembuatan kode nomor urut pasien sesuai poli
                num=0
                num+=1
                kode=str(num).zfill(3)
                kode="PG"+kode
            # mendeklarasikan variabel yang menyimpan data yang diinput oleh pasien
                pasien = {
                    "nama": nama, 
                    "umur": umur, 
                    "alamat": alamat,
                    "tanggal":tanggal,
                    "keluhan": keluhan,
                    "nomor urutan": kode}
            # menambahkan variabel pasien ke variabel array daftar passien
                daftar_pasien.append(pasien)
            #pemberian informasi kepada user jika proses penambahan berhasil dilakukan
                print(" ")
                print(f"Data pasien {nama} telah ditambahkan.")
                print(f"nomor urutan pasien {nama}:",kode)
                print(" ")
            #Pengecekan ulang apakah mau menambahkan pasien lagi atau tidak
                cek_ulang = input("Tambahkan data pasien lainnya? (ya/tidak): ")
                if cek_ulang.lower() != "ya":
                    break

        elif pilihan=="3":
            print("\n-- Tambah Data Pasien --")
            while True: 
                nama = input("Masukkan nama pasien: ")
                umur = input("Masukkan umur pasien: ")
                alamat = input("Masukkan alamat pasien: ")
                tanggal=input("Masukkan tanggal pemeriksaan pasien: ")
                keluhan = input("Masukkan keluhan pasien: ")
            #pembuatan kode nomor urut pasien sesuai poli
                num=0
                num+=1
                kode=str(num).zfill(3)
                kode="PA"+kode
            # mendeklarasikan variabel yang menyimpan data yang diinput oleh pasien
                pasien = {
                    "nama": nama, 
                    "umur": umur, 
                    "alamat": alamat,
                    "tanggal":tanggal,
                    "keluhan": keluhan,
                    "nomor urutan": kode}
            # menambahkan variabel pasien ke variabel array daftar passien
                daftar_pasien.append(pasien)
            #pemberian informasi kepada user jika proses penambahan berhasil dilakukan
                print(" ")
                print(f"Data pasien {nama} telah ditambahkan.")
                print(f"nomor urutan pasien {nama}:",kode)
                print(" ")
            #Pengecekan ulang apakah mau menambahkan pasien lagi atau tidak
                cek_ulang = input("Tambahkan data pasien lainnya? (ya/tidak): ")
                if cek_ulang.lower() != "ya":
                    break

        elif pilihan=="4":
            print("\n-- Tambah Data Pasien --")
            while True: 
                nama = input("Masukkan nama pasien: ")
                umur = input("Masukkan umur pasien: ")
                alamat = input("Masukkan alamat pasien: ")
                tanggal=input("Masukkan tanggal pemeriksaan pasien: ")
                keluhan = input("Masukkan keluhan pasien: ")
            #pembuatan kode nomor urut pasien sesuai poli
                num=0
                num+=1
                kode=str(num).zfill(3)
                kode="GA"+kode
            # mendeklarasikan variabel yang menyimpan data yang diinput oleh pasien
                pasien = {
                    "nama": nama, 
                    "umur": umur, 
                    "alamat": alamat,
                    "tanggal":tanggal,
                    "keluhan": keluhan,
                    "nomor urutan": kode}
            
            # menambahkan variabel pasien ke variabel array daftar passien
                daftar_pasien.append(pasien)
            #pemberian informasi kepada user jika proses penambahan berhasil dilakukan
                print(" ")
                print(f"Data pasien {nama} telah ditambahkan.")
                print(f"nomor urutan pasien {nama}:",kode)
                print(" ")
            #Pengecekan ulang apakah mau menambahkan pasien lagi atau tidak
                cek_ulang = input("Tambahkan data pasien lainnya? (ya/tidak): ")
                if cek_ulang.lower() != "ya":
                    break
        else:
            print("Pilihan tidak valid. Silakan pilih lagi.")
        i += 1
tambah_pasien()