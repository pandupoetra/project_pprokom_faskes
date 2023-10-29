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