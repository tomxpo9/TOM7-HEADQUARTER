import subprocess

def main():
    print("=== Python Nmap Scanner ===")
    target = input("Masukkan target (IP atau domain): ").strip()
    options = input("Masukkan opsi scan (contoh: -sV, -sS, -A): ").strip()

    if not target:
        print("Target tidak boleh kosong!")
        return

    # Bangun perintah nmap
    command = ["nmap"]

    if options:
        command.extend(options.split())
    command.append(target)

    print("\n[+] Menjalankan perintah:", " ".join(command))
    print("[+] Hasil scan:\n")

    try:
        # Jalankan nmap
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)

        if result.stderr:
            print("[!] Error:\n", result.stderr)
    except FileNotFoundError:
        print("[!] Nmap tidak ditemukan. Pastikan sudah terinstall (sudo apt install nmap).")

if __name__ == "__main__":
    main()
