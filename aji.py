import os
import subprocess

def scan_domain(domain, output_file):
    print(f"Scanning {domain}...") 

    # Path folder output untuk menyimpan hasil di Windows (dengan format path WSL)
    output_folder = "/mnt/d/HASIL_XRAY_TOOLS"

    # Pastikan folder tujuan ada
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Menyusun path lengkap dengan nama file yang diberikan pengguna
    output_file_path = os.path.join(output_folder, output_file)

    # Menentukan perintah yang akan dijalankan
    command = [
        "./xray_linux_amd64", "webscan",
        "--basic-crawler",  # Menggunakan basic crawler
        f"https://{domain}",  # URL yang akan di-scan
        "--plugins", "sqldet,xss,path-traversal,xxe,upload,cmd-injection,redirect,jsonp,dirscan,ssrf,struts,thinkphp,brute-force,shiro,fastjson",
        "--html-output", output_file_path  # Menentukan output file dengan path lengkap
    ]

    try:
        # Menjalankan perintah
        subprocess.run(command, check=True)
        print(f"Scan completed. Results saved to {output_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error during Xray scan: {e}")
        print(f"Output: {e.output}")

def scan_subdomains(file_path):
    # Membaca subdomain dari file dan melakukan pemindaian untuk setiap subdomain
    try:
        with open(file_path, 'r') as f:
            domains = f.readlines()

        for domain in domains:
            domain = domain.strip()  # Menghapus whitespace dan newline
            if domain:
                output_file = f"{domain}_scan_result.html"
                scan_domain(domain, output_file)
    except FileNotFoundError:
        print(f"File {file_path} not found. Please check the file path.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    print("Choose an option:")
    print("1. Scan a single domain")
    print("2. Scan subdomains from a file")
    print("3. Exit")
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        domain = input("Enter the domain to scan: ")

        # Pengguna hanya memasukkan nama file output (misalnya 'contoh.html')
        output_file = input("Enter the output filename (e.g. 'contoh.html'): ")

        scan_domain(domain, output_file)
    elif choice == "2":
        # Menggunakan os.path.expanduser untuk mengakses path file dari lokasi manapun
        file_path = input("Enter the path of the file containing subdomains (e.g. 'subdomains.txt'): ")
        file_path = os.path.expanduser(file_path)  # Mengatasi path yang menggunakan ~ (home directory)
        scan_subdomains(file_path)
    elif choice == "3":
        print("Exiting...")
        exit()

if __name__ == "__main__":
    main()
