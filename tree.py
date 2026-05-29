import os

def list_files_tree(start_path, indent=""):
    # Cek apakah jalur yang diberikan valid
    if not os.path.exists(start_path):
        print(f"Jalur '{start_path}' tidak ditemukan.")
        return

    # Ambil semua item di dalam folder saat ini
    try:
        items = os.listdir(start_path)
    except PermissionError:
        # Lewati folder jika tidak ada izin akses
        print(indent + "└── [Akses Ditolak]")
        return

    # Urutkan folder terlebih dahulu, baru file
    items.sort(key=lambda x: (not os.path.isdir(os.path.join(start_path, x)), x.lower()))

    for i, item in enumerate(items):
        item_path = os.path.join(start_path, item)
        is_last = (i == len(items) - 1)
        
        # Tentukan simbol percabangan
        branch = "└── " if is_last else "├── "
        
        # Cetak nama file atau folder
        print(indent + branch + item)
        
        # Jika item adalah folder, lakukan rekursi ke dalamnya
        if os.path.isdir(item_path):
            next_indent = indent + ("    " if is_last else "│   ")
            list_files_tree(item_path, next_indent)

# --- Cara Penggunaan ---
# Ganti '.' dengan jalur folder spesifik jika diperlukan (cth: "C:/Users/Nama/Documents")
folder_target = "."
print(f"Struktur folder untuk: {os.path.abspath(folder_target)}")
list_files_tree(folder_target)
