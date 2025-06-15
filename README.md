**Author:**
# 🔒 Aplikasi Chat MQTT Terenkripsi

Selamat datang di aplikasi chat yang aman dan real-time! Aplikasi ini menggunakan teknologi MQTT dengan enkripsi AES-CBC untuk menjamin kerahasiaan pesan Anda.

## ✨ Fitur Unggulan

- 🔐 **Enkripsi End-to-End:** Pesan Anda aman dengan enkripsi AES mode CBC
- 👥 **Multi-User Support:** Chat dengan siapa saja yang terhubung
- 🎯 **Pengiriman Real-time:** Pesan tersampaikan secara instan
- 📝 **Log Pesan:** Pantau riwayat chat dengan mudah
- 🖥️ **Antarmuka Ramah Pengguna:** Desain simple dan mudah dioperasikan

## 📱 Cara Menggunakan

1. **Mulai Aplikasi**
    - Set username Anda
    - Pilih tujuan chat
    - (Opsional) Atur kunci enkripsi

2. **Kirim Pesan**
    - Ketik pesan Anda
    - Tekan Enter atau klik "Kirim"
    - Pesan terenkripsi otomatis!

## 🛠️ Panduan Instalasi

1. **Siapkan Lingkungan:**
    ```bash
    pip install paho-mqtt pycryptodome
    ```

2. **Jalankan Aplikasi:**
    ```bash
    python mqtt_aes_cbc.py
    ```

## 🔑 Pengaturan MQTT

```yaml
Broker: 103.127.97.36
Port: 1883
Username: username
Password: password
```

## ⚠️ Peringatan Keamanan

- Jaga kerahasiaan kunci enkripsi Anda
- Gunakan kunci yang sama untuk chat dua arah
- Aplikasi ini untuk pembelajaran, bukan untuk data sensitif

## 👨‍💻 Pengembang
Fabian Nabil

*"Keamanan bukanlah produk, tetapi sebuah proses" - Bruce Schneier*