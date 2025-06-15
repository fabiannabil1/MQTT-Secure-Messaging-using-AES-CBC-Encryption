import tkinter as tk
from tkinter import scrolledtext, messagebox
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import threading
from datetime import datetime
import hashlib

# Konfigurasi MQTT
BROKER = "103.127.97.36"
PORT = 1883
USERNAME = "----"
PASSWORD = "----"
TOPIC_PREFIX = "chat/"

# Default AES Key
DEFAULT_KEY = b'ThisIsASecretKey'  # 16-byte key

# Fungsi untuk mengkonversi string key ke 16-byte key
def prepare_key(key_string):
    if len(key_string) == 16:
        return key_string.encode('utf-8')
    elif len(key_string) < 16:
        # Pad dengan null bytes
        return (key_string + '\0' * (16 - len(key_string))).encode('utf-8')
    else:
        # Hash ke MD5 untuk mendapatkan 16 bytes
        return hashlib.md5(key_string.encode('utf-8')).digest()

# Fungsi Enkripsi
def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Fungsi Dekripsi
def decrypt_message(encoded_payload, key):
    raw = base64.b64decode(encoded_payload)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

class ChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encrypted MQTT Chat")
        self.master.geometry("800x700")

        self.username = tk.StringVar()
        self.target_user = tk.StringVar()
        self.encryption_key = tk.StringVar(value="ThisIsASecretKey")
        self.is_username_set = False
        self.current_key = DEFAULT_KEY

        # Frame untuk Encryption Key
        key_frame = tk.Frame(master)
        key_frame.pack(pady=5, padx=10, fill=tk.X)
        
        tk.Label(key_frame, text="Encryption Key:").pack(side=tk.LEFT)
        self.key_entry = tk.Entry(key_frame, textvariable=self.encryption_key, width=25, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        
        self.set_key_btn = tk.Button(key_frame, text="Set Key", command=self.set_encryption_key)
        self.set_key_btn.pack(side=tk.LEFT, padx=5)
        
        self.show_key_btn = tk.Button(key_frame, text="Show/Hide", command=self.toggle_key_visibility)
        self.show_key_btn.pack(side=tk.LEFT, padx=2)
        
        self.key_status = tk.Label(key_frame, text="[Default Key]", fg="orange")
        self.key_status.pack(side=tk.LEFT, padx=5)

        # Frame untuk Username
        username_frame = tk.Frame(master)
        username_frame.pack(pady=5, padx=10, fill=tk.X)
        
        tk.Label(username_frame, text="Username Kamu:").pack(side=tk.LEFT)
        self.username_entry = tk.Entry(username_frame, textvariable=self.username, width=20)
        self.username_entry.pack(side=tk.LEFT, padx=5)
        
        self.set_username_btn = tk.Button(username_frame, text="Set Username", command=self.set_username)
        self.set_username_btn.pack(side=tk.LEFT, padx=5)
        
        self.username_status = tk.Label(username_frame, text="[Belum diset]", fg="red")
        self.username_status.pack(side=tk.LEFT, padx=5)

        # Frame untuk Target User
        target_frame = tk.Frame(master)
        target_frame.pack(pady=5, padx=10, fill=tk.X)
        
        tk.Label(target_frame, text="Kirim ke Username:").pack(side=tk.LEFT)
        self.target_entry = tk.Entry(target_frame, textvariable=self.target_user, width=20)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        
        self.set_target_btn = tk.Button(target_frame, text="Set Target", command=self.set_target)
        self.set_target_btn.pack(side=tk.LEFT, padx=5)
        
        self.target_status = tk.Label(target_frame, text="[Belum diset]", fg="red")
        self.target_status.pack(side=tk.LEFT, padx=5)

        # Notebook untuk Tab Chat dan Log
        self.notebook_frame = tk.Frame(master)
        self.notebook_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Tab buttons
        tab_frame = tk.Frame(self.notebook_frame)
        tab_frame.pack(fill=tk.X)
        
        self.chat_tab_btn = tk.Button(tab_frame, text="Chat", command=self.show_chat_tab, relief=tk.SUNKEN)
        self.chat_tab_btn.pack(side=tk.LEFT, padx=2)
        
        self.log_tab_btn = tk.Button(tab_frame, text="Encrypted Log", command=self.show_log_tab, relief=tk.RAISED)
        self.log_tab_btn.pack(side=tk.LEFT, padx=2)

        # Chat Tab
        self.chat_frame = tk.Frame(self.notebook_frame)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        
        self.chat_box = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state='disabled', height=15)
        self.chat_box.pack(fill=tk.BOTH, expand=True)

        # Log Tab
        self.log_frame = tk.Frame(self.notebook_frame)
        
        self.log_box = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, state='disabled', height=15, font=('Courier', 9))
        self.log_box.pack(fill=tk.BOTH, expand=True)

        # Frame untuk Message Input
        message_frame = tk.Frame(master)
        message_frame.pack(pady=10, fill=tk.X, padx=10)

        self.message_entry = tk.Entry(message_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda event: self.send_message())

        self.send_button = tk.Button(message_frame, text="Kirim", command=self.send_message, state='disabled')
        self.send_button.pack(side=tk.RIGHT)

        # MQTT Setup
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.username_pw_set(USERNAME, PASSWORD)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

        # Show chat tab by default
        self.current_tab = "chat"

    def get_timestamp(self):
        return datetime.now().strftime("[%H:%M:%S]")

    def toggle_key_visibility(self):
        if self.key_entry.cget('show') == '*':
            self.key_entry.config(show='')
        else:
            self.key_entry.config(show='*')

    def set_encryption_key(self):
        key_string = self.encryption_key.get().strip()
        if not key_string:
            messagebox.showerror("Error", "Encryption key tidak boleh kosong!")
            return
        
        try:
            self.current_key = prepare_key(key_string)
            self.key_status.config(text="[Custom Key Set]", fg="green")
            self.append_chat(f"{self.get_timestamp()} [SYSTEM] Encryption key berhasil diset")
            self.append_log(f"{self.get_timestamp()} [SYSTEM] Encryption key changed: {len(key_string)} chars -> 16 bytes")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal set encryption key: {str(e)}")

    def show_chat_tab(self):
        self.log_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_tab_btn.config(relief=tk.SUNKEN)
        self.log_tab_btn.config(relief=tk.RAISED)
        self.current_tab = "chat"

    def show_log_tab(self):
        self.chat_frame.pack_forget()
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_tab_btn.config(relief=tk.SUNKEN)
        self.chat_tab_btn.config(relief=tk.RAISED)
        self.current_tab = "log"

    def set_username(self):
        username = self.username_entry.get().strip()
        if not username:
            self.append_chat(f"{self.get_timestamp()} [ERROR] Username tidak boleh kosong!")
            return
        
        if self.is_username_set:
            self.append_chat(f"{self.get_timestamp()} [WARNING] Username sudah diset sebelumnya!")
            return
            
        self.username.set(username)
        self.is_username_set = True
        self.username_entry.config(state='disabled')
        self.set_username_btn.config(state='disabled')
        self.username_status.config(text=f"[{username}]", fg="green")
        
        # Subscribe ke topic setelah username diset
        threading.Thread(target=self.subscribe_to_own_topic, daemon=True).start()
        self.append_chat(f"{self.get_timestamp()} [SYSTEM] Username diset ke: {username}")
        self.update_send_button_state()

    def set_target(self):
        target = self.target_entry.get().strip()
        if not target:
            self.append_chat(f"{self.get_timestamp()} [ERROR] Target username tidak boleh kosong!")
            return
            
        self.target_user.set(target)
        self.target_status.config(text=f"[{target}]", fg="green")
        self.append_chat(f"{self.get_timestamp()} [SYSTEM] Target diset ke: {target}")
        self.update_send_button_state()

    def update_send_button_state(self):
        if self.is_username_set and self.target_user.get():
            self.send_button.config(state='normal')
        else:
            self.send_button.config(state='disabled')

    def start(self):
        try:
            self.client.connect(BROKER, PORT)
            self.client.loop_start()
            self.append_chat(f"{self.get_timestamp()} [SYSTEM] Menghubungkan ke MQTT broker...")
            self.master.mainloop()
        except Exception as e:
            print(f"Error connecting to MQTT broker: {e}")
            self.append_chat(f"{self.get_timestamp()} [ERROR] Gagal terhubung ke MQTT broker: {e}")

    def subscribe_to_own_topic(self):
        if not self.username.get():
            return
        
        topic = TOPIC_PREFIX + self.username.get()
        result = self.client.subscribe(topic)
        print(f"Subscribed to topic: {topic}, Result: {result}")
        self.append_chat(f"{self.get_timestamp()} [SYSTEM] Berhasil subscribe ke topic: {topic}")
        self.append_log(f"{self.get_timestamp()} [SYSTEM] Subscribed to topic: {topic}")

    def on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            self.append_chat(f"{self.get_timestamp()} [SYSTEM] Berhasil terhubung ke MQTT broker")
            print("Connected to MQTT broker successfully")
        else:
            self.append_chat(f"{self.get_timestamp()} [SYSTEM] Gagal terhubung ke MQTT broker, code: {reason_code}")
            print(f"Failed to connect to MQTT broker, return code: {reason_code}")

    def on_disconnect(self, client, userdata, flags, reason_code, properties):
        self.append_chat(f"{self.get_timestamp()} [SYSTEM] Terputus dari MQTT broker")
        print("Disconnected from MQTT broker")

    def on_message(self, client, userdata, msg):
        timestamp = self.get_timestamp()
        try:
            print(f"Received message on topic: {msg.topic}")
            encrypted_payload = msg.payload.decode('utf-8')
            print(f"Message payload: {encrypted_payload}")
            
            # Log encrypted message
            self.append_log(f"{timestamp} [RECEIVED] Topic: {msg.topic}")
            self.append_log(f"Encrypted: {encrypted_payload}")
            
            decrypted = decrypt_message(encrypted_payload, self.current_key)
            self.append_chat(f"{timestamp} {decrypted}")
            
            # Log decrypted message
            self.append_log(f"Decrypted: {decrypted}")
            self.append_log("=" * 80)
            
        except Exception as e:
            error_msg = f"[Gagal dekripsi] {str(e)}"
            self.append_chat(f"{timestamp} {error_msg}")
            self.append_log(f"{timestamp} [DECRYPT ERROR] {str(e)}")
            print(f"Decryption error: {e}")

    def send_message(self):
        timestamp = self.get_timestamp()
        
        if not self.is_username_set:
            self.append_chat(f"{timestamp} [ERROR] Set username terlebih dahulu!")
            return
            
        msg = self.message_entry.get().strip()
        to_user = self.target_user.get().strip()
        from_user = self.username.get()
        
        if not msg:
            self.append_chat(f"{timestamp} [ERROR] Pesan tidak boleh kosong!")
            return
            
        if not to_user:
            self.append_chat(f"{timestamp} [ERROR] Set target user terlebih dahulu!")
            return
            
        try:
            message_with_sender = f"{from_user}: {msg}"
            encrypted_msg = encrypt_message(message_with_sender, self.current_key)
            topic = TOPIC_PREFIX + to_user
            result = self.client.publish(topic, encrypted_msg)
            
            print(f"Sending message to topic: {topic}")
            print(f"Message sent result: {result}")
            
            # Log sent message
            self.append_log(f"{timestamp} [SENT] Topic: {topic}")
            self.append_log(f"Original: {message_with_sender}")
            self.append_log(f"Encrypted: {encrypted_msg}")
            self.append_log("=" * 80)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.append_chat(f"{timestamp} Saya ke {to_user}: {msg}")
            else:
                self.append_chat(f"{timestamp} [ERROR] Gagal mengirim pesan, error code: {result.rc}")
                
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.append_chat(f"{timestamp} [ERROR] Gagal enkripsi/kirim pesan: {str(e)}")
            self.append_log(f"{timestamp} [ENCRYPT ERROR] {str(e)}")
            print(f"Send message error: {e}")

    def append_chat(self, text):
        self.chat_box.configure(state='normal')
        self.chat_box.insert(tk.END, text + '\n')
        self.chat_box.configure(state='disabled')
        self.chat_box.see(tk.END)

    def append_log(self, text):
        self.log_box.configure(state='normal')
        self.log_box.insert(tk.END, text + '\n')
        self.log_box.configure(state='disabled')
        self.log_box.see(tk.END)

# Jalankan aplikasi
if __name__ == '__main__':
    root = tk.Tk()
    app = ChatApp(root)
    app.start()