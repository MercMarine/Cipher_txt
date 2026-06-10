"""

Author - MercMarine
GitHub - https://github.com/MercMarine

app.py - Отвечает за графический интерфейс.

"""

import os
import customtkinter as ctk
from tkinter import filedialog
from crypto_engine import encrypt_bytes, decrypt_bytes

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("green")

# Класс для уведомлений
class ToastNotification:
    def __init__(self, parent, message, duration=3000, color="green"):
        self.parent = parent
        self.duration = duration
        self.after_id = None

        colors = {
            "green": ("#238636", "white"),
            "blue": ("#1f6feb", "white"),
            "red": ("#da3633", "white"),
            "orange": ("#d29922", "black")
        }

        bg_color, text_color = colors.get(color, colors["green"])

        self.frame = ctk.CTkFrame(
            parent,
            fg_color = bg_color,
            corner_radius = 8,
            border_width = 0
        )

        self.label = ctk.CTkLabel(
            self.frame,
            text = message,
            text_color=text_color,
            font = ctk.CTkFont(size=14, weight='bold')
        )
        self.label.pack(padx=20, pady=10)

        self.frame.place(relx=0.5, rely = 0.95, anchor='center')

        self.after_id = self.parent.after(self.duration, self.destroy)

    def destroy(self):
        if self.frame.winfo_exists():
            self.frame.destroy()

    def cancel(self):
        if self.after_id:
            self.parent.after_cancel(self.after_id)
            self.after_id = None
        self.destroy()

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Cipher text")
        self.geometry("1200x840")
        self.selected_file_path = None
        self.current_toast = None

        # Ввод пароля + заголовок
        self.label_title = ctk.CTkLabel(self, text="Ciphering using AES-256-GCM algorithm",
                                        font=("Arial", 18, "bold"))
        self.label_title.pack(pady=(15, 10))

        self.password_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.password_frame.pack(pady=5)

        self.password_entry = ctk.CTkEntry(self.password_frame, placeholder_text="Enter password for ciphering", width=500,
                                           show="*", font=("Arial", 14))
        self.password_entry.pack(side="left", padx=5)

        self.toggle_pwd_btn = ctk.CTkButton(self.password_frame, text="👁", width=40, anchor='center', command=self.toggle_password)
        self.toggle_pwd_btn.pack(side="left")

        # Выбор файла
        self.file_info_frame = ctk.CTkFrame(self, fg_color="gray20", corner_radius=10)
        self.file_info_frame.pack(pady=15, fill="x", padx=30)

        self.file_label = ctk.CTkLabel(self.file_info_frame, text="File isn't selected", font=("Arial", 13))
        self.file_label.pack(side="left", padx=15, pady=12)

        self.btn_select_file = ctk.CTkButton(self.file_info_frame, text="Select a file", width=130,
                                             command=self.select_file)
        self.btn_select_file.pack(side="right", padx=15, pady=10)

        # Кнопки шифрования/дешифрования
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=5)

        self.btn_encrypt = ctk.CTkButton(self.action_frame, text="Encrypt the file", fg_color="#2ecc71",
                                         hover_color="#27ae60", width=200, height=40, font=("Arial", 14, "bold"),
                                         command=self.action_encrypt_file)
        self.btn_encrypt.pack(side="left", padx=15)

        self.btn_decrypt = ctk.CTkButton(self.action_frame, text="Decrypt the file", fg_color="#2ecc71",
                                         hover_color="#27ae60", width=200, height=40, font=("Arial", 14, "bold"),
                                         command=self.action_decrypt_file)
        self.btn_decrypt.pack(side="left", padx=15)

        # Реализация ридера
        self.reader_frame = ctk.CTkFrame(self, fg_color="gray15", corner_radius=10)
        self.reader_frame.pack(pady=15, fill="both", expand=True, padx=30)

        self.reader_header = ctk.CTkLabel(self.reader_frame,
                                          text="Reader for decrypted file",
                                          font=("Arial", 14, "bold"), text_color="#3498db")
        self.reader_header.pack(pady=(10, 5))

        self.text_reader = ctk.CTkTextbox(self.reader_frame, width=640, height=250, font=("Consolas", 12), wrap="word")
        self.text_reader.pack(pady=5, padx=10, fill="both", expand=True)
        self.text_reader.configure(state="disabled")

        self.btn_copy_reader = ctk.CTkButton(self.reader_frame, text="Copy text", width=150,
                                             command=self.copy_from_reader)
        self.btn_copy_reader.pack(pady=(0, 10))

    def show_toast(self, message, color):
        if self.current_toast is not None:
            self.current_toast.cancel()
        self.current_toast = ToastNotification(self, message, duration=3000, color=color)

    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def select_file(self):
        path = filedialog.askopenfilename(title="Select a file for crypting or decrypting")

        if path:
            self.selected_file_path = path
            file_name = os.path.basename(path)
            file_size = os.path.getsize(path) / 1024
            self.file_label.configure(
                text=f"{file_name} ({file_size:.1f} КБ)",
                text_color="#2ecc71"
            )

            self.show_toast("The file is selected!", "blue")
            self.clear_reader()

    def clear_reader(self):
        self.text_reader.configure(state="normal")
        self.text_reader.delete("0.0", "end")
        self.text_reader.configure(state="disabled")

    def copy_from_reader(self):
        content = self.text_reader.get("0.0", "end-1c").strip()
        if not content:
            self.show_toast("Text field is empty", color="orange")
            return

        self.clipboard_clear()
        self.clipboard_append(content)
        self.show_toast("Текст успешно скопирован!", color="green")

    def action_encrypt_file(self):
        if not self.selected_file_path:
            return self.show_toast("Error: select file first!", color="red")
        password = self.password_entry.get()
        if not password:
            return self.show_toast("Error: enter a password!", color="red")

        try:
            self.show_toast("Reading and ciphering the file...", color="blue")
            self.update()

            with open(self.selected_file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = encrypt_bytes(file_data, password)

            default_name = os.path.basename(self.selected_file_path) + ".enc"
            save_path = filedialog.asksaveasfilename(
                title="Save ciphered file",
                initialfile=default_name,
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )

            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)

                self.show_toast("File encrypted!", color="green")
                self.clear_reader()
                self.text_reader.configure(state="normal")
                self.text_reader.configure(state="disabled")

        except Exception as e:
            self.show_toast(f"Error while ciphering: {e}", "red")

    def action_decrypt_file(self):
        if not self.selected_file_path:
            return self.show_toast("Error: select .enc file first!", "red")
        password = self.password_entry.get()
        if not password:
            return self.show_toast("Error: enter a password!", "red")

        try:
            self.show_toast("Reading and decrypting the file...", "blue")
            self.update()

            with open(self.selected_file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_bytes(encrypted_data, password)
            original_name = os.path.basename(self.selected_file_path)

            if original_name.endswith(".enc"):
                original_name = original_name[:-4]

            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=original_name,
                filetypes=[("All files", "*.*")]
            )

            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                self.show_toast("The file is successfully decrypted and saved!", color="green")
                self.clear_reader()
                self.text_reader.configure(state="normal")

                # Проверка размера для избежания зависания приложения
                if len(decrypted_data) <= 1_000_000:
                    try:
                        text_content = decrypted_data.decode('utf-8')
                        self.text_reader.insert("0.0", text_content)
                    except UnicodeDecodeError:
                        self.text_reader.insert("0.0", "The file isn't .txt")
                else:
                    self.text_reader.insert("0.0", "The file is too big displaying")

                self.text_reader.configure(state="disabled")

        except ValueError:
            self.show_toast("Error: Invalid password or file is damaged!", "red")
            self.clear_reader()
            self.text_reader.configure(state="normal")
            self.text_reader.insert("0.0",
                                    "Decrypting error")
            self.text_reader.configure(state="disabled")
        except Exception as e:
            self.show_toast(f"Error while decrypting: {e}", "red")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()