import tkinter as tk
from tkinter import filedialog, messagebox
import json
import os

config_path = "log_config.json"

def save_config(data):
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=4)

def start_dashboard():
    root = tk.Tk()
    root.title("Cyber Watchdog - Log Destination Setup")
    root.geometry("400x300")

    def choose_local():
        folder = filedialog.askdirectory()
        if folder:
            config = {
                "log_type": "local",
                "log_path": folder
            }
            save_config(config)
            messagebox.showinfo("Success", f"Logs will be saved to:\n{folder}")
            root.destroy()

    def choose_discord():
        def save_webhook():
            url = webhook_entry.get()
            if url:
                config = {
                    "log_type": "discord",
                    "webhook_url": url
                }
                save_config(config)
                messagebox.showinfo("Success", "Discord webhook saved.")
                popup.destroy()
                root.destroy()

        popup = tk.Toplevel(root)
        popup.title("Enter Discord Webhook URL")
        tk.Label(popup, text="Paste your Discord Webhook:").pack(pady=10)
        webhook_entry = tk.Entry(popup, width=40)
        webhook_entry.pack(pady=5)
        tk.Button(popup, text="Save", command=save_webhook).pack(pady=10)

    def choose_gmail():
        messagebox.showinfo("Coming Soon", "Gmail support coming later! 👀")

    label = tk.Label(root, text="Where do you want to store logs?", font=("Arial", 14))
    label.pack(pady=20)

    tk.Button(root, text="📁 Local Folder", command=choose_local, width=30).pack(pady=10)
    tk.Button(root, text="📡 Discord Webhook", command=choose_discord, width=30).pack(pady=10)
    tk.Button(root, text="📧 Gmail (Coming Soon)", command=choose_gmail, width=30, state=tk.DISABLED).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    if not os.path.exists(config_path):
        start_dashboard()
    else:
        print("✅ Config already exists. Skipping setup.")
