import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import shutil  
import hashlib
import requests
from datetime import datetime
import json
import subprocess

API_KEY_FILE = "api_key.json"                         # API 키
CONFIG_FILE = "./build/upload_path.txt"                         
FILE_PATH_FILE = "./build/selected_file_path.txt"  # 파일 경로를 저장할 텍스트 파일

def select_path():
    global UPLOAD_FOLDER
    folder_path = filedialog.askdirectory()
    if folder_path:
        UPLOAD_FOLDER = folder_path
        save_config()

def save_config():
    with open(CONFIG_FILE, "w") as file:
        file.write(UPLOAD_FOLDER)

def load_config():
    try:
        with open(CONFIG_FILE, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return ""

def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as file:
        json.dump({"api_key": api_key}, file)

def load_api_key():
    try:
        with open(API_KEY_FILE, "r") as file:
            data = json.load(file)
            return data.get("api_key", "")
    except FileNotFoundError:
        return ""

def save_selected_file_path(file_path):
    with open(FILE_PATH_FILE, "w") as file:
        file.write(file_path)


def hash_file(filename):
    if os.path.isfile(filename):
        h = hashlib.sha256()
        with open(filename, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
        result = f'sha256 hash of {filename}: {h.hexdigest()}'
        print(result)
        return h.hexdigest()
    else:
        result = f'ERROR: {filename} does not exist. Check the file path location.\n'
        print(result)
        return result

def virusTotal_lookup(hashValue, apiKey, filename=None):
    print(f'VirusTotal report details for file hash: {hashValue}\n')
    url = f'https://www.virustotal.com/api/v3/files/{hashValue}'
    headers = {
        'x-apikey': apiKey,
        'Accept': 'application/json',
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if "404" in str(e):
            if filename:
                result = messagebox.askyesno("File not found", "File not found on VirusTotal.\n Do you want to upload it for analysis?")
                if result:
                    upload_url = 'https://www.virustotal.com/api/v3/files'
                    with open(filename, 'rb') as file:
                        files = {'file': file}
                        upload_response = requests.post(upload_url, headers=headers, files=files)
                    upload_response.raise_for_status()
                    return upload_response.json()  
                else:
                    return {"error": {"message": "File not found on VirusTotal and not uploaded for analysis."}}
            else:
                return {"error": {"message": "File not found on VirusTotal and no file provided for upload."}}
        else:
            result = f'API response: {e}\nFor more information visit: https://developers.virustotal.com/reference/errors\n'
            print(result)
            return {"error": {"message": result}}

def format_json(data):
    formatted_data = ""

    if "error" in data:
        formatted_data += f"Error: {data['error']['message']}\n"
    else:
        total_vendors = 0
        total_detections = 0

        if "data" in data and "attributes" in data["data"]:
            formatted_data += "Security Vendor\tDetection\n"
            if "last_analysis_results" in data["data"]["attributes"]:
                for k, v in data["data"]["attributes"]["last_analysis_results"].items():
                    total_vendors += 1
                    if v["result"] is not None:
                        total_detections += 1
                        formatted_data += f"{k}\t{v['result']}\n"

                formatted_data += f'\nWARNING: {total_detections} of {total_vendors} Security Vendors flagged this file hash value as malicious\n\n'
                
                basic_prop = {}

                if "first_submission_date" in data["data"]["attributes"]:
                    basic_prop["First submission date"] = str(datetime.fromtimestamp(data["data"]["attributes"]["first_submission_date"]))

                if "last_analysis_date" in data["data"]["attributes"]:
                    basic_prop["Last analysis date"] = str(datetime.fromtimestamp(data["data"]["attributes"]["last_analysis_date"]))

                if "ssdeep" in data["data"]["attributes"]:
                    basic_prop["ssdeep"] = data["data"]["attributes"]["ssdeep"]

                if "sha256" in data["data"]["attributes"]:
                    basic_prop["sha256"] = data["data"]["attributes"]["sha256"]

                if "sha1" in data["data"]["attributes"]:
                    basic_prop["sha1"] = data["data"]["attributes"]["sha1"]

                if "md5" in data["data"]["attributes"]:
                    basic_prop["md5"] = data["data"]["attributes"]["md5"]

                formatted_data += "Basic Properties\n"
                for k, v in basic_prop.items():
                    formatted_data += f"{k}\t{v}\n"
            else:
                formatted_data += "No analysis results available.\n"

        else:
            formatted_data += "The file has been uploaded to VirusTotal.\nPlease wait at least 1 minute \nAfter that, please click 'Lookup Hash' again\n"

    return formatted_data

class virusTotalLookupGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal Hash Lookup")
        self.create_widgets()
        saved_folder = load_config()
        if saved_folder:
            global UPLOAD_FOLDER
            UPLOAD_FOLDER = saved_folder
            self.update_folder_path()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(column=0, row=0, sticky="nsew")

        label = ttk.Label(frame, text="Enter File Path or Hash:")
        label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky="nsew")

        self.input_entry = ttk.Entry(frame, width=40)
        self.input_entry.grid(column=0, row=1, columnspan=2, pady=(0, 10), sticky="nsew")

        api_key_label = ttk.Label(frame, text="Enter VirusTotal API Key:")
        api_key_label.grid(column=0, row=4, columnspan=2, pady=(10, 0), sticky="nsew")

        self.api_key_entry_var = tk.StringVar(value=load_api_key())
        self.api_key_entry = ttk.Entry(frame, show="*", width=40, textvariable=self.api_key_entry_var)
        self.api_key_entry.grid(column=0, row=5, columnspan=2, pady=(0, 10), sticky="nsew")

        file_button = ttk.Button(frame, text="File", command=self.browse_file)
        file_button.grid(column=0, row=2, pady=(0, 10), sticky="nsew")

        select_path_button = ttk.Button(frame, text="Select Path", command=select_path)
        select_path_button.grid(column=1, row=2, pady=(0, 10), sticky="nsew")

        upload_button = ttk.Button(frame, text="Upload File", command=self.upload_file)
        upload_button.grid(column=2, row=2, pady=(0, 10), sticky="nsew")

        hash_button = ttk.Button(frame, text="Lookup Hash", command=self.lookup_hash)
        hash_button.grid(column=0, row=3, columnspan=3, pady=(0, 10), sticky="nsew")

        set_key_button = ttk.Button(frame, text="Set API Key", command=self.set_api_key)
        set_key_button.grid(column=0, row=6, columnspan=2, pady=(10, 0), sticky="nsew")

        run_cpp_button = ttk.Button(frame, text="Receive Queue", command=self.Receive_Q)
        run_cpp_button.grid(column=0, row=7, columnspan=3, pady=(10, 0), sticky="nsew")
        
        run_cpp_button = ttk.Button(frame, text="Send Queue", command=self.Send_Q)
        run_cpp_button.grid(column=0, row=8, columnspan=3, pady=(10, 0), sticky="nsew")
        
        run_cpp_button = ttk.Button(frame, text="Run Monitoring", command=self.Run_Monitoring)
        run_cpp_button.grid(column=0, row=9, columnspan=3, pady=(10, 0), sticky="nsew")
        

        self.result_text = tk.Text(frame, height=10, width=50)
        self.result_text.grid(column=0, row=10, columnspan=3, pady=(10, 0), sticky="nsew")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, file_path)

    def upload_file(self):
        file_path = self.input_entry.get()
        if os.path.isfile(file_path):
            shutil.copy(file_path, UPLOAD_FOLDER)
            save_selected_file_path(file_path)
            messagebox.showinfo("Upload Successful", f"File uploaded to: {UPLOAD_FOLDER}")
        else:
            messagebox.showerror("File Error", "The selected file does not exist.")

    def lookup_hash(self):
        input_value = self.input_entry.get()
        api_key = self.api_key_entry.get()

        if os.path.isfile(input_value):
            hash_value = hash_file(input_value)
            response = virusTotal_lookup(hash_value, api_key, input_value)
        else:
            hash_value = input_value
            response = virusTotal_lookup(hash_value, api_key)

        formatted_response = format_json(response)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, formatted_response)

    def set_api_key(self):
        api_key = self.api_key_entry.get()
        save_api_key(api_key)
        messagebox.showinfo("API Key Saved", "Your VirusTotal API Key has been saved.")

    def update_folder_path(self):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Selected upload folder: {UPLOAD_FOLDER}")


    def Receive_Q(self):
        api_key = self.api_key_entry.get()
        save_api_key(api_key)
        save_config()
        subprocess.run(["./receive"], cwd="./build")  # Unix-based 시스템
        # subprocess.Popen(["example.exe"], cwd="./build")  # Windows 시스템
        
    def Send_Q(self):
        api_key = self.api_key_entry.get()
        save_api_key(api_key)
        save_config()
        subprocess.run(["./send"], cwd="./build")  # Unix-based 시스템
        # subprocess.Popen(["example.exe"], cwd="./build")  # Windows 시스템
        
    def Run_Monitoring(self):
        api_key = self.api_key_entry.get()
        save_api_key(api_key)
        save_config()
        subprocess.Popen(["./monitoring"], cwd="./build")  # Unix-based 시스템
        # subprocess.Popen(["example.exe"], cwd="./build")  # Windows 시스템

if __name__ == "__main__":
    root = tk.Tk()
    gui_instance = virusTotalLookupGUI(root)
    root.mainloop()

