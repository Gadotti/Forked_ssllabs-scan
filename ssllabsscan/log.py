import os
import datetime

log_file_name = None
file_size_limit = 500 * 1024  # 500 KB

def generate_log_file_name(log_folder: str):
    global log_file_name
    if log_file_name is None:
        log_file_name = "ssllabsscan-log.txt"
    
    suffix = extract_suffix(log_file_name)    

    while True:
        log_path = os.path.join(log_folder, log_file_name)

        if not os.path.exists(log_path):
            return log_file_name

        if os.path.exists(log_path) and os.path.getsize(log_path) < file_size_limit:
            return log_file_name
        
        suffix += 1
        log_file_name = f"ssllabsscan-log_{suffix}.txt"

def extract_suffix(base_name):
    suffix = 0
    base_name_without_extension, extension = os.path.splitext(base_name)

    if base_name_without_extension.endswith("_"):
        try:
            suffix = int(base_name_without_extension.rsplit("_", 1)[1])
        except ValueError:
            pass

    return suffix

def log_event(log_folder:str, message: str):
    log_file = generate_log_file_name(log_folder)
    log_path = os.path.join(log_folder, log_file)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} > {message}"

    with open(log_path, 'a', encoding='utf-8') as log_file:
        log_file.write(log_message + '\n')

    print(log_message)