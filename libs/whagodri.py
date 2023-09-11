import io
import json
import os
import requests
import sys
import argparse
import gpsoauth
import queue
import threading
import time
import subprocess
from configobj import ConfigObj
from getpass import getpass
from textwrap import dedent
from requests import Response
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium_stealth import stealth


total_size: int
num_files: int

exitFlag = 0
queueLock = threading.Lock()
workQueue = queue.Queue(9999999)
abs_path_file = os.path.abspath(__file__)  # C:\Users\Desktop\whapa\libs\whagodri.py
abs_path = os.path.split(abs_path_file)[0]  # C:\Users\Desktop\whapa\libs\
split_path = abs_path.split(os.sep)[:-1]  # ['C:', 'Users', 'Desktop', 'whapa']
whapa_path = os.path.sep.join(split_path)  # C:\Users\Desktop\whapa


class WaBackup:
    """
    Provide access to WhatsApp backups stored in Google drive.
    """

    def __init__(self, gmail, password, android_id, celnumbr, oauth_token):
        if not oauth_token:
            print("Requesting access to Google...")
            token = gpsoauth.perform_master_login(email=gmail, password=password, android_id=android_id)
            if token.get("Error") == "NeedsBrowser":
                error(token)
                print("\n")
                for remaining in range(15, -1, -1):
                    sys.stdout.write("\r")
                    sys.stdout.write("{:2d} seconds remaining to try to gain access through a web browser. Press Ctrl+C to cancel".format(remaining))
                    sys.stdout.flush()
                    time.sleep(1)

                url = token.get("Url")
                options = Options()
                options.add_argument("--window-size=720,720")
                #os.environ['GH_TOKEN'] = ""
                try:
                    if operating_system() == "Windows":
                        driver = webdriver.Chrome(service=Service("chromedriver.exe"), options=options)
                    elif operating_system() == "MacOs M1":
                        driver = webdriver.Chrome(service=Service("chromedriverM1"), options=options)
                    elif operating_system() == "MacOs":
                        driver = webdriver.Chrome(service=Service("chromedriverMac"), options=options)
                    else:
                        driver = webdriver.Chrome(service=Service("chromedriver"), options=options)
                except:
                    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

                stealth(driver,
                        languages=["en-US", "en"],
                        vendor="Google Inc.",
                        platform="Win32",
                        webgl_vendor="Intel Inc.",
                        renderer="Intel Iris OpenGL Engine",
                        fix_hairline=True,
                        )

                driver.get(url)
                for remaining in range(30, -1, -1):
                    sys.stdout.write("\r")
                    sys.stdout.write("{:2d} seconds remaining to login to your Google Account".format(remaining))
                    sys.stdout.flush()
                    time.sleep(1)

                sys.stdout.write("\nFinished!\n")
                cookies = driver.get_cookies()
                for cookie in cookies:
                    if cookie.get("name") == 'oauth_token':
                        oauth_token = cookie.get("value")
                        print("A valid token has been obtained.")
                        break

                driver.close()
                if not oauth_token:
                    print("No valid token has been obtained.")
                    exit()

                print("Requesting access to Google by OAuth cookie...")
                token = gpsoauth.perform_master_login_oauth(email=gmail, oauth_token=oauth_token, android_id=android_id)
                if "Token" in token:
                    print("Granted.")
                    print("Writing Token in your settings.cfg file...")
                    cfg_file = f'{whapa_path}/cfg/settings.cfg'.replace("/", os.path.sep)
                    config = ConfigObj(cfg_file, interpolation=None)
                    config['google-auth']['oauth'] = token['Token']
                    config.write()
                    oauth_token = token['Token']
                else:
                    error(token)
                    quit()
            elif "Token" not in token:
                error(token)
                quit()
            else:
                print("Granted.")
                oauth_token = token['Token']

        print("Requesting authentication for Google Drive...")
        auth = gpsoauth.perform_oauth(
            gmail,
            oauth_token,
            android_id,
            "oauth2:https://www.googleapis.com/auth/drive.appdata",
            "com.whatsapp",
            "38a0f7d505fe18fec64fbf343ecaaaf310dbd799",
        )
        if "Auth" not in auth:
            error(auth)
            quit()

        print("Granted.")
        global Auth, phone
        Auth = auth
        phone = celnumbr

    def get(self, path, params=None, **kwargs):
        response = requests.get(
            f"https://backup.googleapis.com/v1/{path}",
            headers={"Authorization": f'Bearer {Auth["Auth"]}'},
            params=params,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def get_page(self, path, page_token=None):
        return self.get(path, None if page_token is None else {"pageToken": page_token}, ).json()

    def list_path(self, path):
        last_component = path.split("/")[-1]
        page_token = None
        while True:
            page = self.get_page(path, page_token)
            yield from page[last_component]
            if "nextPageToken" not in page:
                break
            page_token = page["nextPageToken"]

    def backups(self):
        return self.list_path("clients/wa/backups")

    def backup_files(self, backup):
        return self.list_path(f'{backup["name"]}/files')


def banner():
    """ Function Banner """
    print(r"""
     __      __.__             ________      ________        .__ 
    /  \    /  \  |__ _____   /  _____/  ____\______ \_______|__|
    \   \/\/   /  |  \\__  \ /   \  ___ /  _ \|    |  \_  __ \  |
     \        /|   Y  \/ __ \\    \_\  (  <_> )    `   \  | \/  |
      \__/\  / |___|  (____  /\______  /\____/_______  /__|  |__|
           \/       \/     \/        \/              \/          

    -------------- Whatsapp Google Drive Extractor --------------""")


def help():
    """ Function show help """

    print("""\n    ** Author: Ivan Moreno a.k.a B16f00t
    ** Github: https://github.com/B16f00t
    ** Fork from WhatsAppGDExtract by TripCode and forum.xda-developers.com and YuriCosta
    Usage: python3 whagodri.py -h (for help)
    """)


def createSettingsFile():
    """ Function that creates the settings file """

    cfg_file = f'{whapa_path}/cfg/settings.cfg'.replace("/", os.path.sep)
    with open(cfg_file, 'w') as cfg:
        cfg.write(dedent("""
            [report]
            company = ""
            record = ""
            unit = ""
            examiner = ""
            notes = ""
            
            [google-auth]
            gmail = alias@gmail.com
            # Optional. The account password or app password when using 2FA.
            password  = yourpassword
            # Optional. Login using the oauth cookie.
            oauth = ""
            # Optional. The result of "adb shell settings get secure android_id".
            android_id  = 0000000000000000
            # Optional. Enter the backup country code + phonenumber be synchronized, otherwise it synchronizes all backups.
            # You can specify a list of celnumbr = BackupNumber1, BackupNumber2, ...
            celnumbr = ""
            
            [icloud-auth] 
            icloud  = alias@icloud.com
            passw = yourpassword
            """).lstrip())


def getConfigs():
    cfg_file = f'{whapa_path}/cfg/settings.cfg'.replace("/", os.path.sep)
    config = ConfigObj(cfg_file, interpolation=None)
    try:
        gmail = config['google-auth']['gmail']
        password = config['google-auth']['password']
        celnumbr = config['google-auth']['celnumbr'].lstrip('+0')
        oauth_token = config['google-auth']['oauth']
        android_id = config['google-auth']['android_id']
        if not password:
            try:
                password = getpass(f"Enter your password for {gmail}: ")
            except KeyboardInterrupt:
                quit('\nCancelled!')

        return {
            "gmail": gmail,
            "password": password,
            "android_id": android_id,
            "celnumbr": celnumbr,
            "oauth_token": oauth_token,
        }

    except Exception as e:
        print(e)
        quit(f'The "{cfg_file}" file is missing or corrupt!')


def human_size(size):
    for s in ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]:
        if abs(size) < 1024:
            break
        size = int(size / 1024)
    return f"({size} {s})"


def backup_info(backup):
    try:
        print(f'[i] Backup name     : {backup["name"]}')
        print(
            f'[-] Whatsapp version: {json.loads(backup["metadata"]).get("versionOfAppWhenBackup")}'
        )
        print(
            f'[-] Backup protected: {json.loads(backup["metadata"]).get("passwordProtectedBackupEnabled")}'
        )
        print(f'[-] Backup upload   : {backup["updateTime"]}')
        print(
            f'[-] Backup size     : {backup["sizeBytes"]} Bytes {human_size(int(backup["sizeBytes"]))}'
        )
        print("[+] Backup metadata")
        print(
            f'    [-] Backup Frequency         : {json.loads(backup["metadata"]).get("backupFrequency")} '
        )
        print(
            f'    [-] Backup Network Settings  : {json.loads(backup["metadata"]).get("backupNetworkSettings")} '
        )
        print(
            f'    [-] Backup Version           : {json.loads(backup["metadata"]).get("backupVersion")} '
        )
        print(
            f'    [-] Include Videos In Backup : {json.loads(backup["metadata"]).get("includeVideosInBackup")} '
        )
        print(
            f'    [-] Num Of Photos            : {json.loads(backup["metadata"]).get("numOfPhotos")}'
        )
        print(
            f'    [-] Num Of Media Files       : {json.loads(backup["metadata"]).get("numOfMediaFiles")}'
        )
        print(
            f'    [-] Num Of Messages          : {json.loads(backup["metadata"]).get("numOfMessages")}'
        )
        print("    [-] Video Size               : {} Bytes {}".format(json.loads(backup["metadata"]).get("videoSize"),
                                                                      human_size(int(
                                                                          json.loads(backup["metadata"]).get("videoSize")))))
        print("    [-] Backup Size              : {} Bytes {}".format(json.loads(backup["metadata"]).get("backupSize"),
                                                                      human_size(int(
                                                                          json.loads(backup["metadata"]).get("backupSize")))))
        print("    [-] Media Size               : {} Bytes {}".format(json.loads(backup["metadata"]).get("mediaSize"),
                                                                      human_size(int(
                                                                          json.loads(backup["metadata"]).get("mediaSize")))))
        print("    [-] Chat DB Size             : {} Bytes {}".format(json.loads(backup["metadata"]).get("chatdbSize"),
                                                                      human_size(int(
                                                                          json.loads(backup["metadata"]).get("chatdbSize")))))
    except Exception as e:
        print(e)


def error(token):
    print("Failed")
    print(token)
    failed = token.get("Error")
    if "BadAuthentication" in failed:
        print("\n   Workaround\n-----------------")
        print(
            "1. Check that your email and password are correct in the settings file.\n"
            "2. Your are using a old python version. Works >= 3.8.\n"
            "3. Update requirements, use in a terminal: 'pip3 install --upgrade -r ./doc/requirements.txt' or 'pip install --upgrade -r ./doc/requirements.txt\n"
            "4. Your OAuth token configured in the settings file may have expired. The token will be deleted and you will have to log in again.")

        cfg_file = f'{whapa_path}/cfg/settings.cfg'.replace("/", os.path.sep)
        config = ConfigObj(cfg_file, interpolation=None)
        config['google-auth']['oauth'] = ""
        config.write()

    elif "NeedsBrowser" in failed:
        print("\n   Workaround\n-----------------")
        print(
            "1. Maybe you need unlock captcha in your account, If you request it, log in to your browser and then click here, https://accounts.google.com/b/0/DisplayUnlockCaptcha")
        print(
            "2. Or you have double factor authentication enabled, so disable it in this URL: https://myaccount.google.com/security")
        print("3. If you want to use 2FA, you will have to go to the URL: https://myaccount.google.com/apppasswords\n"
              "   Then select Application: Other. Write down: Whapa, and a password will be display, then you must write the password in your settings.cfg.")

    elif "DeviceManagementRequiredOrSyncDisabled" in failed:
        print("\n   Workaround\n-----------------")
        print(
            "1. You are using a GSuite account.  The reason for this is, that for this google-apps account, the enforcement of policies on mobile clients is enabled in admin console (enforce_android_policy).\n"
            "   If you disable this in admin-console, the authentication works.")

def get_file(passed_file: str, is_dry_run: bool):
    global total_size, num_files
    output_folder = args.output
    if not output_folder:
        output_folder = os.getcwd()

    file_short = os.path.sep.join(passed_file.split("/")[3:])
    if is_dry_run:

        print(f"    [-] Skipped (Dry Run): {passed_file}")

    else:
        response = requests.get(
            f"https://backup.googleapis.com/v1/{passed_file}?alt=media",
            headers={"Authorization": f'Bearer {Auth["Auth"]}'},
            stream=True,
        )
        if response.status_code == 200:
            passed_file = output_folder + file_short
            if not os.path.isfile(passed_file):
                os.makedirs(os.path.dirname(passed_file), exist_ok=True)
                with open(passed_file, "bw") as destination:
                    for chunk in response.iter_content(chunk_size=None):
                        destination.write(chunk)
                print(f"    [-] Downloaded: {passed_file}")
                total_size = len(response.content)
                num_files += 1

            else:
                print(f"    [-] Skipped: {passed_file}")

        else:
            print(f"    [-] Not downloaded: {passed_file}")


def get_multiple_files(drives, files_dict: dict, is_dry_run: bool):
    global exitFlag
    exitFlag = 0
    threadList = ["Thread-01", "Thread-02", "Thread-03", "Thread-04", "Thread-05", "Thread-06", "Thread-07",
                  "Thread-08", "Thread-09", "Thread-10",
                  "Thread-11", "Thread-12", "Thread-13", "Thread-14", "Thread-15", "Thread-16", "Thread-17",
                  "Thread-18", "Thread-19", "Thread-20",
                  "Thread-21", "Thread-22", "Thread-23", "Thread-24", "Thread-25", "Thread-26", "Thread-27",
                  "Thread-28", "Thread-29", "Thread-30",
                  "Thread-31", "Thread-32", "Thread-33", "Thread-34", "Thread-35", "Thread-36", "Thread-37",
                  "Thread-38", "Thread-39", "Thread-40"]
    threads = []
    print("[i] Generating threads...")
    print(f'[+] Backup name : {drives["name"]}')
    for threadID, tName in enumerate(threadList, start=1):
        thread = MyThread(threadID, tName, workQueue, is_dry_run=is_dry_run)
        thread.start()
        threads.append(thread)
    lenfiles = len(files_dict)
    queueLock.acquire()

    output_folder = args.output
    if not output_folder:
        output_folder = os.getcwd()

    for n, (entry, size) in enumerate(files_dict.items(), start=1):
        file_name = os.path.sep.join(entry.split("/")[3:])
        local_store = f"{output_folder}/{file_name}".replace("/", os.path.sep)
        workQueue.put(
            {'bearer': Auth["Auth"], 'url': entry, 'local': local_store, 'now': n, 'lenfiles': lenfiles, 'size': size})
    queueLock.release()
    while not workQueue.empty():
        pass

    exitFlag = 1
    for t in threads:
        t.join()


def get_multiple_files_with_out_threads(files_dict: dict, is_dry_run: bool):
    total_files: int = len(files_dict)

    output_folder: str = args.output
    if not output_folder:
        output_folder = os.getcwd()

    global total_size, num_files
    total_size = 0
    num_files = 0

    for file_index, (file_url, file_size) in enumerate(files_dict.items(), start=1):
        file_name = os.path.sep.join(file_url.split("/")[3:])
        local_file_path = f"{output_folder}/{file_name}".replace("/", os.path.sep)
        if os.path.isfile(local_file_path) and os.path.getsize(local_file_path) == file_size:
            print(
                f"    [-] Number: {file_index}/{total_files} - {local_file_path} : Already Exists"
            )

        elif is_dry_run:
            print(f"    [-] Skipped (Dry Run): {local_file_path}")

        else:
            response: Response = requests.get(
                f"https://backup.googleapis.com/v1/{file_url}?alt=media",
                headers={"Authorization": f'Bearer {Auth["Auth"]}'},
                stream=True,
            )
            if response.status_code == 200:

                os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                destination: io.BufferedWriter
                with open(local_file_path, "bw") as destination:
                    chunk: bytes
                    for chunk in response.iter_content(chunk_size=None):
                        destination.write(chunk)
                print(
                    f"    [-] Number: {file_index}/{total_files} - {local_file_path} : Download Success"
                )
                total_size += file_size
                num_files += 1

            else:
                print(
                    f"    [-] Number: {file_index}/{total_files} - {local_file_path} : Download Failure, Error - {response.status_code} : {response.reason}"
                )


class MyThread(threading.Thread):
    def __init__(self, thread_id, name, q, is_dry_run: bool):
        threading.Thread.__init__(self)
        self.threadID = thread_id
        self.name = name
        self.q = q
        self.is_dry_run = is_dry_run

    def run(self):
        process_data(self.name, self.q, self.is_dry_run)


def process_data(thread_name: str, q, is_dry_run: bool):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            data = q.get()
            queueLock.release()
            get_multiple_files_thread(data['bearer'], data['url'], data['local'], data['now'], data['lenfiles'],
                                      data['size'], thread_name, is_dry_run=is_dry_run)
        else:
            queueLock.release()

        time.sleep(1)


def get_multiple_files_thread(bearer: str, url: str, local: str, now: int, len_files: int, size: int, thread_name: str,
                              is_dry_run: bool):
    global total_size, num_files
    if os.path.isfile(local):
        print(f"    [-] Number: {now}/{len_files} - {thread_name} => Skipped: {local}")

    elif is_dry_run:
        print(f"    [-] Skipped (Dry Run): {local}")

    else:
        response: Response = requests.get(
            f"https://backup.googleapis.com/v1/{url}?alt=media",
            headers={"Authorization": f"Bearer {bearer}"},
            stream=True,
        )
        if response.status_code == 200:
            os.makedirs(os.path.dirname(local), exist_ok=True)
            destination: io.BufferedWriter
            with open(local, "bw") as destination:
                chunk: bytes
                for chunk in response.iter_content(chunk_size=None):
                    destination.write(chunk)
            print(
                f"    [-] Number: {now}/{len_files} - {thread_name} => Downloaded: {local}"
            )
            total_size += size
            num_files += 1

        else:
            print(
                f"    [-] Number: {now}/{len_files} - {thread_name} => Not downloaded: {local}"
            )


def operating_system():
    """ Get the name of the OS """

    if sys.platform in ["win32", "cygwin"]:
        return "Windows"
    elif sys.platform == "Darwin":
        if subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string']).decode('utf-8') == "Apple M1\n":
            return "MacOs M1"
        else:
            return "MacOs"
    else:
        return "Linux"


# Initializing
if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Extract your Whatsapp files from Google Drive")
    user_parser = parser.add_mutually_exclusive_group()
    user_parser.add_argument("-i", "--info", help="Show information about Whatsapp backups", action="store_true")
    user_parser.add_argument("-l", "--list", help="List all available files", action="store_true")
    user_parser.add_argument("-lw", "--list_whatsapp", help="List Whatsapp backups", action="store_true")
    user_parser.add_argument("-p", "--pull", help="Pull a file from Google Drive")
    user_parser.add_argument("-s", "--sync", help="Sync all files locally", action="store_true")
    user_parser.add_argument("-si", "--s_images", help="Sync Images files locally", action="store_true")
    user_parser.add_argument("-sv", "--s_videos", help="Sync Videos files locally", action="store_true")
    user_parser.add_argument("-sa", "--s_audios", help="Sync Audios files locally", action="store_true")
    user_parser.add_argument("-sx", "--s_documents", help="Sync Documents files locally", action="store_true")
    user_parser.add_argument("-sd", "--s_databases", help="Sync Databases files locally", action="store_true")
    parser.add_argument("-o", "--output", help="Output path to save files", type=str)
    parser.add_argument("-np", "--no_parallel", help="No parallel downloads", action="store_true")
    parser.add_argument("-dr", "--dry_run", help="Dry Run : No downloads", action="store_true")
    args = parser.parse_args()

    cfg_file = r'{}/cfg/settings.cfg'.format(whapa_path).replace("/", os.path.sep)
    if not os.path.isfile(cfg_file):
        createSettingsFile()

    if len(sys.argv) <= 1:
        help()

    else:
        print("[i] Searching...\n")
        wa_backup = WaBackup(**getConfigs())
        backups = wa_backup.backups()
        try:
            if args.info:
                for backup in backups:
                    backup_info(backup)

            elif args.list:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    print("[i] Backup name: {}".format(backup["name"]))
                    for file in wa_backup.backup_files(backup):
                        num_files += 1
                        total_size += int(file["sizeBytes"])
                        print("    [-] {}".format(file["name"]))

                print("[i] {} files {}".format(num_files, human_size(total_size)))

            elif args.list_whatsapp:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    print("[i] Backup name: {}".format(backup["name"]))
                    for file in wa_backup.backup_files(backup):
                        num_files += 1
                        total_size += int(file["sizeBytes"])
                        if os.path.sep.join(file["name"].split("/")[6:]) == "msgstore.db.crypt14":
                            print("    [-] {}".format(file["name"]))
                            print("    [-] Size {} {}".format(file["sizeBytes"], human_size((int(file["sizeBytes"])))))

            elif args.sync:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("\n[i] Backup {} omitted. Write a correct phone number in the setting file".format(
                            number_backup))

            elif args.s_images:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            if ("jpg" in i) or ("jpeg" in i) or ("png" in i):
                                filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("[i] Backup {} omitted".format(number_backup))

            elif args.s_videos:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            if "mp4" in i:
                                filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("[i] Backup {} omitted".format(number_backup))

            elif args.s_audios:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            if ("mp3" in i) or ("opus" in i):
                                filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("[i] Backup {} omitted".format(number_backup))

            elif args.s_documents:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            if file["name"].split("/")[6] == "WhatsApp Documents":
                                filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("[i] Backup {} omitted".format(number_backup))

            elif args.s_databases:
                for backup in backups:
                    num_files = 0
                    total_size = 0
                    number_backup = backup["name"].split("/")[3]
                    if (number_backup in phone) or (phone == ""):
                        filter_file: dict = {}
                        for file in wa_backup.backup_files(backup):
                            i = os.path.splitext(file["name"])[1]
                            if "crypt" in i and "mcrypt" not in i:
                                filter_file[file["name"]] = int(file["sizeBytes"])

                        if args.no_parallel:
                            get_multiple_files_with_out_threads(filter_file, is_dry_run=args.dry_run)
                        else:
                            get_multiple_files(backup, filter_file, is_dry_run=args.dry_run)

                        print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                         human_size(total_size)))

                    else:
                        print("[i] Backup {} omitted".format(number_backup))

            elif args.pull:
                file = args.pull
                output = args.output
                print("[+] Backup name: {}".format(os.path.sep.join(file.split("/")[:4])))
                get_file(file, is_dry_run=args.dry_run)
                print("\n[i] {} files downloaded, total size {} Bytes {}".format(num_files, total_size,
                                                                                 human_size(total_size)))
        except Exception as e:
            if "401 Client Error" in str(e):
                print("Unable to access the resource, your OAuth token configured in the settings file may have"
                      " expired.\nRemoving token....\nTry again, you will have to log in again.""")
                cfg_file = r'{}/cfg/settings.cfg'.format(whapa_path).replace("/", os.path.sep)
                config = ConfigObj(cfg_file, interpolation=None)
                config['google-auth']['oauth'] = ""
                config.write()

            else:
                print("[e] Error {}".format(e))
