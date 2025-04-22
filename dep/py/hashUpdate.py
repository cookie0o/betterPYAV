from PyQt5.QtCore import QObject, pyqtSignal
import urllib.request
import zipfile
import time
import os

class HashWorker(QObject):
    finished = pyqtSignal()
    def __init__(self, self_, current_dir):
        super().__init__()
        self.self_ = self_
        self.current_dir = current_dir

    def run(self):
        self.self_.changePage("LoadingPage", "Updating Hashes")
        if self.self_.UpdateHashes_checkBox.isChecked():
            self.UpdateHashes_MalwareBazaar()

        self.self_.changePage("HomePage")
        self.finished.emit()
        return
    

    def UpdateHashes_MalwareBazaar(self):
        MalwareBazaar_hash_path = self.current_dir+f"/dep/hashes/"
        MalwareBazaar_hash_file = self.current_dir+f"/dep/hashes/MalwareBazaar_hashList.txt"

        try:
            # check file edit date if available and if a new one should be updated
            def ShouldUpdate():
                if os.path.exists(MalwareBazaar_hash_file):
                    # Get the last modification time of the file UNIX
                    lastEdited_UNIX = os.path.getmtime(MalwareBazaar_hash_file)
                    
                    # get the current time UNIX
                    current_time = time.time()

                    time_difference = current_time - lastEdited_UNIX

                    # get User defined Update Interval
                    UserDefinedInterval = self.self_.UpdateInterval_timeEdit.time().toString("hh:mm:ss")
                    hours, minutes, seconds = map(int, UserDefinedInterval.split(':'))
                    _UserDefinedInterval = hours * 3600 + minutes * 60 + seconds
                    
                    
                    # Compare the modification time with the target time
                    if time_difference > _UserDefinedInterval:
                        return True
                    else:
                        return False
                else:
                    return True
                
            # check if it should be update if yes update
            if ShouldUpdate():
                # url for the latest md5 hashes
                DownloadLink = "https://bazaar.abuse.ch/export/txt/md5/full/"

                # Download the ZIP file
                urllib.request.urlretrieve(DownloadLink, MalwareBazaar_hash_path+"temp_MalwareBazaar.zip")

                try:
                    # Extract the ZIP file
                    with zipfile.ZipFile(MalwareBazaar_hash_path+"temp_MalwareBazaar.zip", 'r') as zip_ref:
                        zip_ref.extractall(MalwareBazaar_hash_path)
                        zip_ref.close()
                    
                    # Rename the extracted file and delete the old one
                    if os.path.exists(MalwareBazaar_hash_file):
                        os.remove(MalwareBazaar_hash_file)
                    os.rename(MalwareBazaar_hash_path+"full_md5.txt", MalwareBazaar_hash_file)
                finally:
                    # try to delete the temp zip
                    for i in range(10):
                        try:
                            # delete the temp zip if it exists
                            if os.path.exists(MalwareBazaar_hash_path+"temp_MalwareBazaar.zip"):
                                os.remove(MalwareBazaar_hash_path+"temp_MalwareBazaar.zip")
                            return
                        except PermissionError:
                            pass
                        time.sleep(2)
                return
        except Exception as e:
            self.self_.ErrorBox(e, (self.self_.def_data()), "MalwareBazaar hash Update Error")
            return