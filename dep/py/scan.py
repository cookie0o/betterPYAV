from PyQt5.QtCore import QObject, pyqtSignal
import asyncio
import hashlib
import vt

class ScanWorker(QObject):
    finished = pyqtSignal()
    def __init__(self, self_, current_dir, filepath, type):
        super().__init__()
        self.current_dir = current_dir
        self.filepath = filepath
        self.type = type
        self.self_ = self_

    def run(self):
        HashScan_found = None
        VirusTotal_found = None

        try:
            # check if enabled and scan using Method
            if self.self_.Method_HashCheck_checkBox.isChecked():
                HashScan_found, hash = scanning.HashScan(self, self.current_dir, self.filepath)
                # check if scan was successfully
                if HashScan_found==None:self.self_.HashCheck_noInput_checkBox.setChecked(False)
                else: self.self_.HashCheck_noInput_checkBox.setChecked(True)
                
            if self.self_.Method_VirusTotal_checkBox.isChecked():
                VirusTotal_found, hash = scanning.VirusTotalScan(self, self.current_dir, self.filepath)
                # check if scan was successfully
                if VirusTotal_found==None:self.self_.VirusTotalCheck_noInput_checkBox.setChecked(False)
                else: self.self_.VirusTotalCheck_noInput_checkBox.setChecked(True)  
                
            
            # set values in Ui
            self.self_.FilePathDisplay_label.setText(str(self.filepath))
            self.self_.HashDisplay_label.setText(str(hash))

            
            
            # detection
            if HashScan_found != None and HashScan_found != False:
                self.self_.HashCheckDetection_noInput_checkBox.setChecked(True)
                self.self_.HashCheckDetection_noInput_checkBox.setStyleSheet("color: red")
            else:
                self.self_.HashCheckDetection_noInput_checkBox.setChecked(False)
                self.self_.HashCheckDetection_noInput_checkBox.setStyleSheet("")
                
            if VirusTotal_found != None and VirusTotal_found != False:
                self.self_.VirusTotal_harmless_results_label.setText(str(VirusTotal_found["harmless"]))
                self.self_.VirusTotal_malicious_results_label.setText(str(VirusTotal_found["malicious"]))
                self.self_.VirusTotal_suspicious_results_label.setText(str(VirusTotal_found["suspicious"]))
                self.self_.VirusTotal_timeout_results_label.setText(str(VirusTotal_found["timeout"]))
                self.self_.VirusTotal_unsupported_results_label.setText(str(VirusTotal_found["type-unsupported"]))
                self.self_.VirusTotal_undetected_results_label.setText(str(VirusTotal_found["undetected"]))
                self.self_.VirusTotal_failure_results_label.setText(str(VirusTotal_found["failure"]))
            else:
                self.self_.VirusTotal_harmless_results_label.setText("No Results/VirusTotal Disabled.")
                self.self_.VirusTotal_malicious_results_label.setText("")
                self.self_.VirusTotal_suspicious_results_label.setText("")
                self.self_.VirusTotal_timeout_results_label.setText("")
                self.self_.VirusTotal_unsupported_results_label.setText("")
                self.self_.VirusTotal_undetected_results_label.setText("")
                self.self_.VirusTotal_failure_results_label.setText("")
                
            
            # show Ui
            self.self_.changePage("ResultsPage")
            self.finished.emit()
            
        except Exception as e:
            self.self_.ErrorBox(e, (self.self_.def_data()), "Scan Error")
            self.finished.emit()
            # fatal Error go to Home Page
            self.self_.changePage("HomePage")
            return


class scanning():
    def HashScan(self, current_dir, filepath):
        HashScan_found = False
        try:
            self.self_.changePage("LoadingPage", "Hash Scan...")
            # get the md5 hash of the defined file
            # Open the file in binary mode
            with open(filepath, 'rb') as f:
                # Create an MD5 hash object
                md5_hash = hashlib.md5()
                # Read the file in chunks to avoid loading the entire file into memory
                while chunk := f.read(4096):  # Read 4KB chunks
                    md5_hash.update(chunk)
            hash = md5_hash.hexdigest()
            
            # check the hash
            for i in range(1, 2):
                hash_file_path = current_dir+f"/dep/hashes/hashList_{i}.txt"
                if self.self_.scan_lib.check_hash_in_file(hash_file_path.encode(), hash.encode()):
                    HashScan_found = True
                    break
            # return result
            return HashScan_found, hash
        
        except Exception as e:
            self.self_.ErrorBox(e, (self.self_.def_data()), "Hash Scan Error")
            return None, None
        
    def VirusTotalScan(self, current_dir, filepath):
        VirusTotal_found = False
        try:
            self.self_.changePage("LoadingPage", "Virus Total Scan...")
            # fix asyncio not finding a event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # define the VirusTotal client with the api key in the apiKey box
            VTclient = vt.Client(str(self.self_.VirusTotal_ApiKey_lineEdit.text()))
            # get the md5 hash of the defined file
            # Open the file in binary mode
            with open(filepath, 'rb') as f:
                # Create an MD5 hash object
                md5_hash = hashlib.md5()
                # Read the file in chunks to avoid loading the entire file into memory
                while chunk := f.read(4096):  # Read 4KB chunks
                    md5_hash.update(chunk)
            hash = md5_hash.hexdigest()
            
            # check the hash using the Api
            try:
                file = VTclient.get_object("/files/"+str(hash))
                VirusTotal_found = file.last_analysis_stats
            except vt.error.APIError as e:
                # file not found upload it
                if e.args[0] == 'NotFoundError':
                    with open(filepath, "rb") as f:
                        VTclient.scan_file(f, wait_for_completion=True)
                    f.close()
                    file = VTclient.get_object("/files/"+str(hash))
                    VirusTotal_found = file.last_analysis_stats 
            # close VirusTotal client connection
            VTclient.close()
            # return result
            return VirusTotal_found, hash
        
        except Exception as e:
            self.self_.ErrorBox(e, (self.self_.def_data()), "VirusTotal Scan Error")
            return None, None