from MetaDefender.api import MetaDefender_api
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
import os
import vt

class ScanWorker(QThread):
    finished = pyqtSignal()
    def __init__(self, self_, current_dir, input_arg, type):
        super().__init__()
        self.current_dir = current_dir
        self.input_arg = input_arg
        self.type = type
        self.self_ = self_ # MainWindow self

    def run(self):
        # check if it should scan at all (empty Path or None arg passed)
        if self.input_arg == None:
            self.self_.changePage("HomePage")
            self.finished.emit()
            return

        # select scan type
        if self.type == "HashFile":
            ScanTypes.File_Hash_Scan(self, self.self_, self.current_dir, self.input_arg, self.type)

        # show Ui
        self.self_.changePage("ResultsPage")
        self.finished.emit()

class ScanTypes():
    def File_Hash_Scan(self, self_, current_dir, input_arg, type):
        HashScan_found = None
        VirusTotal_found = None
        MetaDefender_found = None
        MLCheck_found = None

        try:
            filepath = None
            hash = None
            # check if the input_arg is a filepath or a hash
            if len(input_arg) in [32, 40, 64] and all(c in "abcdefABCDEF0123456789" for c in input_arg):
                # hash
                hash = input_arg

                # set values in Ui
                self_.MD5_HashDisplay_label.setText("None")
                self_.SHA1_HashDisplay_label.setText("None")
                self_.SHA256_HashDisplay_label.setText("None")
                self_.InputDisplay_label.setText(str(hash))
            elif os.path.exists(input_arg):
                filepath = input_arg
                # get the MD5, SHA1 and SHA-255 hash of the file
                MD5_hash, SHA1_hash, SHA256_hash = self_.get_Hashes(filepath)
                hash = MD5_hash

                # set values in Ui
                self_.MD5_HashDisplay_label.setText(str(MD5_hash))
                self_.SHA1_HashDisplay_label.setText(str(SHA1_hash))
                self_.SHA256_HashDisplay_label.setText(str(SHA256_hash))
                self_.InputDisplay_label.setText(str(filepath))
            else:
                self_.ErrorBox("No valid Filepath or Hash submitted.", (self_.def_data()), "Scan Error")
                # fatal Error go to Home Page
                self_.changePage("HomePage")
                self.finished.emit()
                return


            # type
            # check if enabled and scan using Method
            if self_.Method_HashCheck_checkBox.isChecked():
                # check if the hash is MD5 if not dont check with local MD5 hashes
                if self_.is_MD5_hash(hash):
                    HashScan_found, hash = scanning.HashScan(self, self_, current_dir, hash)
             
            if self_.Method_VirusTotal_checkBox.isChecked():
                VirusTotal_found, hash = scanning.VirusTotalScan(self, self_, current_dir, filepath, hash)

            if self_.Method_MetaDefender_checkBox.isChecked():
                MetaDefender_found, hash = scanning.MetaDefenderScan(self, self_, current_dir, filepath, hash)

            if self_.Method_MLCheck_checkBox.isChecked():
                # only scan when a file is selected (a filepath exists) and its a PE (.exe)
                if filepath != None and filepath.lower().endswith(".exe"):
                    MLCheck_found, percentage = scanning.MLCheck(self, self_, current_dir, filepath)
                else:
                    self_.MLCheckDetection_noInput_checkBox.setText("ML Check")

            
            # detection
            if HashScan_found != None and HashScan_found != False:
                self_.HashCheck_noInput_checkBox.setChecked(True)
                self_.HashCheckDetection_noInput_checkBox.setChecked(True)
                self_.HashCheckDetection_noInput_checkBox.setStyleSheet("color: red")

            else:
                if HashScan_found == False:
                    self_.HashCheck_noInput_checkBox.setChecked(True)
                else:
                    self_.HashCheck_noInput_checkBox.setChecked(False)
                self_.HashCheck_noInput_checkBox.setChecked(True)
                self_.HashCheckDetection_noInput_checkBox.setChecked(False)
                self_.HashCheckDetection_noInput_checkBox.setStyleSheet("color: green")
                

            VirusTotal_name = [
                "harmless", "malicious", "suspicious", "timeout", "unsupported", "undetected", "failure"
            ]
            if VirusTotal_found != None and VirusTotal_found != False:
                self_.VirusTotalCheck_noInput_checkBox.setChecked(True)
                VirusTotal_labels = [
                    (str(VirusTotal_found["harmless"]), "color: green;"),
                    (str(VirusTotal_found["malicious"]), "color: red;"),
                    (str(VirusTotal_found["suspicious"]), "color: orange;"),
                    (str(VirusTotal_found["timeout"]), ""),
                    (str(VirusTotal_found["type-unsupported"]), ""),
                    (str(VirusTotal_found["undetected"]), ""),
                    (str(VirusTotal_found["failure"]), ""),
                ]
                for i, (label, style_sheet) in enumerate(VirusTotal_labels):
                    getattr(self_, f"VirusTotal_{VirusTotal_name[i]}_results_label").setText(label)
                    getattr(self_, f"VirusTotal_{VirusTotal_name[i]}_results_label").setStyleSheet(style_sheet)

            else:
                if VirusTotal_found == False:
                    self_.VirusTotalCheck_noInput_checkBox.setChecked(True)
                else:
                    self_.VirusTotalCheck_noInput_checkBox.setChecked(False)
                VirusTotal_labels = [
                    ("No Results. - VirusTotal Disabled / API down?", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                ]
                for i, (label, style_sheet) in enumerate(VirusTotal_labels):
                    getattr(self_, f"VirusTotal_{VirusTotal_name[i]}_results_label").setText(label)
                    getattr(self_, f"VirusTotal_{VirusTotal_name[i]}_results_label").setStyleSheet(style_sheet)


            MetaDefender_name = [
                "EngineDetections", "Engines", "DetectionPercentage", "UserVotesMalicious", "UserVotesHarmless"
            ]
            if MetaDefender_found != None and MetaDefender_found != False:
                self_.MetaDefenderCheck_noInput_checkBox.setChecked(True)
                MetaDefender_labels = [
                    (str(MetaDefender_found[0]), "color: red;"),
                    (str(MetaDefender_found[1]), ""),
                    (str(MetaDefender_found[2]+"%"), "color: green;"),
                    (str(MetaDefender_found[3]), "color: orange;"),
                    (str(MetaDefender_found[4]), "color: green;"),
                ]
                for i, (label, style_sheet) in enumerate(MetaDefender_labels):
                    getattr(self_, f"MetaDefender_{MetaDefender_name[i]}_results_label").setText(label)
                    getattr(self_, f"MetaDefender_{MetaDefender_name[i]}_results_label").setStyleSheet(style_sheet)
                # dynamic color
                if int(MetaDefender_found[2]) > 50:
                    self_.MetaDefender_DetectionPercentage_results_label.setStyleSheet("color: red")
                    self_.label_31.setStyleSheet("color: red")

            else:
                if MetaDefender_found == False:
                    self_.MetaDefenderCheck_noInput_checkBox.setChecked(True)
                else:
                    self_.MetaDefenderCheck_noInput_checkBox.setChecked(False)
                MetaDefender_labels = [
                    ("No Results. - Meta Defender Disabled / API down?", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                    ("", ""),
                ]
                for i, (label, style_sheet) in enumerate(MetaDefender_labels):
                    getattr(self_, f"MetaDefender_{MetaDefender_name[i]}_results_label").setText(label)
                    getattr(self_, f"MetaDefender_{MetaDefender_name[i]}_results_label").setStyleSheet(style_sheet)


            if MLCheck_found != None and MLCheck_found != False:
                self_.MLCheck_noInput_checkBox.setChecked(True)
                self_.MLCheckDetection_noInput_checkBox.setChecked(True)
                self_.MLCheckDetection_noInput_checkBox.setStyleSheet("color: red")
                self_.MLCheckDetection_noInput_checkBox.setText("ML Check "+percentage+"%")

            else:
                if MLCheck_found == False:
                    self_.MLCheck_noInput_checkBox.setChecked(True)
                    self_.MLCheckDetection_noInput_checkBox.setText("ML Check "+percentage+"%")
                else:
                    self_.MLCheck_noInput_checkBox.setChecked(False)
                self_.MLCheckDetection_noInput_checkBox.setChecked(False)
                self_.MLCheckDetection_noInput_checkBox.setStyleSheet("color: green")    

            return
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "Scan Error")
            # fatal Error go to Home Page
            self_.changePage("HomePage")
            self.finished.emit()
            return



class scanning():
    def HashScan(self, self_, current_dir, hash=None):
        HashScan_found = False
        try:
            self_.changePage("LoadingPage", "Hash Scan")
            
            # check the hash
            hash_file_path = current_dir+f"/dep/hashes/"
            for file in os.listdir(hash_file_path):
                if file.endswith(".txt"):
                    if self_.scan_lib.check_hash_in_file((hash_file_path+file).encode(), hash.encode()):
                        HashScan_found = True
                        break

            # return result
            return HashScan_found, hash
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "Hash Scan Error")
            return None, None
        
    def VirusTotalScan(self, self_, current_dir, filepath=None, hash=None):
        VirusTotal_found = False
        try:
            self_.changePage("LoadingPage", "Virus Total Scan")
            # fix asyncio not finding a event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # define the VirusTotal client with the api key in the apiKey box
            VTclient = vt.Client(str(self_.VirusTotal_ApiKey_lineEdit.text()))
            
            # check the hash using the Api
            try:
                file = VTclient.get_object("/files/"+str(hash))
                VirusTotal_found = file.last_analysis_stats
            except vt.error.APIError as e:
                # file not found upload it (if available)
                if filepath != None:
                    if e.args[0] == 'NotFoundError':
                        with open(filepath, "rb") as f:
                            VTclient.scan_file(f, wait_for_completion=True)
                        f.close()
                        file = VTclient.get_object("/files/"+str(hash))
                        VirusTotal_found = file.last_analysis_stats 

            # close VirusTotal client connection
            VTclient.close()
            # Terminate the asyncio event loop 
            loop.close()
            # return result
            return VirusTotal_found, hash
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "VirusTotal Scan Error")
            return None, None
        
    def MetaDefenderScan(self, self_, current_dir, filepath=None, hash=None):
        MetaDefender_found = False
        try:
            self_.changePage("LoadingPage", "Meta Defender Scan")

            # define Meta Defender api key
            key = str(self_.MetaDefender_ApiKey_lineEdit.text())
            
            # check the hash using the Api 
            response = MetaDefender_api.Hash_Lookup(hash, key)
            if not None in response:
                total_avs = response["scan_results"]["total_avs"]
                total_detections = response["scan_results"]["total_detected_avs"] 
                try:
                    voteUP = response["votes"]["up"],
                    voteDOWN = response["votes"]["down"]
                except:voteUP=0;voteDOWN=0
                MetaDefender_found = (
                    total_detections,
                    total_avs,
                    str(int((total_detections / total_avs) * 100)),
                    voteUP,
                    voteDOWN
                )
            else:
                if response[1] == 400 or response[1] == 404:      
                    # file not found upload it (if available)
                    if filepath != None:
                        response = MetaDefender_api.File_Scanning(filepath, "", 1, 0, True, key)
                        total_avs = response["scan_results"]["total_avs"]
                        total_detections = response["scan_results"]["total_detected_avs"] 
                        try:
                            voteUP = response["votes"]["up"],
                            voteDOWN = response["votes"]["down"]
                        except:voteUP=0;voteDOWN=0
                        MetaDefender_found = (
                            total_detections,
                            total_avs,
                            str(int((total_detections / total_avs) * 100)),
                            voteUP,
                            voteDOWN
                        )
            # return result
            return MetaDefender_found, hash
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "Meta Defender Scan Error")
            return None, None
        
    def MLCheck(self, self_, current_dir, filepath=None):
        MLCheck_found = False
        try:
            self_.changePage("LoadingPage", "ML Check")

            MLCheck, percentage_raw = self_.file_MLCheck(current_dir, filepath)
            if MLCheck == 1:
                MLCheck_found = True
            
            percentage = int(percentage_raw * 100)

            # return result
            return MLCheck_found, str(percentage)
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "ML Check Error")
            return None, None