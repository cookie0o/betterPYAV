from MetaDefender.api import MetaDefender_api
from PyQt5.QtCore import QObject, pyqtSignal
import asyncio
import os
import vt

class ScanWorker(QObject):
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
        self.finished.emit()

class ScanTypes():
    def File_Hash_Scan(self, self_, current_dir, input_arg, type):
        HashScan_found = None
        VirusTotal_found = None
        MetaDefender_found = None

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
                return


            # type
            # check if enabled and scan using Method
            if self_.Method_HashCheck_checkBox.isChecked():
                # check if the hash is MD5 if not dont check with local MD5 hashes
                if self_.is_MD5_hash(hash):
                    HashScan_found, hash = scanning.HashScan(self, self_, current_dir, hash)
                # check if scan was successful
                if HashScan_found==None:self_.HashCheck_noInput_checkBox.setChecked(False)
                else: self_.HashCheck_noInput_checkBox.setChecked(True)
                
            if self_.Method_VirusTotal_checkBox.isChecked():
                VirusTotal_found, hash = scanning.VirusTotalScan(self, self_, current_dir, filepath, hash)
                # check if scan was successful
                if VirusTotal_found==None:self_.VirusTotalCheck_noInput_checkBox.setChecked(False)
                else: self_.VirusTotalCheck_noInput_checkBox.setChecked(True)  

            if self_.Method_MetaDefender_checkBox.isChecked():
                MetaDefender_found, hash = scanning.MetaDefenderScan(self, self_, current_dir, filepath, hash)
                # check if scan was successful
                if MetaDefender_found==None:self_.MetaDefenderCheck_noInput_checkBox.setChecked(False)
                else: self_.MetaDefenderCheck_noInput_checkBox.setChecked(True)  

            
            # detection
            if HashScan_found != None and HashScan_found != False:
                self_.HashCheckDetection_noInput_checkBox.setChecked(True)
                self_.HashCheckDetection_noInput_checkBox.setStyleSheet("color: red")
            else:
                self_.HashCheckDetection_noInput_checkBox.setChecked(False)
                self_.HashCheckDetection_noInput_checkBox.setStyleSheet("")
                
            if VirusTotal_found != None and VirusTotal_found != False:
                self_.VirusTotal_harmless_results_label.setText(str(VirusTotal_found["harmless"]))
                self_.VirusTotal_harmless_results_label.setStyleSheet("color: green;")
                self_.VirusTotal_malicious_results_label.setText(str(VirusTotal_found["malicious"]))
                self_.VirusTotal_suspicious_results_label.setText(str(VirusTotal_found["suspicious"]))
                self_.VirusTotal_timeout_results_label.setText(str(VirusTotal_found["timeout"]))
                self_.VirusTotal_unsupported_results_label.setText(str(VirusTotal_found["type-unsupported"]))
                self_.VirusTotal_undetected_results_label.setText(str(VirusTotal_found["undetected"]))
                self_.VirusTotal_failure_results_label.setText(str(VirusTotal_found["failure"]))
            else:
                self_.VirusTotal_harmless_results_label.setText("No Results. - VirusTotal Disabled / API down?")
                self_.VirusTotal_harmless_results_label.setStyleSheet("")
                self_.VirusTotal_malicious_results_label.setText("")
                self_.VirusTotal_suspicious_results_label.setText("")
                self_.VirusTotal_timeout_results_label.setText("")
                self_.VirusTotal_unsupported_results_label.setText("")
                self_.VirusTotal_undetected_results_label.setText("")
                self_.VirusTotal_failure_results_label.setText("")

            if MetaDefender_found != None and MetaDefender_found != False:
                self_.MetaDefender_EngineDetections_results_label.setText(str(MetaDefender_found[0]))
                self_.MetaDefender_EngineDetections_results_label.setStyleSheet("color: red;")
                self_.MetaDefender_Engines_results_label.setText(str(MetaDefender_found[1]))
                self_.MetaDefender_DetectionPercentage_results_label.setText(str(MetaDefender_found[2]+"%"))
                self_.MetaDefender_UserVotesMalicious_results_label.setText(str(MetaDefender_found[3]))
                self_.MetaDefender_UserVotesHarmless_results_label.setText(str(MetaDefender_found[4]))
                if int(MetaDefender_found[2]) > 50:
                    self_.MetaDefender_DetectionPercentage_results_label.setStyleSheet("color: red")
                    self_.label_31.setStyleSheet("color: red")
                else:
                    self_.HashCheckDetection_noInput_checkBox.setStyleSheet("color: green")
                    self_.label_31.setStyleSheet("color: green")
            else:
                self_.MetaDefender_EngineDetections_results_label.setText("No Results. - Meta Defender Disabled / API down?")
                self_.MetaDefender_EngineDetections_results_label.setStyleSheet("")
                self_.MetaDefender_Engines_results_label.setText("")
                self_.MetaDefender_DetectionPercentage_results_label.setText("")
                self_.MetaDefender_UserVotesMalicious_results_label.setText("")
                self_.MetaDefender_UserVotesHarmless_results_label.setText("")
            return
            
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "Scan Error")
            # fatal Error go to Home Page
            self_.changePage("HomePage")
            return



class scanning():
    def HashScan(self, self_, current_dir, hash=None):
        HashScan_found = False
        try:
            self_.changePage("LoadingPage", "Hash Scan.")
            
            # check the hash
            for i in range(1, 2):
                hash_file_path = current_dir+f"/dep/hashes/hashList_{i}.txt"
                if self_.scan_lib.check_hash_in_file(hash_file_path.encode(), hash.encode()):
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
                MetaDefender_found = (
                    total_detections,
                    total_avs,
                    str(int((total_detections / total_avs) * 100)),
                    response["votes"]["up"],
                    response["votes"]["down"]
                )
            else:
                if response[1] == 400 or response[1] == 404:      
                    # file not found upload it (if available)
                    if filepath != None:
                        response = MetaDefender_api.File_Scanning(filepath, "", 1, 0, True, key)
                        total_avs = response["scan_results"]["total_avs"]
                        total_detections = response["scan_results"]["total_detected_avs"] 
                        MetaDefender_found = (
                            total_detections,
                            total_avs,
                            str(int((total_detections / total_avs) * 100)),
                            response["votes"]["up"],
                            response["votes"]["down"]
                        )
            # return result
            return MetaDefender_found, hash
        except Exception as e:
            self_.ErrorBox(e, (self_.def_data()), "Meta Defender Scan Error")
            return None, None