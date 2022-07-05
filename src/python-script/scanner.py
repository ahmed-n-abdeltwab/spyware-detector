import re
import pefile
import csv
import mmap
import os
import hashlib
import pandas as pd

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
PathOfTheDataSet = os.path.join(ROOT_PATH, '../datasets/malwares.csv')
##########################################################
################### readMultiple function retured the count of 'searchString' in the file 'logfile'
def readMultiple(logfile, searchString):
    string = logfile.split(' ')
    count = 0
    for line in string:

        # line = line.replace('.', '\n')
        # line = line.replace(',', '\n')
        line = line.rstrip()  # remove '\n' at end of line
        # print "Line", line

        if searchString in line:
            # print(line )
            count += 1
    return count


##########################################################


def calcEntropy(fileData):
    import math

    byteArr = bytearray(fileData)
    fileSize = len(byteArr)

    freqList = [0] * 256
    for b in byteArr:
        freqList[b] += 1

    ent = 0.0
    for f in freqList:
        if f > 0:
            freq = float(f) / fileSize
            ent = ent + freq * math.log(freq, 2)
    ent = -ent

    return format(ent, "0.3f")


##########################################################
########### scanFile function retured a file that contain the APIs ,IPs and URLs in the file 'current_file'
def Scanner(current_file):
    global PathOfTheDataSet
    URL_list = []
    IP_list = []
    API_list = []

    fileData = current_file.read()
    f = str(fileData, "latin-1").split()
    for line in f:

        urls = re.findall("https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", line)
        ips = re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)

        if len(ips) > 0:  # extract IPs
            for ip in ips:
                ip = ip.replace(".", "_")
                IP_list.append(str(ip).lower())

        if len(urls) > 0:  # extract URLs
            for url in urls:
                url = url.replace(".", "_")
                url = url.replace(":", "_")
                url = url.replace("/", "_")
                url = url.replace("-", "_")
                URL_list.append(str(url).lower())

    pe_data = mmap.mmap(current_file.fileno(), 0, access=mmap.ACCESS_READ)

    pe = pefile.PE(data=pe_data)  # extract APIs
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for API in entry.imports:
            API_list.append(str(API.name)[2 : len(str(API.name)) - 1].lower())

    finalListOfTheFile = IP_list + URL_list + API_list

    pe_data.close()

    content = " ".join(finalListOfTheFile)  # convert file to string

    content.replace(",", " ")
    content.replace("[", " ")
    content.replace("]", " ")
    content.replace('"', " ")
    # print(content)
    dataset = pd.read_csv(PathOfTheDataSet)

    features = []
    for key in dataset.keys()[1:-2]:
        features.append(readMultiple(content, key))
    # print(features)

    hash_sha256 = hashlib.sha256(fileData).hexdigest()
    entropy = calcEntropy(fileData)
    features.append(float(entropy))
    return {
        "features": features,
        "details": {
            "API_list": API_list,
            "fileHash": hash_sha256,
            "entropy": entropy,
        },
    }


##########################################################


#
