
import re
import pefile
import os
import hashlib
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

PATH="samples/ALL"
labels =[]
entropy=[]
hashes=[]
AllFeatures =[]
#####################################################
############  this function used to calculate entropy [ the encryption rate] in a program
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
####################################################


########################  scan file to the extract IPs ,URLs and APIs
def scanFile(current_file):
    
    URL_list =[]
    IP_list =[]
    API_list =[]
    with open(current_file, encoding="latin-1") as f:
        for line in f:
        
            urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',line)
            ips = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
        
            if len(ips) > 0:            # extract IPs
                for ip in ips:
                    ip=ip.replace("." ,"_") 
                    IP_list.append(str(ip).lower())
            
            if len(urls) > 0:            # extract URLs
                 for url in urls:
                    url=url.replace("." ,"_")
                    url=url.replace(":" ,"_")
                    url=url.replace('/' ,"_")
                    url=url.replace('-' ,"_")
                    URL_list.append(str(url).lower())

        pe = pefile.PE(current_file)        # extract APIs
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for API in entry.imports:
                API_list.append(str(API.name)[2:len(str(API.name))-1].lower())
            
            
        finalListOfTheFile=IP_list+URL_list+API_list
        
    return finalListOfTheFile # return a list of IPs ,URLs ,APIs
    



for FILE in os.listdir(PATH):       # this loop to get all the sample files
        filename=os.path.join(PATH,FILE)
        finalList=[]
        
        #print(filename)
        
        try:
            finalList=scanFile(filename)
    
        except Exception as e:
            print(e)
        
        with open(filename,"rb") as f:  # open as "rb" to get entropy and hash
            bytes = f.read() # read entire file as bytes
            
            readable_hash = hashlib.sha256(bytes).hexdigest();
            hashes.append(readable_hash)   
            
            ent=calcEntropy(bytes)
            entropy.append(ent)
            
        if "GOOD" in FILE: # if the file name contain a word "GOOD" then is goodware else it is spyware 
            labels.append("1")
        else:
            labels.append("0")
            
        content=' '.join(finalList) # convert file to string 
        

        content.replace(","," ")
        content.replace('[', " " )
        content.replace(']', " " )
        content.replace('"', " " )
        
        AllFeatures.append(content)
        
       
        
    
######################################
vectorizer = CountVectorizer(stop_words='english',max_features= 5000)
######################################

dtm = vectorizer.fit_transform(AllFeatures)
df = pd.DataFrame(dtm.toarray(),index=labels, columns=vectorizer.get_feature_names())

df.index.name = "labels"
df["entropy"] = entropy
df["hash"] = hashes
df.to_csv(r'FinalStaticDataSet.csv')

#######################################








