import re
import pefile
import csv
import mmap
import os
##########################################################
################### readMultiple function retured the count of 'searchString' in the file 'logfile'
def readMultiple(logfile,searchString):
    
    with open(logfile) as search:
        count=0
        for line in search:
            
            #line = line.replace('.', '\n')
            #line = line.replace(',', '\n')
            line = line.rstrip()  # remove '\n' at end of line
            #print "Line", line

            if searchString in line:
                #print(line )
                count+=1
    return count
##########################################################


##########################################################
########### scanFile function retured a file that contain the APIs ,IPs and URLs in the file 'current_file'
def Scanner(PathOfTheDataSet,current_file):

    URL_list =[]
    IP_list =[]
    API_list =[]

    f = str(current_file.read(),'latin-1').split()
    for line in f:
        
        urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',line)
        ips = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
        
        if len(ips) > 0:
            IP_list.append(str(ips)[2:len(str(ips))-2])
            
        if len(urls) > 0:
            URL_list.append(str(urls)[2:len(str(urls))-2])

    pe_data = mmap.mmap(current_file.fileno(), 0, access=mmap.ACCESS_READ)

    pe = pefile.PE(data=pe_data)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for API in entry.imports:
            API_list.append(str(API.name)[2:len(str(API.name))-1])
    pe_data.close()        
    textfile = open("Good.txt", "w")
    
    for element in URL_list:
        textfile.write(str(element).lower() + "\n")
        
    for element in IP_list:
        textfile.write(str(element).lower() + "\n")
        
    for element in API_list:
        textfile.write(str(element).lower() + "\n") 
    textfile.close()

    ############### read features of the original dataset
    fi = open(PathOfTheDataSet, newline='')
    csv_reader = csv.reader(fi)
    featuresOfTheDataSet=next(csv_reader)[1:]
    fi.close()
    
    ret_list=[]

    for f in featuresOfTheDataSet:
        ret_list.append(readMultiple("Good.txt",f))
    
    os.remove("Good.txt")
    return {'features' : ret_list, 'size': len(ret_list)}
##########################################################


# 