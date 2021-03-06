'''
Created on Sep 10, 2015

@author: nancy
'''
import re, os
import ast
import json
import gzip
from urlparse import urlparse #used to extract the URL domain
from datetime import datetime as time
from collections import defaultdict, Counter, Mapping, Iterable
from safebrowsinglookup import SafebrowsinglookupClient
global malwareDomains; malwareDomains = [];

def readRawDataFromFiles(directory):  
    ''' reads a file from S3 and returns a list of dictionaries (JSONs) after parsing''' 
    
    print "Read Data From Files... " + str(time.now())
    
    number_of_entries = 0
    
    Files = os.listdir(directory)
    
    for filename in Files: 
        
        with gzip.open(directory+filename, "rb") as data_file:
            
            print ("Reading file " + str(filename) + "...")
            
            for opportunity in data_file:
                
                opportunity = parseLine(opportunity)
                
                opportunitydict = convertToDictionary(opportunity)
                
                if (opportunitydict): 
                    yield encodeDict(opportunitydict)['request']['properties']
                else:
                    continue
            
            number_of_entries += 1
     
    print "Number of opportunities read from file: %s" % str(number_of_entries) 
    
def extractURLs(oppData):
    
    print "Extract URLs... " + str(time.now())
    
    # Build a dictionary, for each exchange, the number of opportunities with each domain
    d = defaultdict(lambda: defaultdict(int))
    
    for opp in oppData:
        
        if ('bidRequest' in opp):
            
            ex = opp['exchange']
            request = opp['bidRequest']
            
            if (ex == '9.sundaysky.googlertb.r'): # Google
                if 'url' in request:
                    url = request['url']
                    domain = getDomainFromRequestedSite(url)
                else: continue
                 
            elif (ex == '3.sundaysky.fh.r'): # BrightRoll
                if 'site' in request and 'domain' in request['site']: 
                    domain = request['site']['domain']
                else: continue
                
            else: # LiveRail, AdapTV
                doamin = find_between( request, '"domain":', ',' )
        
            # update the dictionary (exchange: (url, count))
            if domain not in d[ex]:
                d[ex][domain] = 1 
            else:  
                
                d[ex][domain] += 1
                
        else:
            continue
        
        
    return d

def getDistinctDomains(domains_dict):
    
    print "Get Distinct Domains... " + str(time.now())
    
    distinct_domains = {}
    
    v = domains_dict.values()
    
    for i in v:
        for domain in i.keys():
            if domain not in distinct_domains:
                distinct_domains[domain] = 1  
    
    return distinct_domains
   
def parseLine(line):
    
    ''' strip and remove the first date element from file'''  
    return line.rstrip()[23:] 

def convertToDictionary(str):
    ''' convert (deserialize) a string to dictionary using the built-in json module '''
    try:
        return json.loads(str, encoding='ISO-8859-1')
    except ValueError, e:
        print (">>Warning: ValueError exception - convert (deserialize) a string to dictionary using the built-in json module - failed")
        print e
        print ("Skip this request...")
        return {}
        
        

def encodeDict(data):
    '''  convert a dict's keys & values from unicode to str '''
    if isinstance(data, basestring):
        return data.encode('utf-8')
    elif isinstance(data, Mapping):
        return dict(map(encodeDict, data.iteritems()))
    elif isinstance(data, Iterable):
        return type(data)(map(encodeDict, data))
    else:
        return data
    
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def getDomainFromRequestedSite(url): 
    
    if(url and str(url) != 'nan'):
        
        if(re.compile('\[|\]').search(url) != None):   
            parsed = ''
            return parsed
        else: 
            parsed = urlparse(url)
            
            if (parsed.netloc == ''): # mostly- urls without http
                tmp = 'http://'+ str(url)
                tmpParsed = urlparse(tmp)
                parsed = tmpParsed   
            return parsed.hostname
    else: return '' 

def writeToFile(filePath, text):
        
        print "Write To File... " + str(time.now())
        
        os.path.exists(filePath) and os.remove(filePath)
        target = open(filePath, 'w')
        
        target.write(str(text)) 
        target.close()
        return None  

def retrieveSafeBrowseringResutls(domains):
    
    print("Connecting to SafebrowsinglookupClient...")
    
    #key = 'ABQIAAAAMW5c1P9_7qTcpx8drxoM8xQXc-3IJoTDvJwbFxcncj5ENdNsVw'
    key = 'AIzaSyAWHi27ImtGlIc2APppC4lGlU1N01fiE1c'
    client = SafebrowsinglookupClient(key)
    
    if(client):
        print("Connected successfully to SafebrowsinglookupClient!")
        print("Running lookup ...")
        
        results = client.lookup(*domains.keys());
        
        for url in results:
            print url + ',' + results[url]
            #if (results[url] != 'ok'):
                #print url + ',' + results[url]
            if (results[url] == "malware" or results[url] ==  "phishing" or results[url] ==  "malware,phishing"):
                malwareDomains.append(url)
    
        print("Number of Malware Domains : " + str(len(malwareDomains)) + " Out of: " + str(len(domains))) 
         
    
class Main():
    
    global outputfilecontent
    
    print "STRAT -----> " + str(time.now())
    running_time = time.now()
    
    #inputfile = 'C:\\Users\\nancy\\Desktop\\opportunities_sample_small_test.txt'
    #inputfile = 'C:\\Users\\nancy\\Desktop\\opportunities_sample.txt'
    targetFilePath = 'C:/Users/nancy/Desktop/opportunities_malwarelist_' + str(time.now()) +'.txt'
    
    directory = 'W:/RD/NancyFancy/backup_s3_opportunities/'

    data = extractURLs(readRawDataFromFiles(directory))
    
    retrieveSafeBrowseringResutls(getDistinctDomains(data))
    
    writeToFile(targetFilePath, malwareDomains)
            
    running_time = time.now() - running_time
    
    print("\nFINISH -----> " + str(time.now()) + " Total running time : %s " % str(running_time))