#!/usr/bin/python3
# import socials
from termcolor import colored
import numpy as np
import requests
import re
import time
import sqlite3
from urllib.parse import urlparse

#DB
    #links:
        #id         - auto id
        #url        - url
        #origin     - url where url was found 
        #scan_date  - date when the url was found epoch
        #info       - info about request 

    #files:
        #id         - auto id
        #url        - file url
        #origin     - url where url was found 
        #scan_date  - date when the url was found epoch

# def checkUrl(url, path_rule="*"): #check if path matches check
#     if path_rule == "*": #all is allowed
#         return True

#     rule_end = path_rule[-1] # if "/" at end

#     path = urlparse(url).path
#     print(path)
#     path = path.split("/")
#     path = list(filter(lambda p: len(p) > 0, path)) #remove empty elements
    
#     path_rule = path_rule.split("/")
#     path_rule = list(filter(lambda p: len(p) > 0, path_rule)) #remove empty elements

#     if path_rule == path: #if path is exact
#         return True

#     i = 0

#     if len(path) >= len(path_rule): #if original path is longer
#         for p in path:
#             i += 1

#             if i == len(path_rule)-1: #end of check
#                 if rule_end == "*": #if rule ends with "*"
#                     break

#             if path_rule[i-1] == "*": #all is allowed
#                 continue

#             if p != path_rule[i-1]: #if part of path doesn't match
#                 return False
#     else:
#         for p in path_rule:
#             i += 1

#             if i == len(path)-1: #end of check
#                 return rule_end == "*" #if ends with "*"

#             if path_rule[i-1] == "*": #all is allowed
#                 continue

#             if p != path_rule[i-1]: #if part of path doesn't match
#                 return False

#     return True

def checkUrl(url, path_rule="*"): #check if path matches check
    if path_rule == "*": #if rule is all, allow
        return True

    path = urlparse(url).path #get path from url
    rule_cap = path_rule[-1] == "/"; #if last character of rule is "/"

    path_split = path.split("/") #split by path divider
    rule_split = path_rule.split("/") #split by path divider


    path_split = list(filter(lambda p: len(p) > 0, path_split)) #remove empty elements
    rule_split = list(filter(lambda p: len(p) > 0, rule_split)) #remove empty elements

    if len(rule_split) > len(path_split): #if more rules than path parts
        return False

    if (len(path_split) > len(rule_split)) and rule_cap: #if more parts than rules and last last char of rules is not "*"
        return False

    i = 0

    for p in path_split: #for every path part
        if i >= len(rule_split): #if i is larger than length of rules
            return rule_split[-1] == "*" #return True if last char of rules is "*"
        
        r = rule_split[i] #rules at current index
        
        if r != "*" and (p != r): #if rule is not "*" and part of path does not match with rule
            return False

        i += 1 #stupid python increment

    return True #no return False from for loope, so return True


def showWarning(text): #show message with color yellow
    print(colored(f"Warning: {text}", "yellow"))

def showInfo(text): #show message with color green
    print(colored(f"Info: {text}", "green"))

def scanSite(start_url, path_rules=["*"], cookie={}, db_file="scan.db", file_extentions=[], protocols=["http://", "https://"], same_domain=True, override_db=True): #scan a site for links
    start_domain = urlparse(start_url).hostname

    global file_num
    global link_num

    file_num = 0
    link_num = 0
    start_time = time.time()

    con = sqlite3.connect(db_file) #connect to database
    db = con.cursor()

    #create links table
    db.execute('''
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY,
            url,
            origin TEXT NOT NULL,
            scan_date TEXT,
            info TEXT
        )
    ''')

    #create files table if doesn't exist
    db.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            origin TEXT NOT NULL,
            scan_date TEXT
        )
    ''')

    if override_db: #delete all data
        back_name = f"{db_file}-backup.db";

        with sqlite3.connect(back_name) as back: #backup just in case
            con.backup(back)

        showWarning(f"Override mode turned on, backed up database to \"{back_name}\";")
        back.close()

        db.execute("DELETE FROM links")
        db.execute("DELETE FROM files")
        con.commit()

    def urlVisited(url):
        db.execute(f"SELECT * FROM links WHERE origin='{url}'")
        return db.fetchone() != None

    def getUrls(url):
        links = []
        global file_num
        global link_num

        for rule in path_rules:
            if not checkUrl(url, rule):
                showWarning(f"Url \"{url}\" not passed check \"{path_rules}\", skipped;")
                return links

        if "://" not in url: #url has no protocol
            showWarning(f"Url \"{url}\" has no protocol, skipped;")
            return links

        if urlVisited(url): #url already scanned
            showWarning(f"Already scanned url \"{url}\", skipped;")
            return links

        showInfo(f"Scanning \"{url}\";")

        if same_domain and urlparse(url).hostname != start_domain:
            showWarning(f"Url, \"{url}\" not on domain \"{start_domain}\", skipped;")
            return links

        if ":" not in url: #no protocol
            return links

        if url[:url.index(":")] not in protocols: #check if allowed protocol
            return links
    
        req = requests.get(url, cookies=cookie) #get url
        base_url = url[:(url[8:].index("/"))+8] # without path

        if req.status_code != 200:
            showWarning(f"\"{url}\", returned code {req.status_code}, skipped;")
            db.execute(f'''
                INSERT INTO links (url, origin, scan_date, info)
                VALUES('{url.replace("'", "%27")}', '{url.replace("'", "%27")}', '{time.time()}', 'status code: {req.status_code}');
            ''')
            return links

        for u in np.concatenate((re.findall('src="[\s\S]*?"', req.text), re.findall('href="[\s\S]*?"', req.text))):
            u = u[(u.index("=\"")+2):-1]


            if u in ["#", url]: #check url blacklist
                continue
            
            if len(u) > 0:
                if u[0] == "/": 
                    base_url = base_url if base_url[-1] != "/" else base_url[:-1] #remove if last char "/"
                    u = (base_url + u)

                    a = u[:8]
                    b = u[8:].replace("//", "/")
                    u = a + b


            # if ":" not in u: # if url does not start with protocol
            #     if u[0] == "/": # if url starts with "/"
            #         base_url = base_url if base_url[-1] != "/" else base_url[:-1] #remove if last char "/"
            #         u = base_url + "/" + (u if u[0] != "/" else u[1:]) #remove if first char "/" and concat

            #         print(u)

                # if url.split('.')[-1] in np.concatenate((file_extentions, [ "html", "php" ])): # if page is a file
                #     u = url[:url.rfind("/")] + "/" + u
                # else:
                #     u = url + "/" + u


            table = "files" if u.split('.')[-1] in file_extentions else "links" #see if result is a file

            if table == "links": #add to links array
                links.append(u)
                link_num += 1
            else:
                file_num += 1
            #add url to database
            
            db.execute(f'''
                INSERT INTO {table} (url, origin, scan_date)
                VALUES('{u.replace("'", "%27")}', '{url.replace("'", "%27")}', {time.time()});
            ''')

            con.commit() # write to database
        
        for link in links: #scan every found link
            getUrls(link) #scan
            # time.sleep(0.5) #wait a moment

        return links

    getUrls(start_url) #scan the start url
    print(colored(f"\033[1mSuccessfully scanned \"{start_url}\" with path check \"{path_rules}\", scanned {link_num} links and found {file_num} files;", "magenta"))
    print(f"operation took: {time.time() - start_time}seconds;")

    

    return 0