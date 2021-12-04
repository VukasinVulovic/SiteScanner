import scanner
import time
import atexit

URL = "" #url to start
PATH_RULES = ["*"] #rules for paths to follow
COOKIE = {} #set cookie
OVERRIDE = True #delete previous scan db
SAME_DOMAIN = True #scan only this domain 

def main():
    file_extentions = []
    protocols = []
    
    with open("./file_extentions.txt", "r") as f: #list of file extentions
        file_extentions = f.read()
        file_extentions = file_extentions.split("\n")
        f.close()
    
    with open("./protocols.txt", "r") as f: #list of protocols
        protocols = f.read()
        protocols = protocols.split("\n")
        f.close()

    start_time = time.time()
    atexit.register(lambda: print(f"Operation took {time.time() - start_time} seconds;"))
    
    scanner.scanSite(
        start_url=URL,
        path_rules=PATH_RULES,
        cookie=, 
        file_extentions=file_extentions,
        protocols=protocols,
        same_domain=SAME_DOMAIN,
        override_db=OVERRIDE
    )

if __name__ == "__main__":
    main()
