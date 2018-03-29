#!/usr/bin/python
# bucklegripper_exe.py
# Automation for opendir/malware/crimeware file acquisition
# hadojae

# -*- coding: utf-8 -*-

import urllib2
import subprocess
import re
import os
import sys
import time
import traceback
import requests
import dns.resolver
from pyvirtualdisplay import Display
from selenium import webdriver
import urlnorm
from urlparse import urlparse
from datetime import datetime
import argparse
import signal

#via http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#via http://stackoverflow.com/questions/8464391/what-should-i-do-if-socket-setdefaulttimeout-is-not-working
class Timeout():
    """Timeout class using ALARM signal."""
    class Timeout(Exception):
        pass

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm

    def raise_timeout(self, *args):
        raise Timeout.Timeout()

def do_selenium(url, user_agent, domain, source):

	# start up the virtual display
	display = Display(visible=0, size=(1366, 768))
	display.start()

	# start up browser
	profile = webdriver.FirefoxProfile()
	profile.set_preference("general.useragent.override", user_agent)
	browser = webdriver.Firefox(firefox_profile=profile)
	browser.set_page_load_timeout(15)

    	try:
       	    with Timeout(60):
                browser.get(url)
    	except Timeout.Timeout:
            print bcolors.WARNING + "  [-] " + url + " has timed out. :(" + bcolors.ENDC
            return False
        except Exception:
            e = sys.exc_info()[0]
            print bcolors.WARNING + "  [-] " + url + " has errored: %s" % e + bcolors.ENDC
            return False

        # accept a pop up alert if one comes up
        try:
            alert = browser.switch_to.alert
            print "\n[+] Popup alert observed: %s\n" % alert.text
            if re.search("(?:requesting your username|zeus|call microsoft|call apple|call support)", alert.text, re.IGNORECASE):
                print "\n    [-] This looks like it might be a tech support scam user/password popup, leaving it alone."
                pass
            else:
                alert.accept()
                print "[+] Popup Alert observed, bypassing..."
        except Exception:
            pass

	# check page source to eliminate looking at pages that are parked and stuff we dont care about
	try:
	    pagesource = browser.page_source
	except Exception:
	    return False

	# do the screencap and sort it into known tp, known fp, or unknown
	try:
	    pagetitle = browser.title.lower()
	    shot_name = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + domain + '.png'
            try:
                browser.save_screenshot(shot_name)
		print "  [+] Screencapped %s as %s" % (url, shot_name)
	    except Exception:
		print bcolors.FAIL + "  [-] Unable to screencap " + url + bcolors.ENDC
 		pass
	except Exception:
	    print bcolors.FAIL + "  [-] An error occured, unable to screencap " + url + bcolors.ENDC
	    pass

	# screencaps.close()
	browser.quit()
	display.stop()
	return True

def search_opendir_files(response, partial_url, headers, domain, source):

    file_matches = list(set(re.findall('(?:[a-zA-Z0-9_-]|\%|\.)(?:[a-zA-Z0-9_-]|\%|\.|\s)+\.(?:txt|rar|zip|exe|jar|bin|ico|png|scr|gif|7z|msi|hta)', response)))
    for z in file_matches:
        newfile = partial_url + z
        try:
	    response = make_request(newfile, headers)
	except Exception:
	    pass
        saved_file = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + z
        with open(os.path.basename(saved_file), "wb") as local_file:
            local_file.write(response)
            local_file.close()
            print bcolors.OKGREEN + "  [+] Saved %s as %s" % (newfile, saved_file) + bcolors.ENDC
    return

def search_php_files(response, partial_url):

    php_matches = list(set(re.findall('[a-zA-Z0-9_-]+\.php', response)))
    for f in php_matches:
	print "  [+] Found php file: %s" % partial_url + f
    return

def attempt_download(fileurl, filename, headers, domain, source):

    try:
        response = make_request(fileurl, headers)
        print bcolors.OKGREEN + "  [+] Found file at %s" % fileurl + bcolors.ENDC
        saved_file = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + filename
        with open(os.path.basename(saved_file), "wb") as local_file:
            local_file.write(response)
            local_file.close()
            print bcolors.OKGREEN + "  [+] Saved %s as %s" % (fileurl, saved_file) + bcolors.ENDC
    except Exception:
        pass
    return

def make_request(url, headers):
  
    #print "[+] Requesting %s..." % url 
    try:
        openreq = urllib2.Request(url, None, headers)
        response = urllib2.urlopen(openreq, timeout = 15).read()
    except Exception:
	pass
    return response

def check_domain(parsed_uri):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8']
    
    try:
        domain = '{uri.netloc}'.format(uri=parsed_uri)
    except Exception:
        print bcolors.FAIL + "[-] I can't parse the domain properly here." + bcolors.ENDC
        return False 

    # "make sure domain resolves if not an ip"
    if not re.search("^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$", domain):
        try:
            my_resolver.query(domain)
            return domain
        except Exception:
            print bcolors.FAIL + "[-] This domain did not resolve." + bcolors.ENDC
            return False

def mainloop(full, headers, user_agent, source):

    # "cleanup url - get parts for later"
    full = urlnorm.norm(full.strip())
    nohttp = re.sub(r'^https?:\/\/','', full)
    parsed_uri = urlparse(full)

    print "\n[+] Processing %s" % full

    #make sure domain resulves
    domain = check_domain(parsed_uri)
    if domain == False:
        return False

    # "break apart full into array"
    parts = nohttp.split('/')

    # remove the base in the array
    del parts[0]

    # get number of iterations we need to make to build all the urls
    num_folders = len(parts)

    #if the url ends in any of these, just try to download the exe
    if re.search('\.(?:exe|jar|zip|rar|bin|ico|png|scr|gif|7z|msi)$', full, re.IGNORECASE):
        url_filename = full.split('/')[-1]
        attempt_download(full, url_filename, headers, domain, source)
 
    # "loop and look for things"
    while num_folders >= 1:
        m = re.match(r"^https?://([^/]+\/){%s}" % num_folders , full)
        try:
            partial_url = m.group(0)
        except Exception:
            print bcolors.FAIL + "[-] Looks like regex failed on this possibly malformed URI" + bcolors.ENDC
            break

        # "format up the zip url"
        zipurl = re.sub(r'\/$', '', partial_url) + ".zip"
        r = re.search(r'[^/]+.zip$', zipurl)
        zipname = r.group(0).replace(" ","")

        # if this is not the last part of the url we are accessing
        if num_folders > 1:
            attempt_download(zipurl, zipname, headers, domain, source)

        # "----opendirs"                
        try:
            response = make_request(partial_url, headers)
        except Exception:
            break

        # check page content for evidence of opendir            
        if re.search(r'(?:<title>Index of|Parent Directory)', response) is not None:
            # look for files
            print "[+] Found Opendir at %s" % partial_url
            if re.search(r'\.(txt|rar|zip|exe|jar|bin|ico|png|hta|scr|gif|7z|msi)', response) is not None:
                search_opendir_files(response, partial_url, headers, domain, source)
            # look for php (we can't download these, just screenshot via selenium)
            if re.search(r'\.php', response) is not None:
                php_matches = list(set(re.findall('[a-zA-Z0-9_-]+\.php', response)))
                for f in php_matches:
                    screen_url = partial_url + f
                    selenium_result = do_selenium(screen_url, user_agent, domain, source)

        num_folders -= 1
    return True

def main():

    print "\n.: BUCKLEGRIPPER v0.2 EXE_PIRATE Edition https://github.com/hadojae/DATA :."

    parser = argparse.ArgumentParser(description='Visit a malicious page, screenshot it and pillage it for malware archives')
    parser.add_argument('-u','--url', help='Url to visit',required=False,default=False)
    parser.add_argument('-s','--source', help='Apply a source to where this url came from',required=False,default="bucklegripper")
    parser.add_argument('-r','--readfile', help='Read in a file of URLs one per line',required=False,default=False)
    parser.add_argument('-a','--useragent', help='Custom User-Agent',required=False,default="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")

    args = parser.parse_args()
    user_agent = args.useragent
    full = args.url
    source = args.source
    readfile = args.readfile

    if full == False and readfile == False:
        print bcolors.FAIL + "\n[-] You have to enter either a url with '-u' to analyze or specify a file with urls in it with '-r'\n" + bcolors.ENDC
        sys.exit() 

    # "setup fake ua for urllib2 requests"
    headers = { 'User-Agent' : user_agent }

    if readfile == False:
        mainloop(full, headers, user_agent, source)
        sys.exit()
    else:
        print "\n[+] Beginning processing of " + readfile
        with open(readfile) as f:
            content = f.readlines()
            for line in content:
                #catch bad url
                try:
                    full = urlnorm.norm(line).strip('\n')
                except Exception:
                    print bcolors.FAIL + "[-] " + line + " is a Malformed URI" + bcolors.ENDC
                    continue 
  		mainloop(full, headers, user_agent, source)
        print "\n[+] Finished processing " + readfile + '\n'
        sys.exit() 

if __name__ == '__main__':
  main()
