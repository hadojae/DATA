#!/usr/bin/python
# bucklegripper.py
# Automation for phishing kit acquisition
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
	    if re.search("<iframe src=\"http:\/\/mcc\.godaddy\.com\/park\/|https:\/\/www\.godaddy\.com\/domains\/search\.aspx|\/px\.js\?ch=1\"><\/script>|<td bgcolor=\"#788298\">|http:\/\/findbetterresults\.com\/\?dn=|Sponsored Listings displayed above are served automatically by a third party|La Caja Verde RSS Feed|http:\/\/imptestrm\.com\/rg\-erdr\.php\?_dnm=|http:\/\/c\.parkingcrew\.net\/|parking\.jino\.ru\/static\/main\.js|cdn\.dsultra\.com\/js\/registrar\.js|http:\/\/www\.findingresult\.com\/\?dn=|This page is parked free, courtesy of Media Temple|\/js\/standard\.js\?rte=1&tm=2&dn=|This error is generated when there was no web page with the name you specified at the web site|url: \'\/logpstatus\.php|the domain that was pointed to by this Ow\.ly link has been blocked because it was used|href=\"\/hosting_static_403\/style\.css|Ow\.ly link bandito \(404 error\)|Please contact your service provider for more details|The page that you have requested could not be found", pagesource):
	        print bcolors.FAIL + "  [-] Pagesource triggered a known FP string, omitting screenshot." + bcolors.ENDC
		return False
	except Exception:
	    return False

	# do the screencap and sort it into known tp, known fp, or unknown
	try:
	    pagetitle = browser.title.lower()
	    if not re.search("403|404|503|301|500|nicht verf[^\s]+gbar|request rejected|sayfa bulunamad|^error$|nothing found|contact support|nie znaleziono|strona nie zosta.+znaleziona|is for sale\!|not found|forbidden|account suspended|bandwidth limit exceeded|pagina non trovata|no se encontr|o encontrada|has expired|coming soon|host is not delegated|maintenance mode|website is blocked|site unavailable|unknown domain|1freehosting\.com|under construction|sucuri website firewall|pagina suspendata|site maintenance|page non trouv|sitio web suspendido|there has been an error processing your request|this website is temporarily suspended|seite wurde nicht gefunden|hugedomains.com|pagina niet gevonden|^wordpress.+error$|hosting linux e windows|bluehost.com|000webhost\.com|resource limit is reached|your access to this site has been limited|whoops\! there was an error|suspended by ranca\.com|under construction|400 bad request|seite wurde nicht gefunden|sidan kunde inte hittas|site not installed|web site currently not available|domain for sale|coming soon: another fine website hosted by|502 bad gateway|this website is currently unavailable|this account has been suspended|we can't find that page|web filter violation|girls near you|pagina niet gevonden|pagina nu a fost|sua imobiliaria em brumadinho|database error|website is inactive|seite nicht gefunden|^4club$|account disabled|the page cannot be found|we don\'t have that page|forbes|service unavailable|suspended website|gwen stefani shares blake shelton|ukraine\.com\.ua|apache http server test page|temporary error 502|expired registration recovery policy|welcome to nginx|absolutely free dynamic dns|suspended site|create a website |dropbox \- 460|410 gone|a small hello|bad request|sitebuilder|cuenta suspendida|contact admin|domain default page|apache http server test page|microsoft azure app service|site en construction|student from cornell university|shrink your urls and get paid|cheap domain names|domain does not exist|linkbucks\.com|hostmonster|the request could not be satisfied|hospedagem de sites|apache2 ubuntu default page|no se encuentra la|domain seo service registration corp|site no longer available|buy sell rent properties in|parallels h\-sphere|domain profile \- afternic|cloudyfiles\.co|free reliable file hosting|canadian web hosting|web hosting canada|film streaming|byethost free hosting|unlimited free subdomain hosting|something lost|error page|dns resolution error|appserv open project|powered by discuz!|free web hosting|high cpu notice|powered by phpwind", pagetitle):				
	        shot_name = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + domain + '.png'
         	try:
		    browser.save_screenshot(shot_name)
		    print "  [+] Screencapped %s as %s" % (url, shot_name)
		except Exception:
		    print bcolors.FAIL + "  [-] Unable to screencap " + url + bcolors.ENDC
 		    pass

		    # putting this section on hold, as the fuzzy hashing is giving me FP
  		    # gs_shot = "gs_" + shot_name
		    # subprocess.call(['convert', shot_name, '-colorspace', 'Gray', gs_shot])
		    # resized_shot = "rs_" + gs_shot
		    # subprocess.call(['convert', gs_shot, '-resize', '250x250!', resized_shot])
		    # subprocess.call(['rm', gs_shot])
		    # hash_response_fp=subprocess.check_output(['ssdeep', '-bm', 'gs_phish_fps.hashes', resized_shot])
		    # hash_response_tp=subprocess.check_output(['ssdeep', '-bm', 'gs_phish_positives.hashes', resized_shot])
		    # if 'matches' in hash_response_fp:
		    #	shot_result="False Positive"
		    #	subprocess.call(['mv', shot_name, 'fp_screencaps'])
		    #	subprocess.call(['rm', resized_shot])
		    # elif 'matches' in hash_response_tp:
		    #	shot_result="True Positive"
		    #	subprocess.call(['mv', shot_name, 'tp_screencaps'])
		    #	subprocess.call(['rm', resized_shot])
		    # else:
		    #	shot_result="Unknown"
   	    	    #	subprocess.call(['mv', shot_name, 'unk_screencaps'])
		    #	subprocess.call(['rm', resized_shot])

            else:
		print bcolors.FAIL + "  [-] Pagetitle triggered a known FP string, omitting screenshot." + bcolors.ENDC
		pass

	except Exception:
	    print bcolors.FAIL + "  [-] An error occured, unable to screencap " + url + bcolors.ENDC
	    pass

	# screencaps.close()
	browser.quit()
	display.stop()
	return True

def search_opendir_files(response, partial_url, headers, domain, source):

    file_matches = list(set(re.findall('(?:[a-zA-Z0-9_-]|\%|\.)(?:[a-zA-Z0-9_-]|\%|\.|\s)+\.(?:rar|zip|txt)', response)))
    for z in file_matches:
        newfile = partial_url + z
        try:
	    response = make_request(newfile, headers)
	except Exception:
	    pass
        saved_file = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + domain + '-' + z
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

def attempt_zip_download(zipurl, zipname, headers, domain, source):

    try:
        response = make_request(zipurl, headers)
        if response[:2] == "PK":
            print bcolors.OKGREEN + "  [+] Found Zip file at %s" % zipurl + bcolors.ENDC
            saved_zip = time.strftime("%Y%m%d-%H%M%S") + '-' + source + '-' + domain + '-' + zipname
            with open(os.path.basename(saved_zip), "wb") as local_file:
                local_file.write(response)
                local_file.close()
   		print bcolors.OKGREEN + "  [+] Saved %s as %s" % (zipurl, saved_zip) + bcolors.ENDC
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

    #do screenshot
    selenium_result = do_selenium(full, user_agent, domain, source)
    if selenium_result == False:
     return False

    # "break apart full into array"
    parts = nohttp.split('/')

    # remove the base in the array
    del parts[0]

    # get number of iterations we need to make to build all the urls
    num_folders = len(parts)

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
            attempt_zip_download(zipurl, zipname, headers, domain, source)

        # "----opendirs"                
        try:
            response = make_request(partial_url, headers)
        except Exception:
            break

        # check page content for evidence of opendir            
        if re.search(r'(?:<title>Index of|Parent Directory)', response) is not None:
            # look for files
            print "[+] Found Opendir at %s" % partial_url
            if re.search(r'\.(txt|rar|zip)', response) is not None:
                search_opendir_files(response, partial_url, headers, domain, source)
            # look for php (we can't download these, just log)
            if re.search(r'\.php', response) is not None:
                search_php_files(response, partial_url)

        num_folders -= 1
    return True

def main():

    print "\n.: BUCKLEGRIPPER v0.1 https://github.com/hadojae/DATA :."

    parser = argparse.ArgumentParser(description='Visit a suspected phishing page, screenshot it and pillage it for phishing archives')
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
