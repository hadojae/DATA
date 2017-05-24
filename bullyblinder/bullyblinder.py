#!/usr/bin/python
#https://github.com/hadojae/DATA/
#https://www.youtube.com/watch?v=McM6q4EgJNY

################ IMPORTS ################
import sys
import subprocess
import time
import os
import re
import base64
import random
import argparse
import mechanize
import urllib2
from bs4 import BeautifulSoup
import urlnorm
import cookielib
import hashlib
import urlparse
from faker import Faker
from selenium import webdriver
from pyvirtualdisplay import Display
import aes

################ START FUNCTIONS ################
def fix_spaces(url_with_spaces):
    fixed_url = re.sub(' ', '%20', url_with_spaces)
    return fixed_url

def request_page(phish_url):
    print "\n[+] Processing %s" % phish_url
    try:
        response = req_mechanize(phish_url)
        if response:
            return response
    except Exception:
        print "[-] Couldnt load %s with mechanize, trying with selenium..." % phish_url
        try:
            response = req_selenium(phish_url)
            if response:
                return response
            else:
                return False
        except Exception:
            return False

def req_mechanize(phish_url):
    try:
        if len(url_array) > 1:
            br.addheaders = [('Referer', referer)]
        response_req_mech = br.open(phish_url, timeout=req_timeout)
        return response_req_mech
    except Exception:
        return False

def req_selenium(phish_url):
    if not display.is_alive():
        display.start()
    browser = webdriver.Firefox() #this probably needs to use the chrome UA or whatever
    try:
        browser.get(phish_url) #timeout?
    except Exception:
        browser.quit()
        teardown_display()
        return False
    #if there is an alert, whatever accept it
    #probably need a check here to see if there is a popup, put this in another function
    try:
        browser.switch_to_alert().accept()
    except Exception:
        pass
    sel_page = browser.page_source
    tmp_file = "/tmp/tmp.html"
    with open (tmp_file, "wb") as temp_f:
        temp_f.write(sel_page.encode("UTF-8"))
        temp_f.close()
    browser.quit()
    response = br.open('file://' + tmp_file) 
    global using_selenium
    using_selenium=True
    return response

def redir_opendir(page, current_url):
    soup = BeautifulSoup(page, "lxml")
    if current_url[-1:] != "/":
        current_url = current_url + "/"
    for link in soup.findAll("a"):
        if link is not None:
            link = str(link.get("href"))
            if re.search("(?:login|update|archive|apple|paypal|account|e\-?mail|^ren\/$|^op\/$|^\*?id\/$|^ap\/$|sign\-?in)", link, re.IGNORECASE):
                response = br.open(current_url+link)
                return response
            else:
                continue
    return False

def redir_popupwnd(page, current_url):
    try:
        visit = re.search("javascript:popupwnd\('([^']+)','", page, re.IGNORECASE)
    except Exception:
        print "[-] Popupwnd is in the page, but it looks like the regex failed - this is probably a bug"
        return False
    if not re.search('http:\/\/.+\/.+\..+$', current_url, re.IGNORECASE):
        if not re.search('\/$', current_url):
            base_url = current_url
            base_url += '/'
        else:
            base_url = current_url
    else:
        base_url = re.sub('\/[^/]+$', '', current_url)
        current_url = base_url
        current_url += '/'
    popupwnd_url = current_url + visit.group(1)
    try:
        response = request_page(popupwnd_url)
        return response
    except Exception:
        print "This site has popupwnd, but i couldn't figure out where to go... ;_;" 
        return False

def redir_meta_http_refresh(page, current_url):
        try:
            refresh_string = re.search("refresh[^>]*https?:\/\/[^'\"]+", page)
            refresh_url = re.sub("refresh.+http", "http", refresh_string.group(0).lower())
        except Exception:
            print "[-] Looks like there was an error with the regex - this could be a bug"
            return False
        check_legit_site(refresh_url)
        response = request_page(refresh_url)
        return response

def redir_ameli(page, current_url):
    if re.search('<meta http-equiv=["\']refresh', page, re.IGNORECASE):
        redirect_re = re.compile('<meta[^>]*?url=(.*?)["\']', re.IGNORECASE)
        try:
            match = redirect_re.search(page)
            ameli_refresh_url = urlparse.urljoin(current_url, match.groups()[0].strip())
        except Exception:
            print "[-] Looks like there was an error with the regex - this could be a bug"
            return False
        check_legit_site(ameli_refresh_url)
        response = request_page(ameli_refresh_url)
        return response

def redir_jstimeout(page, current_url):
    try:
        visit = re.search("setTimeout\(\"location\.href\s*=\s*\'([^']+)\'", page, re.IGNORECASE)
    except Exception:
        print "[-] Looks like there was an error with the regex - this could be a bug"
        return False
    if not re.search('https?:\/\/.+\/.+\..+$', current_url, re.IGNORECASE):
	if not re.search('\/$', current_url):
	    base_url = current_url
            base_url += '/'
        else:
            base_url = current_url
	    
    elif re.search('^https?:\/\/', visit.group(1), re.IGNORECASE):
        js_timeout_redir_url = visit.group(1)
        try:
            response = request_page(js_timeout_redir_url)
            return response
        except Exception:
            print "[-] This site has a JS setTimeout redirector, but i couldn't figure out where to go... ;_;"
            return False
    else:
        base_url = re.sub('\/[^/]+$', '', current_url)
        current_url = base_url
        current_url += '/'
    js_timeout_redir_url = current_url + visit.group(1)
    check_legit_site(js_timeout_redir_url)
    try:
        response = request_page(js_timeout_redir_url)
        return response
    except Exception:
    	print "[-] This site has a JS setTimeout redirector, but i couldn't figure out where to go... ;_;"
        return False

def redir_jstoplocation(page, current_url):
    try:
        visit = re.search("var\s*page\s*=\s*[\"\']([^\"\']+)[\"\'];\s*top\.location\s*=\s*page", page, re.IGNORECASE)
    except Exception:
        print "[-] Looks like there was an error with the regex - this could be a bug"
        return False
    if not re.search('https?:\/\/.+\/.+\..+$', current_url):
        if not re.search('\/$', current_url):
            base_url = current_url
            base_url += '/'
        else:
            base_url = current_url
    else:
        base_url = re.sub('\/[^/]+$', '', current_url)
        current_url = base_url
        current_url += '/'
    js_top_redir_url = current_url + visit.group(1)
    check_legit_site(js_top_redir_url)
    try:
        response = request_page(js_top_redir_url)
        return response
    except Exception:
        print "[-] This site has a JS top.location redirector, but i couldn't figure out where to go... ;_;"
        return False

def redir_jswindowlocation(page, current_url):
    soup = BeautifulSoup(page, "lxml")
    try:
        js = soup.find('script').text
        front = js.split('"', 1)[-1]
        back = front.split('"', 1)[0] 
        link = str(back)
    except Exception:
        print "[-] Looks like there was an error with parsing the link out of js soup - this is probably a bug"
        return False
    if link.startswith("http"):
        check_legit_site(link)
        response = request_page(link)
        return response
    elif link.startswith("../"):
        current_url = re.sub("\/[^/]+\/(?:[^/]+)?$", "", current_url)
        link = link.strip("../")
        jsredir_url = current_url + '/' + link
        jsredir_url = fix_spaces(jsredir_url)
        check_legit_site(jsredir_url)
        try:
            response = request_page(jsredir_url)
            return response
        except Exception:
            cj.clear()
            response = request_page(jsredir_url)
            return response
    else:
        if re.search("[^/]$",current_url):
            new_url = re.sub("\/[^/]+$","/",current_url)
        else:
            new_url = current_url + link
        try:
            response = request_page(new_url)
            return response
        except Exception:
            return False

def obfuscation_unescape(page):
    soup = BeautifulSoup(page, "lxml")
    for scr in soup(["script"]):
        if re.search('unescape', str(scr), re.IGNORECASE):
            encoded = re.search("(?:%[0-9A-F][0-9A-F])+", str(scr), re.IGNORECASE)
            decoded_content = urllib2.unquote(encoded.group(0))
            scr.replace_with(decoded_content)
    decoded_page = soup.decode(formatter=None)   
    tmp_file = "/tmp/tmp.html"
    with open (tmp_file, "wb") as temp_f:
        temp_f.write(decoded_page)
        temp_f.close()
    try:
        response = br.open('file://' + tmp_file)
        global using_selenium
        using_selenium = True
        return response
    except Exception:
        return False

def obfuscation_b64dataframe(page):
    try:
        b64_uri=str(re.findall('[a-zA-Z0-9+/=]{50,}', page))
    except Exception:
        print "[-] Found a base64 frame source refresh, but i wasnt able to find base64 in there..."
        return False
    unencoded=base64.b64decode(b64_uri)
    try:
        found_link=re.findall('https?:\/\/[^"]+', unencoded, re.IGNORECASE)
        found_url=''.join(found_link)
    except Exception:
        print "[-] Wasnt able to find a url in the decoded base64, not sure what else to try here."
        return False
    try:
        response = br.open(found_url)
        return response
    except Exception:
        return False

def obfuscation_b64data(page, current_url):
    try:
        b64_content=str(re.findall('[a-zA-Z0-9+/=]{50,}', page))
        unencoded=base64.b64decode(b64_content)
        tmp_file = "/tmp/tmp.html"
	with open (tmp_file, "wb") as temp_f:
            temp_f.write(unencoded.encode("UTF-8"))
            temp_f.close()
        response = br.open('file://' + tmp_file)
        global using_selenium
        using_selenium=True
        return response
    except Exception:
        print "[-] Didnt work, going to try with selenium instead..."
        try:
            response = req_selenium(current_url)
            return response
        except Exception:
            return False   

def redir_paypal_landing(page, current_url):
    soup = BeautifulSoup(page, "lxml")
    for link in soup.findAll("a"):
        link = str(link.get("href"))
        if re.search("signin", link, re.IGNORECASE):
            response = br.open(link)
            return response
    return False

def obfuscation_multimail(page, current_url):
    soup = BeautifulSoup(page, "lxml")
    if not re.search('http:\/\/.+\/.+\..+$', current_url, re.IGNORECASE):
        if not re.search('\/$', current_url):
            base_url = current_url
            base_url += '/'
        else:
            base_url = current_url
    else:
        base_url = current_url
    for link in soup.findAll("a"):
        link = str(link.get("href"))
        if link is None:
            continue
        if not re.search("^(?:..\/)*(?:al|out(?:look)?|oth(?:r|er)|365|(?:begin_file\/)?google|webmail|gmail|yah|liamg|oohay|kooltuo|office)", link, re.IGNORECASE):
            continue
        if ".php" in link or ".htm" in link:
            if link.startswith("http"):
                email_url = link
                try:
                    response = br.open(email_url)
                    return response
                except Exception:
                    return False
            elif link.startswith("../"):
                current_url = re.sub("\/[^/]+\/(?:[^/]+)?$", "", current_url)
                link = link.strip("../")
                new_url = current_url + '/' + link
		try:
                    multi_phish = 1
                    response = br.open(new_url)
                    return response
                except Exception:
                    return False
            else:
                if re.search("[^/]$",current_url):
                    email_url = re.sub("\/[^/]+$","/",current_url)
                    email_url = email_url + link
                else:
                    email_url = current_url + link
                try:
                    response = br.open(email_url)
                    return response
                except Exception:
                    return False
        else:
            return False

def redir_exampledomain(current_url):
    try:
        curl_page=subprocess.check_output(['curl', '-q', current_url])
    except Exception:
        return False
    tmp_file = "/tmp/tmp.html"
    with open (tmp_file, "wb") as temp_f:
        temp_f.write(curl_page.encode("UTF-8"))
        temp_f.close()
    try:
        response = br.open('file://' + tmp_file)
        global using_selenium
        using_selenium=True
        return response
    except Exception:
        return False

def redir_bitly(page):
    soup = BeautifulSoup(page, "lxml")
    spamURLdiv = soup.findAll('div', attrs={'class' : 'spamURLBox'})
    for div in spamURLdiv:
        bitly_inner_link = div.find('a')['href']
        if re.search(' ', bitly_inner_link):
            bitly_inner_link = re.sub(' ', '%20', bitly_inner_link)
        try:
            response = br.open(bitly_inner_link)
            initial_url = bitly_inner_link
            return response
        except Exception:
            try:
                cj.clear()
                response = br.open(bitly_link)
                initial_url = bitly_inner_link
                return response
            except Exception:
                return False

def redir_twitter(page):
    soup = BeautifulSoup(page, "lxml")
    spamURLdiv = soup.findAll('p', attrs={'class' : 'WarningMsg'})
    for div in spamURLdiv:
        twit_inner_link = div.find('a')['href']
        if not 'twitter' in twit_inner_link:
            try:
                response = br.open(twit_inner_link)
                initial_url = twit_inner_link
                return response
            except Exception:
                return False
            
def redir_iframe_basic(page, current_url):
    soup = BeautifulSoup(page, "lxml")
    try:
        link_iframe = soup.iframe.attrs['src']
    except Exception:
        return False
    if link_iframe.startswith('http'):
        try:
            response = br.open(link_iframe)
            return response
        except Exception:
            return False
    else:
        try:
            response = br.open(current_url + link_iframe)
            return response
        except Exception:
            return False

def redir_cloudflare():
    try:
        br.form = list(br.forms())[0]
        response = br.submit()
        return response
    except Exception:
        return False

def decode_aes(page):  
    matches = re.findall("var\s*[^\s=]+\s*=\s*(?:\(\s*)?['\"][^'\"]+", page)
    key = re.sub("^[^'\"]+['\"]","", matches[0])
    ciphertext = re.sub("^[^'\"]+['\"]","", matches[1])
    decoded = aes.decrypt(ciphertext, key, 256)
    tmp_file = "/tmp/tmp.html"
    with open (tmp_file, "wb") as temp_f:
        temp_f.write(decoded.encode("UTF-8"))
        temp_f.close()
    try:
        response = br.open('file://' + tmp_file)
        return response
    except Exception:
        return

def redirs_and_obfuscations(page, current_url): 

    #popupwnd
    if re.search('popupwnd', page):
        print "[+] Found page using popupwnd method, processing the popup"
        response = redir_popupwnd(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to acquire popupwnd link - this could be a bug"
            tshark("stop")
            sys.exit()

    #opendir
    elif "Index of" in br.title():
        print "[+] Found an open directory, attempting to handle the redir."
        response = redir_opendir(page, current_url)
        if response:
            return response
        else:
            print "[-] I wasn't able to get to a phish landing from this, might want to investigate this manually."
            tshark("stop")
            sys.exit()

    #weird ameli.fr template refresh
    elif br.title() and 'ameli.fr' in br.title():
	print "[+] Found ameli.fr in title, processing the refresh"
        if re.search('<meta http-equiv=["\']refresh', page, re.IGNORECASE):
            response = redir_ameli(page, current_url)
            if response:
                return response
            else:
                print "[-] Failed to acquire ameli.fr link - this could be a bug"
                tshark("stop")
                sys.exit()

    #JS Timeout redirector
    elif re.search('setTimeout\(\"location\.href', page, re.IGNORECASE):
        print "[+] Found js timeout, processing the redir"
        response = redir_jstimeout(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to acquire js timeout redirector link - this could be a bug"
            tshark("stop")
	    sys.exit()

    #JS top.location redirector
    elif re.search(';\s*top\.location\s*=\s*page', page, re.IGNORECASE):
        print "[+] Found js top.location, processing the redir"
        response = redir_jstoplocation(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to acquire js top.location redirector link - this could be a bug"
	    tshark("stop")
            sys.exit()

    #unescape(tmp[0]);
    elif re.search('unescape\(tmp\[0\]\)', page, re.IGNORECASE):
        print "[+] Found that custom js xor obfuscation, letting selenium process the deobfuscation"
        response = req_selenium(current_url)
        if response:
            return response
        else:
            print "[-] Failed to load a page with selenium in order to decode a custom js xor obfuscation - this could be a bug"
            tshark("stop")
            sys.exit()

    #document.write(unescape
    elif re.search('\(\s*unescape\s*\(\s*[\'"][^\s]{100}', page, re.IGNORECASE):
	print "[+] Found unescape, processing the deobfuscation"
        response = obfuscation_unescape(page)
        if response:
            return response
        else:
            print "[-] Failed to deobfuscate a javascript unescape - this could be a bug"
            tshark("stop")
 	    sys.exit()

    # AES js encrypted page
    # use this instead of popping selenium - https://raw.githubusercontent.com/moneytoolkit/Bank-Scraper/master/utils/aes.py
    elif re.search('(?:hea2[pt]|Aes\s*\.\s*Ctr\s*\.\s*decrypt)', page, re.IGNORECASE):
        print "[+] Found an AES encrypted page, processing the decoding"
        try:
            response = decode_aes(page)
        except Exception:
            print "[-] Failed to decode, going to let selenium do the work"
            response = req_selenium(current_url)
        if response:
            global using_selenium
            using_selenium=True
            return response
        else:
            print "[-] Failed to deobfuscate an AES encoded page - this could be a bug"
            tshark("stop")
	    sys.exit()

    # b64 frame src uri reload
    elif re.search('<\s*frame\s*\.\s*src\s*=\s*data:text/html;base64,', page, re.IGNORECASE):
	print "[+] Found base64 frame src data uri reload, processing the decoding"
        response = obfuscation_b64dataframe(page)
        if response:
            return response
        else:
            print "[-] Failed to deobfuscate a frame src Base64 DataURI encoded page - this could be a bug"
            tshark("stop")
   	    sys.exit()

    #common base64 refresh stuff
    elif re.search('data:text/html;base64,', page, re.IGNORECASE):
	print "[+] Found base64 data uri, processing the decoding"
        response = obfuscation_b64data(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to deobfuscate a frame src Base64 DataURI encoded page - this could be a bug"
            tshark("stop")
            sys.exit()

    #multi email provider
    elif re.search('[sS]l?elect\sYour\s(?:[eE]\-?mail)?\s[pP]rovider', page, re.IGNORECASE):
    	print "[+] Found a 'Select Your Email Provider' multi-phish landing, processing the landing"
        if multi_phish != 1:
            response = obfuscation_multimail(page, current_url)
            if response:
                return response
            else:
                print "[-] Failed to properly parse a 'select your email prover' phish - this could be a bug"
                tshark("stop")
                sys.exit()

    #cheeky redir to example domain
    elif re.search('<title>Example Domain</title>', page, re.IGNORECASE):
        print "[+] Found an attempted refresh to 'Example Domain', processing the landing"
	response = redir_exampledomain(current_url)
        if response:
            return response
        else:
            print "[-] Failed to handle an 'example domain' redir - this could be a bug"
            tshark("stop")
 	    sys.exit()

    #clickthrough bit.ly warning page
    elif re.search('<title>Warning! | There might be a problem with the requested link</title>', page, re.IGNORECASE):
	print "[+] Found a bit.ly phishing warning page, bypassing"
        response = redir_bitly(page)
        if response:
            return response
        else:
            print "[-] Failed to bypass the bitly warning page - this could be a bug"
            tshark("stop")
	    sys.exit()

    #clickthrough twitter warning page
    elif re.search('The link you are trying to access has been identified by Twitter or our partners', page, re.IGNORECASE):
        print "[+] Found a twitter phishing warning page, bypassing"
        response = redir_twitter(page)
        if response:
            return response
        else:
            print "[-] Failed to bypass the twitter warning page - this could be a bug"
            tshark("stop")
	    sys.exit()

    #clickthrough cloudflare warning page
    elif re.search('<title>Suspected phishing site | Cloudflare</title>', page, re.IGNORECASE):
        print "[+] Found a cloudflare phishing warning page, bypassing"
        response = redir_cloudflare()
        if response:
            return response
        else:
            print "[-] Failed to bypass the cloudflare warning page - this could be a bug"
            tshark("stop")
	    sys.exit()

    #byethost has a stupid AES redir
    elif re.search('toHex\(slowAES.decrypt\(', page, re.IGNORECASE):
	print "[+] Found a byethost AES redirect, processing the redir"
        response = req_selenium(current_url)
        if response:
            return response
        else:
            print "[-] Failed to load a page with selenium in order to decode a byethost AES redir- this could be a bug"
            tshark("stop")
	    sys.exit()

    #window.location or document.location redir
    elif re.search('(?:window|document)\s*\.\s*location', page[:1000], re.IGNORECASE):
        print "[+] Found js window.location or document.location, processing the redir"
        response = redir_jswindowlocation(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to acquire js window.location.href redirector link - this could be a bug"
            tshark("stop")
            sys.exit()

    #unhandled meta http-equiv refresh
    elif re.search('<\s*meta\s*http\-equiv\s*=\s*[\'"]\s*refresh', page[:1000], re.IGNORECASE):
        print "[+] Found an unhandled meta http refresh, processing the redir"
        response = redir_meta_http_refresh(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to acquire js window.location.href redirector link - this could be a bug"
            tshark("stop")
            sys.exit()

    #paypal landing
    elif re.search("Now hiring @ https://www.paypal.com/jobs", page):
        print "[+] Found a paypal landing page, processing the redir"
        response = redir_paypal_landing(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to process a paypal landing redirector link - this could be a bug"
            tshark("stop")
            sys.exit()

    #if we have no form yet, we check for an iframe maybe?
    elif re.search('<iframe src', page, re.IGNORECASE):
	print "[+] Found an iframe, following"
        response = redir_iframe_basic(page, current_url)
        if response:
            return response
        else:
            print "[-] Failed to follow an iframe - this could be a bug"
            tshark("stop")
	    sys.exit()

    #last ditch effort
    elif using_selenium is False and count == 0:
	    print "[+] Going to try and load this up with selenium as a last ditch effort"
            response = req_selenium(current_url)
            if response:
                return response
            else:
                print "[-] Failed to load a page with selenium - this could be a bug"
                tshark("stop")
		sys.exit()
    else:
        finish_him(count)

def find_post_form():

    post_form = False
    form_count = 0
    
    while post_form is False:
        reset_loop = False
        try:
            br.form = list(br.forms())[form_count]
        except Exception:
	    finish_him(count)

        if br.form.attrs:
            for keys,values in br.form.attrs.items():
                if re.search('(^tx_anmelden$|showContactUs|autoScroll|helpCentre_curtain|MenuControls_contactform|lang_switch_form_|^suche$|gaia_langform|locatorForm|curtainMenuControls|^ForgotPsw$|^forgotUsername$|^enterCard$|^remNick$|^GOCANACT$|^SIGNOUT2$|^SIGNOUTNS$|checkQ)', values): 
		    form_count=form_count+1
                    reset_loop = True
   
            if reset_loop is True: 
                continue

        try:
            if re.search('post', br.form.method, flags=re.IGNORECASE):
                if br.form.controls:
                    for test_control in br.form.controls:
                        test_control = str(test_control)
                        #print test_control
                        if re.search('(^q=$|\(q=\)|search)', test_control, flags=re.IGNORECASE):
			    form_count=form_count+1
                            reset_loop = True
                    if reset_loop is True: 
                        continue

                if br.form.name:
                    if re.search('(search|locale_|j_id[0-9]{10}_[a-f0-9]{7})', br.form.name, flags=re.IGNORECASE):
		        form_count=form_count+1
                        continue
                    else:
                        post_form=True
                else:
                    post_form=True
            else:
                form_count=form_count+1
                continue

        except Exception:
            print "[-] Unable to find a POST form"
            tshark("stop")
	    sys.exit()

        #set it to the form we want to scrape
        br.form = list(br.forms())[form_count]

def form_fill():

    ignore_select=0

    #load up the fake module for data - THIS MIGHT MOVE
    fake = Faker()

    for control in br.form.controls:
        #hidden control type
        if "hidden" in control.type:
            try: 
                if "hidCflag" in control.name: #this is a flag in many gmail/gdoc phish
                    ignore_select=1
                    br.form.find_control('hidCflag').readonly = False
                    br.form[control.name] = '1'
            except Exception:
                pass
        #image control type (don't care)
        elif (control.type == "image"):
            pass
        #email control type
        elif (control.type == "email"):
            try:
                br.form[control.name] = '%s' % fake.free_email()
                continue
            except Exception:
                pass
        #ssn control type   
        elif (control.type == "ssn"):
            br.form[control.name] = '%s' % fake.ssn()
            continue
        #text control type - THE BIG ONE
        elif control.type == "text" or control.type == "text2":
            #check to see that control.name isnt blank, we'll deal with this later if it is
            if control.name is not None:
                #try to make an educated guess at what should go in this form
                try:
                    #email address
                    if re.search('(?:winners1|liamguname|email|accountname|donnee1|^feedback$|^eml$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.free_email()
                        continue

                    #full name 
                    elif re.search('(?:^nn$|holder|^comname$|^hold$|full(?:_|-|\s)?nax?me|name_?on_?card|naonca|^name$|^nom$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s %s' % (fake.first_name(), fake.last_name()) 
                        continue

                    #username
                    elif re.search('(?:onlineId|^login$|loginid|user|apple_?id|user?name|^usr$)', control.name, flags=re.IGNORECASE):
		        br.form[control.name] = '%s' % fake.random_letter()+fake.last_name()
                        continue

                    #name prefix
                    elif re.search('prefix', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.prefix()
                        continue

                    #first name 
                    elif re.search('(^(?:spy\-)name$|^first$|fname|first(?:_|-|\s)?name|fnme|prenom|^_?fn$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.first_name()
                        continue

                    #last name
                    elif re.search('(^(?:spy\-)?last$|lname|last(?:_|-|\s)?name|surname|lnme|^_?ln$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.last_name()
                        continue

                    #street address
                    elif re.search('(?:^spy\-add|adds1|addr|hnber|billing_add?r|homeadd|add?ress[^2])', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.street_address()
                        continue

                    #second address line - never fill it out
                    elif re.search('(add?ress?e?2)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = ''
                        continue

                    #license
                    elif re.search('licen[sc]e', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.random_letter().upper()+str(fake.random_int()*fake.random_int()*fake.random_int())
                        continue

                    #state
                    elif re.search('state', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.state_abbr()
                        continue

                    #zip
                    elif re.search('(zip|postale)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.zipcode()
                        continue

                    #maiden name
                    elif re.search('(MMN|Mother|Maiden|maman)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.last_name()
                        continue

                    #country
                    elif re.search('country', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = 'USA'
                        continue

                    #month
                    elif re.search('(month|^mois$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.month()
                        continue

                    #four digits - birth year
                    elif re.search('(year|dob?3)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % 2017+fake.random_digit()-60
                        continue

                    #four digits - year
                    elif re.search('(spy\-year|dob?3)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % 2017+fake.random_digit()
                        continue

                    #four digits - random
                    elif re.search('(ss?n3|atm?pin|pin|atmp)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_int())[:4]
                        continue

                    #three digits
                    elif re.search('ss?n1', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_int())[:3]
                        continue

                    #two digts 
                    elif re.search('(ss?n2|dob?1|dob?2)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_digit())+str(fake.random_digit())
                        continue

                    #full date 
                    elif re.search('(dateofbirth|dob)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.date()
                        continue

                    #full ssn   
                    elif re.search('ssn', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.ssn()
                        continue

                    #id
                    elif re.search('^id$', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.random_letter()+fake.last_name()+fake.year()
                        continue

                    #credit card number
                    elif re.search('(?:^spy\-card$|^comnum$|^numb$|card(?:_|-|\s)?num|creditcard|ccd|ccrd|cnum|^cc$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.credit_card_number()
                        continue

                    #city
                    elif re.search('(?:city|ville)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.city()
                        continue

                    #phone number 
                    elif re.search('(?:tel|phone?|phne?|pnum|mobile|mbl|donnee3|winners3)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.phone_number()
                        continue

                    #credit card expiry 
                    elif re.search('(?:exp|pry|edate)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.credit_card_expire()
                        continue

                    #credit card code
                    elif re.search('(?:^comc$|^cv$|git|ccv|cvv|^3d$|verify|card_veri_num|c22d)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.credit_card_security_code()
                        continue

                    #sort code
                    elif re.search('(?:sort(?:[_-]?code)?|c522a)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_digit())+str(fake.random_digit())+"-"+str(fake.random_digit())+str(fake.random_digit())+"-"+str(fake.random_digit())+str(fake.random_digit())
                        continue

                    #account number - 9 digits
                    elif re.search('(?:ca22|acc(?:ount)?[_-]?num(?:ber)?|membership|accten|^account$)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_int())+str(fake.random_int())+str(fake.random_int())[:1]
                        continue

                    #account number - 8 digits
                    elif re.search('^comid2?$', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % str(fake.random_int())+str(fake.random_int())
                        continue

                    #other passwords
                    elif re.search('(?:vbv|[ep]pass|psword|passwd)', control.name, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % random.choice(list(open('10k.txt'))).strip()
                        continue

                    else:
                        pass

                except Exception:
                    #print "[-] Looks like theres no control.name"
                    pass

            #see if this control has an id - another way we can try and provide accurate information
            if control.id is not 'None':
                try:
                    #username
                    if re.search('user', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.random_letter()+fake.last_name()+fake.year()
                    elif re.search('(^id$|onlineid)', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.random_letter()+fake.last_name()+fake.year()
                    elif re.search('email', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.free_email()
                    elif re.search('ssn', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.ssn()
		    elif re.search('expy', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % 2017+fake.random_digit() 
                    #account number
                    elif re.search('account', control.id, flags=re.IGNORECASE):
                        num=""
                        for _ in range(9):
                            num=num+str(fake.random_digit())
                        br.form[control.name] = '%s' % num
                    #credit card number
                    elif re.search('(card(_|-|\s)?num|creditcard|ccd|ccrd|cnum)', control.id, flags=re.IGNORECASE):
                        br.form[control.name] = '%s' % fake.credit_card_number()
                    else:
                        #pass
                        try:
                            br.form[control.name] = '%s' % fake.catch_phrase()
                        except Exception:
                            #print "[-] You shouldn't be here..."
			    pass
                except Exception:
                    pass

            #if we can't figure out what it is, just put some businessy catch phrase in here
            else:
                try:
                    print "[-] Ehh i dunno what this is %s %s %s %s" % (control, control.type, control.name, control.id)
                    br.form[control.name] = '%s' % fake.catch_phrase()
                except Exception:
                    print "[-] You shouldn't be here..."

        #password
        elif control.type == "password":
            try:
                #cvv
                if re.search('cvv', control.name, flags=re.IGNORECASE):
                    br.form[control.name] = '%s' % str(fake.random_int())[:3]
                #atm pin
                elif re.search('(atm|pin|atmp)', control.name, flags=re.IGNORECASE):
                    br.form[control.name] = '%s' % fake.random_int()
                #generic password
                else: 
                    br.form[control.name] = '%s' % random.choice(list(open('10k.txt'))).strip() 
            except Exception:
               pass
 
        elif control.type == "select":
            if ignore_select==1:
                continue
            try:
                #pick anything, yolo
                control.value = [str((random.choice(control.items)))] 
            except Exception:
                #print "[-] Something weird, there was a select, but i couldn't pick one." 
		pass  

        #telephone control type
        elif (control.type == "tel"):
            br.form[control.name] = '%s' % fake.phone_number()
            continue
 
        #checkbox
        elif control.type == "checkbox":
            pass

        elif (control.id == "signin"):
            pass

        elif (control.type == "submit"):
            pass

        elif (control.type == "submitbutton"):
            pass
   
        elif control.name:
            if re.search('email', control.name, flags=re.IGNORECASE):
                br.form[control.name] = '%s' % fake.free_email()
            elif re.search('phone', control.name, flags=re.IGNORECASE):
                br.form[control.name] = '%s' % fake.phone_number()

        #catchall for debugging
        else:
            #print "[-] I don't know how you got here %s %s %s %s" % (control, control.type, control.name, control.id)
	    pass

def fixup_url(current_url):
        if re.search(r'^http', br.form.action):
            br.form.action = br.form.action
            #print "[+] I should submit this form to %s" % br.form.action 
        else:
            base_url = re.sub(r'\/[^/]+$', '', current_url)
            base_action = re.sub(r'^.+\/', '', br.form.action)
            submit_me = base_url+'/'+base_action
            br.form.action = urlnorm.norm(submit_me)

def teardown_display():

    #teardown display
    if display.is_alive():
        display.stop()
    return

def finish_him(count):

    teardown_display()
    if count > 0:
        print "\n[+] Complete! Submitted %s form(s)\n" % count
	print "[+] Url Request Chain:"
	url_count=0
        for url in url_array:
	    num_dash = url_count*1
	    print '--' * num_dash + url
            url_count+=1
        print '\n'

        #stop capture
        tshark("stop")
	sys.exit()
    else:
        #http://db.destinytracker.com/grimoire/allies/rasputin/ghost-fragment-rasputin-3
        print "[-] ENTERING MIDNIGHT EXIGENT -*"
       
        #stop capture
        tshark("stop")
        sys.exit()

def redir_loop_infinite():
    print "[-] Looks like you are stuck in a redir loop, this is either a bug, this phish is VERY redir heavy, or a countermeasure. Best to examine this manually"
    tshark("stop")
    sys.exit()

def check_legit_site(current_url):
    if re.search("^https?:\/\/(?:www\.)?[^/]+(?:c(?:o(?:m(?:mbank\.com\.au|presso\.co\.th|cast\.net)|(?:ldwellbankerpreviews)\.com|rnell\.edu)|(?:i(?:ti(?:zensbank)?|ovaccocapital|bcfcib)|h(?:ristianmingl|as)e)\.com|r(?:edit(?:-agricole|mutuel)\.fr|aigslist\.org)|a(?:pitalone(?:360)?\.com|rtasi\.it)|panel\.(?:com|net)|entrin\.net\.id|fapubs\.org)|s(?:e(?:(?:niorpeoplemeet|rvice-now)\.com|c(?:ure\.lcl\.fr|\.gov))|u(?:n(?:corp\.com\.au|trust\.com)|ddenlink\.net)|a(?:ntander\.co(?:m\.br|\.uk)|atchiart\.com)|(?:c(?:otiabank)?|ocietegenerale)\.com|t(?:andardbank\.co\.za|ripe\.com)|in(?:a\.com\.cn|gtel\.com)|parkasse\.(?:at|de)|wisscom\.ch|fr\.fr)|i(?:n(?:t(?:er(?:netbanking\.caixa\.gov\.br|tekgroup\.org)|uit\.com)|vestorjunkie\.com|dianatech\.edu|g\.(?:be|nl))|c(?:(?:icibank|loud)\.com|scards\.nl)|m(?:pots\.gouv\.fr|ages\.kw\.com)|(?:wmusa|bm)\.com|rs\.gov)|a(?:(?:cc(?:ounts\.google|esbankplc)|li(?:express|baba|yun)|d(?:obe|p)|irbnb|pple|ol|tt)\.com|m(?:azon\.c(?:o(?:\.uk|m)|a)|ericanexpress\.com)|s(?:perasoft\.com|b\.co\.nz)|nz\.co(?:\.nz|m)|bl\.com\.pk|ruba\.it)|b(?:a(?:n(?:que(?:populaire|-accord)\.fr|kofamerica\.com)|rclays\.co\.uk|9hus\.in)|(?:i(?:gpond|ztree)|2bchinasources|mo|t)\.com|bva(?:compass\.com|\.com\.co)|l(?:ackboard\.com|uewin\.ch))|d(?:(?:iscover(?:bank|card)?|r(?:ive\.google|opbox))\.com|oc(?:(?:s(?:\.google)?|usign)\.(?:com|net)|droid\.net)|e(?:sjardins\.c(?:om|a)|loitte\.com)|hl\.co(?:\.uk|m))|m(?:(?:icrosoft(?:(?:onlin|stor)e)?|organstanley)\.com|a(?:(?:(?:rketwa)?tch|de-in-china|cu)\.com|il\.ru)|s(?:outlookonline\.net|n\.com)|bna\.co\.uk)|w(?:e(?:(?:althmanagement|llsfargo|transfer)\.com|stpac\.co(?:m\.au|\.nz)|bmail\.sfr\.fr)|(?:ww-01\.ibm|hatsapp)\.com|ikimedia\.org)|n(?:a(?:v(?:yf(?:ederal|cu)\.org|er\.com)|t(?:ionwide\.co\.uk|west\.com)|b\.com\.au)|(?:et(?:suit|eas)e|wolb)\.com|fcu\.org)|t(?:e(?:(?:chnologyordie|scobank)\.com|l(?:stra\.com\.au|ekom\.com))|(?:d(?:canadatrust|bank)|radekey)\.com|-online\.de)|g(?:o(?:o(?:gle(?:\.(?:c(?:o(?:m(?:\.(?:[en]g|au|my|pk))?|\.uk)|a)|r[ou])|apps\.com)|\.gl)|daddy\.com|v\.uk)|mail\.com)|p(?:ost(?:finance\.ch|bank\.de|epay\.it)|ri(?:melocation\.com|nceton\.edu)|aypal\.(?:co(?:\.uk|m)|fr)|[nw]c\.com)|e(?:bay\.(?:co(?:\.uk|m)|de|it)|xperienceasb\.co\.nz|(?:tisalat|im)\.ae|arthlink\.net|ftel\.com\.au|c21\.com)|r(?:e(?:al(?:tyexecutives\.com|estate\.com\.au)|(?:gions|max)\.com)|(?:bc(?:royalbank|ds)|oyalbank)\.com)|o(?:(?:ff(?:ice(?:365)?|erup)|u(?:rtime|tlook))\.com|n(?:line\.hmrc\.gov\.uk|ey\.fr)|range\.(?:co\.uk|fr))|v(?:eri(?:fyemailaddress\.org|zon\.net)|(?:a(?:luewalk|nguard)|snl)\.com|i(?:deotron\.com|saeurope\.ch))|l(?:(?:i(?:nkedin|ve)|endingtree|loydsbank)\.com|a(?:banquepostale\.(?:mobi|fr)|tech\.edu))|f(?:i(?:delity(?:bank\.ng|\.com)|rst-online\.com)|ede(?:ralreserve\.gov|x\.com)|acebook\.com)|h(?:a(?:lifax(?:-online)?\.co\.uk|waiiantel\.net)|(?:otmail|sbc)\.com|blibank\.com\.pk)|u(?:(?:s(?:bank|aa|ps)|[bp]s)\.com|n(?:icredit\.it|[ch]\.edu)|csd\.edu)|(?:x(?:finity|oom)|yahoo(?:mail)?|1(?:26|63)|qq)\.com|k(?:iwibank\.co\.nz|eybank\.com)|z(?:(?:illow|oosk)\.com|kb\.ch))\/", current_url):
        print "\n[+] %s appears to be a legitimate website." % current_url
        finish_him(count)

def tshark(action):
    if action == "start":
        parsed_url = urlparse.urlparse(initial_url)
        pcap_name = time.strftime("%Y%m%d-%H%M%S") + '-' + parsed_url.netloc + ".pcap"
        FNULL = open(os.devnull, 'w')
        subprocess.Popen(["tshark","-i",tshark_if,"-w",pcap_name], stdout=FNULL, stderr=subprocess.STDOUT) 
        print "\n[+] Preparing pcap: %s" % pcap_name
        time.sleep(2)
        return
    else:
        time.sleep(2)
        subprocess.call(["pkill","tshark"])
        return

################ START MAIN ################
if __name__ == "__main__":

    print "\n.: BULLYBLINDER v0.1 https://github.com/hadojae/DATA :."

    parser = argparse.ArgumentParser(description='Visit a suspected phishing page and attempt form filling while getting a pcap')
    parser.add_argument('-u','--url', help='Url to visit',required=True,default=False)
    parser.add_argument('-a','--useragent', help='Custom User-Agent to use',required=False,default="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")
    parser.add_argument('-i','--interface', help='Interface to tell tshark to listen on',required=True,default="eth0") 

    args = parser.parse_args()
    initial_url = args.url
    user_agent = args.useragent
    tshark_if = args.interface

    req_timeout=30
    using_selenium=False
    count=0
    multi_phish=0
    redir_count=0
    display_running=False
    url_array=[ ]   

    #display
    display = Display(visible=0, size=(1366, 768))

    #make sure strings are utf-8
    reload(sys)
    sys.setdefaultencoding("utf-8")

    #init mechanize with additional robustness
    br = mechanize.Browser()
    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)
    #header / browser settings
    br.addheaders = [('User-agent', user_agent)]
    br.set_handle_equiv(True)
    br.set_handle_redirect(mechanize.HTTPRedirectHandler)
    br.set_handle_referer(True)
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=30)
    br.set_handle_robots(False)
 
    #fixup spaces in the initial url
    if re.search(' ', initial_url):
        initial_url = fix_spaces(initial_url)

    #start packet capture
    tshark("start")

    if re.search('(?:goo\.gl|bit\.ly|ow\.ly|tinyurl\.com)', initial_url):
        print "\n[+] URL shortener observed, expanding."
        headers = { 'User-Agent' : user_agent }
        req = urllib2.Request(initial_url, None, headers)
        a = urllib2.urlopen(req)
        initial_url = a.url

    #lets do it
    response = request_page(initial_url)
    if response is False or response is None:
        print "[-] Failed to retrieve %s" % initial_url
        tshark("stop")
        sys.exit()

    while count < 3: 

        if redir_count >= 9:
	    redir_loop_infinite()

        #read the response content 
        page = response.read()

        #check to see that we're looking at html
        if br.viewing_html() == False:
            if page[:4] == "%PDF":
                print "\n[+] %s is a PDF" % current_url
                finish_him(count)
            else:
                print "\n[-] Page content does not appear to be HTML.\n"
                print "    " + page[:100]
                finish_him(count)

        #get the current url in case we've been through some redirects
        if br.geturl().startswith("http"): 
            current_url = br.geturl()
        elif br.geturl().startswith("file"):
            current_url = url_array[-1]
        else:
            current_url = initial_url

	#check the url to see if this is a common legitimate site
	check_legit_site(current_url)

        #print "\n[+] Currently processing %s" % current_url + '\n'
        url_array.append(current_url)

        if len(url_array) > 1:
            referer = url_array[-2]

        # check for a form, if there isn't one, run it through all the redirector
        # and obfuscation checks
        try:
            br.form = list(br.forms())[0]
        except Exception:
            print "\n [-] No form found, checking for redirectors and obfuscation. \n"
            response = redirs_and_obfuscations(page, current_url)
            redir_count+=1
            continue

        #check to make sure that there isnt an empty form action
        if br.form.attrs:
            if br.form.attrs['action'] == "":
                print "\n [-] Empty form action found, checking for redirectors and obfuscation. \n"
                response = redirs_and_obfuscations(page, current_url)
                redir_count+=1
                continue

        #acquire the post form
        find_post_form()

        #check enctype - sometimes people put stupid stuff in here and it breaks mechanize
        if br.form.enctype:
            br.form.enctype = "application/x-www-form-urlencoded"

        #fill the form as best we can
        form_fill()

        #if we've used selenium or something that wrote to the tmp file, we may need to modify where we are actually posting our data to
        if using_selenium is True:
            fixup_url(current_url)

	print "\n[+] Submitting POST"

	#print out what we are going to be submitting for debugging purposes
        for control in br.form.controls:
            print "    [+] Control: %s, Control.Type: %s, Control.Name: %s, Control.ID: %s" % (control, control.type, control.name, control.id)

	#submit the form        
	try:
	    response = br.submit()
        except (mechanize.HTTPError,mechanize.URLError) as e:
            print "[-] The HTTP response to the form submission has returned an error: %s" % str(e)

        count+=1

    finish_him(count)  

################ END MAIN ################
