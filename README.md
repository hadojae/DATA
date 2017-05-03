# DATA
Credential Phish Analysis and Automation

*Tested on Ubuntu 16.04

## BUCKLEGRIPPER (py)
  - Given a suspected phishing url or file of line separated urls, visit, screenshot, and scrape for interesting files.
  - Requirements can be installed by running or reviewing install_bucklegripper_deps.sh
```
usage: bucklegripper.py [-h] [-u URL] [-s SOURCE] [-r READFILE] [-a USERAGENT]

Visit a suspected phishing page, screenshot it and pillage it for phishing
archives

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Url to visit
  -s SOURCE, --source SOURCE
                        Apply a source to where this url came from
  -r READFILE, --readfile READFILE
                        Read in a file of URLs one per line
  -a USERAGENT, --useragent USERAGENT
                        Custom User-Agent
```

Example of reading in a single url
```
$ python bucklegripper.py -s openphish -u http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au/Login.html 

.: BUCKLEGRIPPER v0.1 https://github.com/hadojae/DATA/ :.

[+] Processing http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au/Login.html
  [+] Screencapped http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au/Login.html as 20170503-032950-openphish-www.govwebsearch.com.png
  [+] Found Zip file at http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au.zip
  [+] Saved http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au.zip as 20170503-032950-openphish-www.govwebsearch.com-optusnet.com.au.zip
[+] Found Opendir at http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au/
  [+] Found php file: http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au/post.php
[+] Found Opendir at http://www.govwebsearch.com/apc/opc/pdp/safe/
  [+] Saved http://www.govwebsearch.com/apc/opc/pdp/safe/optusnet.com.au.zip as 20170503-032951-openphish-www.govwebsearch.com-optusnet.com.au.zip
[+] Found Opendir at http://www.govwebsearch.com/apc/opc/pdp/
[+] Found Opendir at http://www.govwebsearch.com/apc/opc/
[+] Found Opendir at http://www.govwebsearch.com/apc/
```

Example of reading in a file of line separated urls
```
$ python bucklegripper.py -s openphish -r ../../test_urls.txt

.: BUCKLEGRIPPER v0.1 https://github.com/hadojae/DATA/ :.

[+] Beginning processing of ../../test_urls.txt

[+] Processing http://onjasela.net/DB/fr/
  [+] Screencapped http://onjasela.net/DB/fr/ as 20170503-010034-openphish-onjasela.net.png

[+] Processing http://suesschool.com/yahoologin/yahoologin/clients/login.php
  [+] Screencapped http://suesschool.com/yahoologin/yahoologin/clients/login.php as 20170503-010053-openphish-suesschool.com.png
[+] Found Opendir at http://suesschool.com/yahoologin/yahoologin/clients/
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/clients/login.php
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/clients/data.php
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/clients/block.php
[+] Found Opendir at http://suesschool.com/yahoologin/yahoologin/
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/login.php
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/data.php
  [+] Found php file: http://suesschool.com/yahoologin/yahoologin/block.php
  [+] Found Zip file at http://suesschool.com/yahoologin.zip
  [+] Saved http://suesschool.com/yahoologin.zip as 20170503-010125-openphish-suesschool.com-yahoologin.zip
[+] Found Opendir at http://suesschool.com/yahoologin/

[+] Processing http://communitypartnersjc.org/wp-admin/js/index
  [+] Screencapped http://communitypartnersjc.org/wp-admin/js/index as 20170503-010138-openphish-communitypartnersjc.org.png

[+] Processing http://ytrdesh.com/info/
  [+] Screencapped http://ytrdesh.com/info/ as 20170503-010148-openphish-ytrdesh.com.png
  
...continues...
```

## BULLYBLINDER (py)
  - While capturing a pcap visit a suspected phishing page. Handle redirectors and obfuscation to find a web form. Scrape the form and make educated guesses at what should be entered into the fields. Submit the form and repeat.
  - Requirements can be installed by running or reviewing install_bullyblinder_deps.sh
  
```
usage: bullyblinder.py [-h] -u URL [-a USERAGENT] -i INTERFACE

Visit a suspected phishing page and attempt form filling while getting a pcap

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Url to visit
  -a USERAGENT, --useragent USERAGENT
                        Custom User-Agent to use
  -i INTERFACE, --interface INTERFACE
                        Interface to tell tshark to listen on
```
Example Usage
```
$ python bullyblinder.py -i eth0 -u http://www.justpropertydevelopers.com/scanned

.: BULLYBLINDER v0.1 https://github.com/hadojae/DATA/ :.

[+] Preparing pcap: 20170503-033243-www.justpropertydevelopers.com.pcap

[+] Processing http://www.justpropertydevelopers.com/scanned

[+] Submitting POST
    [+] Control: <HiddenControl(hidCflag=1)>, Control.Type: hidden, Control.Name: hidCflag, Control.ID: hidCflag
    [+] Control: <SelectControl(<None>=[])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <SelectControl(<None>=[*0])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <SelectControl(<None>=[*1])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <SelectControl(<None>=[*2])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <SelectControl(<None>=[*3])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <SelectControl(<None>=[*4])>, Control.Type: select, Control.Name: None, Control.ID: None
    [+] Control: <TextControl(Email=shannonjudith@gmail.com)>, Control.Type: email, Control.Name: Email, Control.ID: Email
    [+] Control: <PasswordControl(Passwd=696969)>, Control.Type: password, Control.Name: Passwd, Control.ID: Passwd
    [+] Control: <SubmitControl(signIn=Sign in to view attachment) (readonly)>, Control.Type: submit, Control.Name: signIn, Control.ID: signIn
    [+] Control: <CheckboxControl(PersistentCookie=[yes])>, Control.Type: checkbox, Control.Name: PersistentCookie, Control.ID: PersistentCookie
    [+] Control: <HiddenControl(rmShown=1) (readonly)>, Control.Type: hidden, Control.Name: rmShown, Control.ID: None

 [-] No form found, checking for redirectors and obfuscation. 

[+] Found js window.location or document.location, processing the redir

[+] https://drive.google.com/#my-drive appears to be a legitimate website.

[+] Complete! Submitted 1 form(s)

[+] Url Request Chain:
http://justpropertydevelopers.com/scan/docg/doc/filewords/index.php
--http://justpropertydevelopers.com/scan/docg/doc/filewords/index.php
```

## SLICKSHOES (sh)
  - A basic bash script that pulls urls out of pdfs in streams or in clear view.
  - The only argument to the script is the path to a folder containing the pdfs you want to process.
  
Example Usage
```
$ ./slickshoes.sh ~/PDFs/
http://4cgemstones.com/polaiowpwwww/GD/index.php
http://80bpm.net/invoice-17524-Apr-26-2017-US-048591/
http://acheirapido.com.br/arquivos/pdf/
http://adams-kuwait.com/REview/office
http://rfaprojects.co.uk/invoice-80633-Apr-24-2017-US-665952/
http://sacm.net/SCANNED/ZN3747CGMSCWC/
https://geloscubinho.com.br/cgi/pdf/index.php
http://afriquecalabashsafaris.com/layouts/GD/index.php
http://akukoomole.com/AdobeLogin/index.php
...continues...
```

*PINCHERSOFPERIL and BULLYBUSTER are WIP

DATA scripts are a constant work in progress. Feedback, issues, and additions are welcomed.

Proper python packages will be created once suffecient testing and features have been added and more bugs have been squashed.
