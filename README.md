# DATA
Credential Phish Analysis and Automation

(https://i.kinja-img.com/gawker-media/image/upload/s--UbOvuJRg--/c_scale,fl_progressive,q_80,w_800/18mkc27z3skq4jpg.jpg)

DATA currently consists of the following scripts:

- Bucklegripper (py)
  - Given a suspected phishing url or file of line separated urls, visit, screenshot, and scrape for interesting files.
  - Requirements can be installed by running or reviewing install_bucklegripper_deps.sh

- Bullyblinder (py)
  - While capturing a pcap visit a suspected phishing page. Handle redirectors and obfuscation to find a web form. Scrape the form and make educated guesses at what should be entered into the fields. Submit the form and repeat.
  - Requirements can be installed by running or reviewing install_bullyblinder_deps.sh

- Slickshoes (sh)
  - A basic bash script that pulls links out of pdfs in streams or in clear view.
  
