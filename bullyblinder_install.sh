#headless bullyblinder install script
#hadojae 05.02.2017

#update/upgrade
sudo apt-get update && sudo apt-get upgrade

#install stuff
sudo apt-get -y install git xvfb python-pip firefox unzip zip tshark wireshark

#download geckodriver
wget https://github.com/mozilla/geckodriver/releases/download/v0.11.1/geckodriver-v0.11.1-linux64.tar.gz
tar xzf geckodriver-v0.11.1-linux64.tar.gz
rm geckodriver-v0.11.1-linux64.tar.gz
sudo chmod a+x geckodriver
sudo mv geckodriver /usr/bin

#pip stuff
sudo pip install mechanize Beautifulsoup4 urlnorm selenium faker pyvirtualdisplay

#grap orca stuff
git clone https://github.com/hadojae/DATA

#grab common passwords
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10k_most_common.txt && mv 10k_most_common.txt DATA/10k.txt

#TROUBLESHOOTING

#If you have pcap writing issues, use this to fixup dumpcap perms, observed when using digitalocean
#change myusername to your username
#-----
#sudo chgrp myusername /usr/bin/dumpcap
#sudo chmod 750 /usr/bin/dumpcap
#sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
#-----

# remember to set your interface properly otherwise checksum errors may eat your face when you try to read pcaps w/ tools
# AS ROOT: for i in rx tx sg tso ufo gso gro lro; do ethtool -K eth0 $i off; done
