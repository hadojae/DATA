#headless bullyblinder install script
#hadojae 05.02.2017

#update/upgrade
sudo apt-get update && sudo apt-get upgrade

#install stuff
sudo apt-get -y install git xvfb python-pip firefox unzip zip tshark wireshark

#download geckodriver
wget https://github.com/mozilla/geckodriver/releases/download/v0.21.0/geckodriver-v0.21.0-linux64.tar.gz
tar xzf geckodriver-v0.21.0-linux64.tar.gz
rm geckodriver-v0.21.0-linux64.tar.gz
sudo chmod a+x geckodriver
sudo mv geckodriver /usr/bin

#pip stuff
sudo pip install mechanize Beautifulsoup4 urlnorm selenium faker pyvirtualdisplay lxml
