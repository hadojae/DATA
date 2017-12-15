#headless bucklegripper install script
#hadojae 05.02.2017

sudo apt-get update && sudo apt-get upgrade

#install stuff
sudo apt-get install xvfb firefox fdupes ssdeep python-pip unzip zip

#download geckodriver
wget https://github.com/mozilla/geckodriver/releases/download/v0.19.1/geckodriver-v0.19.1-linux64.tar.gz
tar xzf geckodriver-v0.19.1-linux64.tar.gz
rm geckodriver-v0.19.1-linux64.tar.gz
sudo chmod a+x geckodriver
sudo mv geckodriver /usr/bin

#pip stuff
sudo pip install mechanize urlnorm requests dnspython selenium faker pyvirtualdisplay python-magic
