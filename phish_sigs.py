# phish_sig.py
# https://github.com/hadojae/DATA/phish_sigs.py
#
# Usage: 
# python phish_sigs.py -p "loginOp=login&username=lHunter&password=blondie&client=preferred" -n Zimbra -s 5005436
#
# Suricata:
# alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Successful Zimbra Phish 2017-11-10"; 
# flow:to_server,established; content:"POST"; http_method; content:"loginOp="; depth:8; nocase; http_client_body; 
# content:"&username="; nocase; distance:0; http_client_body; content:"&password="; nocase; distance:0; http_client_body; 
# content:"&client="; nocase; distance:0; http_client_body; classtype:trojan-activity; sid:5005436; rev:1;)
#
# Snort:
# alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Successful Zimbra Phish 2017-11-10"; 
# flow:to_server,established; content:"POST"; http_method; content:"loginOp="; depth:8; nocase; http_client_body; 
# content:"&username="; nocase; distance:0; http_client_body; content:"&password="; nocase; distance:0; http_client_body; 
# content:"&client="; nocase; distance:0; http_client_body; classtype:trojan-activity; sid:5005436; rev:1;)

import argparse
import datetime

parser = argparse.ArgumentParser(description='Make a phish sig with the contents of the http_client_body of a successful phish')
parser.add_argument('-p','--postbody', help='The http_client_body contents; eg. "user=bob&pass=ok&signin=Sign+In"',required=True,default=False)
parser.add_argument('-n','--name', help='Usually the brand being phished',required=True,default=False)
parser.add_argument('-s','--sid', help='signature id number',required=False,default="100")

#setup vars
args = parser.parse_args()
http_client_body = args.postbody
name = args.name
sid = args.sid
arg_list=[]
count=0

#date
today = str(datetime.date.today())

#parse http_client_body args
for i in http_client_body.split("&"):
    if count==0:
        depth = len(i.split("=")[0] + "=")
        arg_list.append("content:\"" + i.split("=")[0] + "=\"; depth:" + str(depth) + "; nocase; http_client_body;")
        count=count+1
    else:
        arg_list.append("content:\"&" + i.split("=")[0] + "=\"; nocase; distance:0; http_client_body;")

rule_content = ' '.join(arg_list)

#suri rule stubs
suri_front = "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET CURRENT_EVENTS Successful " + name+ " Phish " + rule_date + "\"; flow:to_server,established; content:\"POST\"; http_method; "
suri_end = " classtype:trojan-activity; sid:" + sid + "; rev:1;)"

#snort rule stubs
snort_front = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"ET CURRENT_EVENTS Successful " + name + " Phish " + rule_date + "\"; flow:to_server,established; content:\"POST\"; http_method; "
snort_end = " classtype:trojan-activity; sid:" + sid + "; rev:1;)"

#print rules
print ""
print suri_front + rule_content + suri_end
print ""
print snort_front + rule_content + snort_end
print ""
