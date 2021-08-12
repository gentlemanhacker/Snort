# Snort
Snort Rule Examples<br>
This is a dump of various rules from CTF's or Assignments<br>
<br>
#Create a test.rules<br>
  <br>
var HOME_NET 192.168.121.134<br>
var EXTERNAL_NET !$HOME_NET<br>
<br>
#Write a rule to check any external network access your webserver /admin pages<br>
alert tcp any any -> $HOME_NET 22 (msg:"SSH Attack";sid:1324; flow:established,to_server;\detection_filter: track by_src, count 3, seconds 60;)<br>
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (sid:1002354;rev:2;msg:"Warning A host is trying to access /admin"; uricontent:"/admin";)<br>
alert tcp 10.10.20.10 any -> 10.10.10.10 any (msg:"Any TCP connections from your host to 10.10.10.10"; sid: 100001;)<br>
alert udp 10.10.20.10 any -> 10.10.10.10 any (msg:"Any UDP connections from your host to 10.10.10.10"; sid: 100002;)<br>
alert tcp any any <> 10.10.10.10 any (msg:"Any TCP connection to 10.10.10.10 containing the content Delete"; content:"delete"; sid: 100003;)<br>
alert tcp any any <> any any (msg:"drop connection";content:"drop"; sid: 100004;)<br>
#alert tcp any any <> !54.70.73.131 any (msg:"IgnoreIPtcp";  sid: 9000001; )<br>
pass tcp 54.70.73.131 any <> 54.70.73.131 any (msg:"Ignore AWS"; rev:1; sid: 9000001;)<br>
pass tcp any any <> 54.70.73.131 any (msg:"pass2";sid: 90000003;)<br>
<br>

#Call and test the rules<br>
include /etc/snort/test.rules<br>
then call that<br>
snort -i eth0 -c /etc/snort/snort-test.conf -l /var/log/snort<br>
