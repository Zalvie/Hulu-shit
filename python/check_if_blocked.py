#!/usr/local/bin/python

import hmac, operator, time, random, urllib2, md5
from Crypto.Cipher import AES

def genSID(p):
    return hmac.new('f6daaa397d51f568dd068709b0ce8e93293e078f7dfc3b40dd8c32d36d2b3ce1', # sec_as3->generateSignatureToCSEL
                    ''.join([''.join(k[0]+k[1]) for k in sorted(p.items(), # Sort by letter
                    key=operator.itemgetter(0))])).hexdigest() # Get Key and hmac the msg with the key to make an session id

def decryptAES_CBC(s):
    key = str(bytearray(x ^ 42 for x in bytearray('fcf0ea63e6be6f33aa40938b9fc8b6e5c9cd67819ed06873a06fe9770a81f702'.decode('hex')))) # sec_as3->xmldec[key=42, sec="...".encode(hex)]
    return AES.new(key, AES.MODE_CBC, str(bytearray('36c8cdeg64bb@3dB'))).decrypt(s.decode('hex')) # sec_as3->xmldec[AES.CBC, IV="...", s.encode(hex)]

q = {
     'device_id': md5.new(str(random.random())).hexdigest().upper(), # upper(MD5(computerGUID))
     'ts':        str(int(time.time())), # Timestamp
     'np':        '1', # ?
     'vp':        '1', # ? 
     'pc':        '1', # ?
     'load_type': 'load', # reload / load
     'video_id':  '60487967', # Video ID
     'v':         '888324234', # sec_as3->generateSignatureToCSEL
     'pp':        'hulu', # distroPartner
     'dp_id':     'hulu', # distroPartner
     'ep':        '1', # Video reload
     'region':    'US', # Region JP / US
     'language':  'en' # Language
    }

url = ''.join(['http://s.hulu.com/select?', '&'.join(['='.join(k) for k in q.items()]), '&bcs=', genSID(q)])

print '[URL] :', url

request = urllib2.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', 
                                        'Cookie': 'guid=' + q['device_id']}) # It checks the guid, cute
response = urllib2.urlopen(request).read()

decrypted = decryptAES_CBC(response)

print '[BLOCKED] :', 'tp:geoCheck="block"' in decrypted # tp:geoCheck="allow"
