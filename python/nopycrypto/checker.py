#!/usr/local/bin/python

import hmac, operator, time, random, urllib2, md5
import aes, sys, math


def decrypt(cipherIn, key, IV):
    iput = output = ciphertext = []
    plaintext = [0] * 16
    stringOut = ''
    firstRound = True
    if cipherIn != None:
        for j in range(int(math.ceil(float(len(cipherIn))/16))):
            start = j*16
            end = j*16+16
            if j*16+16 > len(cipherIn):
                end = len(cipherIn)
            ciphertext = cipherIn[start:end]
        
            output = aes.AES().decrypt(ciphertext, key, 32)
            for i in range(16):
                if firstRound:
                    plaintext[i] = IV[i] ^ output[i]
                else:
                    plaintext[i] = iput[i] ^ output[i]
            firstRound = False
            for k in range(end-start):
                stringOut += chr(plaintext[k])
            iput = ciphertext
    return stringOut

def genSID(p):
    return hmac.new('f6daaa397d51f568dd068709b0ce8e93293e078f7dfc3b40dd8c32d36d2b3ce1', # sec_as3->generateSignatureToCSEL
                    ''.join([''.join(k[0]+k[1]) for k in sorted(p.items(), # Sort by letter
                    key=operator.itemgetter(0))])).hexdigest() # Get Key and hmac the msg with the key to make an session id

def decryptAES_CBC(s):
    key = map(ord, str(bytearray(x ^ 42 for x in bytearray('fcf0ea63e6be6f33aa40938b9fc8b6e5c9cd67819ed06873a06fe9770a81f702'.decode('hex'))))) # sec_as3->xmldec[key=42, sec="...".encode(hex)]
    return decrypt(map(ord, s.decode('hex')), key, map(ord, str(bytearray('36c8cdeg64bb@3dB'))))

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

decrypt = decryptAES_CBC(response)

print '[BLOCKED] :', 'tp:geoCheck="block"' in decrypt # tp:geoCheck="allow"
