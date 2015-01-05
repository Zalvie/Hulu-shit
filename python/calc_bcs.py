import hmac, operator

url = 'http://s.hulu.com/select?'
key = 'f6daaa397d51f568dd068709b0ce8e93293e078f7dfc3b40dd8c32d36d2b3ce1' # sec_as3->generateSignatureToCSEL

output = '7041170249d4e928e8079b0f86ca8cbc'

o = 'v=888324234&ts=1420447496&np=1&vp=1&pc=1&load_type=load&video_id=60487967&device_id=61878066F367D01DADFB0AF49D7B02CF&pp=hulu&dp_id=hulu&ep=1&region=US&language=en'

v = hmac.new(key,''.join([''.join(k[0]+k[1]) for k in sorted([i.split('=') for i in o.split('&')], key=operator.itemgetter(0))])).hexdigest()

print '[BCS] :', v, '=', output, '==', v == output

print '[URL] :', ''.join([url, o, '&bcs=', v])

'''
        public static function getUrl(_arg1:Number, _arg2:String=null, _arg3:ContentSelectParameters=null, _arg4:Number=-1):String{
            var _local9:String;
            var _local5:String = Security.v;
            _arg3 = ((_arg3) || (new ContentSelectParameters()));
            var _local6:Array = [["v", _local5], ["ts", int((new Date().valueOf() / 1000))], ["np", 1], ["vp", 1], ["pc", 1], ["load_type", _arg3.loadType]];
            if (_arg1 > 0){
                _local6.push(["video_id", _arg1]);
            } else {
                if (_arg2 != null){
                    _local6.push(["eid", _arg2]);
                };
            };
            var _local7:String = NetUtility.URLJoin(ServerConfig.PLATFORM_PROXY_SITE, "select?");
            if (_arg3.cdnprefs != null){
                _local6.push(["cdnprefs", _arg3.cdnprefs]);
            };
            if (_arg3.computerGUID != null){
                _local6.push(["device_id", _arg3.computerGUID]);
            };
            if (((!((_arg3.distroPartner == null))) && (!((_arg3.distroPlatform == null))))){
                _local6.push(["pp", _arg3.distroPlatform]);
                _local6.push(["dp_id", _arg3.distroPartner]);
            };
            if (!TextUtility.IsBlank(_arg3.userToken)){
                _local6.push(["token", _arg3.userToken]);
            };
            if (_arg4 > 0){
                _local6.push(["retry", _arg4]);
            };
            _local6.push(["ep", 1]);
            if (((((!(TextUtility.IsBlank(_arg3.removedToken))) && (!(TextUtility.IsBlank(_arg3.oldKey))))) && (!(TextUtility.IsBlank(_arg3.oldKeyVersion))))){
                _local9 = ((("1," + _arg3.removedToken) + ",") + GUID.getNewGUID()).slice(0, 16);
                _local9 = Security.encryptping(_local9, _arg3.oldKey).slice(0, 32);
                _local6.push(["p", _local9]);
                _local6.push(["kv", _arg3.oldKeyVersion]);
            };
            if (((!(TextUtility.IsBlank(_arg3.region))) && (!(TextUtility.IsBlank(_arg3.language))))){
                _local6.push(["region", _arg3.region]);
                _local6.push(["language", _arg3.language]);
            };
            if (_arg3.defaultHighQuality){
                _local6.push(["hq", 1]);
            };
            if (_arg3.privateMode){
                _local6.push(["sr", 1]);
            };
            if (!TextUtility.IsBlank(_arg3.authToken)){
                _local6.push(["auth_token", _arg3.authToken]);
            };
            var _local8:int;
            while (_local8 < _local6.length) {
                _local7 = (_local7 + ((((((_local8 == 0)) ? "" : "&") + _local6[_local8][0]) + "=") + encodeURIComponent(_local6[_local8][1])));
                _local8++;
            };
            _local7 = (_local7 + ("&bcs=" + Security.generateSignatureToCSEL(getQueryString(_local6))));
            return (_local7);
        }
        private static function getQueryString(_arg1:Array):String{
            var item:* = null;
            var parameters:* = _arg1;
            parameters.sort(function (_arg1:Array, _arg2:Array):Number{
                return ((((_arg1[0] > _arg2[0])) ? 1 : -1));
            });
            var data:* = "";
            for each (item in parameters) {
                data = (data + (item[0] + item[1]));
            };
            return (data);
        }
'''
