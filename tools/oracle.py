#!/usr/bin/env python3
"""Independent raw-byte Gecko oracle through standard WebDriver, not Lizard DOM.

Uses a pinned stock Firefox binary; never rewrites or serializes the HTML before
loading it. JavaScript is only used by WebDriver to inspect the rendered tree.
"""
import argparse,base64,hashlib,json,os,pathlib,socket,subprocess,time,urllib.request

ORACLE_CODE_SHA256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
def environment_fingerprint():
    files={}
    for directory in ['/usr/share/fonts/truetype/dejavu','/usr/share/fonts/truetype/liberation','/usr/share/fonts/truetype/liberation2']:
        for path in sorted(pathlib.Path(directory).glob('*.ttf')):files[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(pathlib.Path('/usr/lib/x86_64-linux-gnu').glob('libfreetype.so.*')):
        files[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps({'files':files,'fontconfig':{key:os.environ.get(key)for key in ['FONTCONFIG_FILE','FONTCONFIG_PATH','FREETYPE_PROPERTIES']}},sort_keys=True).encode()).hexdigest()
ORACLE_ENVIRONMENT=environment_fingerprint()

class Gecko:
    def __init__(self,firefox,driver,output):
        self.output=pathlib.Path(output);self.output.mkdir(parents=True,exist_ok=True)
        self.firefox=str(pathlib.Path(firefox).resolve())
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        self.base=f'http://127.0.0.1:{port}';self.session=None
        self.log=(self.output/'geckodriver.log').open('w')
        env=os.environ.copy();env.update(MOZ_HEADLESS='1')
        self.proc=subprocess.Popen([str(pathlib.Path(driver).resolve()),'--host','127.0.0.1','--port',str(port),'--log','error'],stdout=self.log,stderr=self.log,env=env)
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(200):
            try:self.call('GET','/status');break
            except Exception:
                if self.proc.poll() is not None:raise RuntimeError('geckodriver exited; see log')
                time.sleep(.05)
        prefs={'gfx.webrender.software':True,'gfx.webrender.software.opengl':False,
            'gfx.webrender.all':True,'gfx.color_management.mode':0,
            'layout.css.devPixelsPerPx':'1.0','browser.display.use_document_fonts':1,
            'font.name.serif.x-western':'DejaVu Serif','font.name.sans-serif.x-western':'DejaVu Sans',
            'font.name.monospace.x-western':'DejaVu Sans Mono','font.size.variable.x-western':16,
            'javascript.enabled':False,'network.proxy.type':1,'network.proxy.http':'127.0.0.1',
            'network.proxy.http_port':9,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':9,
            'network.proxy.no_proxies_on':'','toolkit.telemetry.enabled':False,
            'datareporting.healthreport.uploadEnabled':False,'app.update.auto':False,
            'browser.shell.checkDefaultBrowser':False,'browser.startup.homepage':'about:blank'}
        value=self.call('POST','/session',{'capabilities':{'alwaysMatch':{'browserName':'firefox','webSocketUrl':True,
            'moz:firefoxOptions':{'binary':self.firefox,'args':['-headless'],'prefs':prefs}}}})
        self.session=value['sessionId'];self.capabilities=value['capabilities']
        if self.capabilities['browserVersion']!='160.0' or self.capabilities.get('moz:buildID')!='20261104181552':raise RuntimeError('Oracle must use the pinned Firefox 160.0 build')
        from websockets.sync.client import connect
        self.ws=connect(self.capabilities['webSocketUrl'],proxy=None);self.bidi_id=0
        (self.output/'oracle-capabilities.json').write_text(json.dumps(self.capabilities,indent=2)+'\n')
    def call(self,method,path,data=None):
        body=None if data is None else json.dumps(data).encode()
        req=urllib.request.Request(self.base+path,data=body,method=method,headers={'Content-Type':'application/json'})
        with self.http.open(req,timeout=45) as response:value=json.load(response)['value']
        if isinstance(value,dict) and 'error' in value:raise RuntimeError(value)
        return value
    def command(self,path,data=None,method='POST'):return self.call(method,'/session/'+self.session+path,data)
    def js(self,script,args=None):return self.command('/execute/sync',{'script':script,'args':args or []})
    def bidi(self,method,params):
        self.bidi_id+=1;self.ws.send(json.dumps({'id':self.bidi_id,'method':method,'params':params}))
        while True:
            msg=json.loads(self.ws.recv(timeout=30))
            if msg.get('id')==self.bidi_id:
                if msg.get('type')=='error':raise RuntimeError(msg)
                return msg.get('result')
    def capture(self,path,width,height,out):
        source=pathlib.Path(path).read_bytes();out=pathlib.Path(out)
        context=self.command('/window',method='GET')
        self.bidi('browsingContext.setViewport',{'context':context,'viewport':{'width':width,'height':height},'devicePixelRatio':1})
        self.command('/url',{'url':pathlib.Path(path).resolve().as_uri()})
        state=self.js('return {w:innerWidth,h:innerHeight};')
        if state!={'w':width,'h':height}:raise RuntimeError(('viewport mismatch',state,width,height))
        # Deterministic local resources. Poll decoded images, then flush layout.
        for _ in range(100):
            if self.js('return Array.from(document.images).every(i=>i.complete);'):break
            time.sleep(.02)
        trace=self.js('''
        const props=['display','color','background-color','font-family','font-size','font-weight','line-height','width','height','margin-top','margin-right','margin-bottom','margin-left','padding-top','padding-right','padding-bottom','padding-left','direction','white-space'];
        const nodes=[];
        function walk(n,parent){if(![1,3,8,9].includes(n.nodeType))return;const id=nodes.length;
          const entry={id,parent,kind:n.nodeType,tag:n.nodeType===1?n.localName:'',text:n.nodeType===3||n.nodeType===8?n.data:'',attrs:n.nodeType===1?Array.from(n.attributes,a=>[a.localName,a.value]):[],children:[]};nodes.push(entry);
          if(n.nodeType===1){const r=n.getBoundingClientRect(),s=getComputedStyle(n);entry.rect={x:r.x,y:r.y,w:r.width,h:r.height};entry.style=Object.fromEntries(props.map(p=>[p,s.getPropertyValue(p)]));}
          for(const child of n.childNodes){const next=nodes.length;walk(child,id);if(nodes.length>next)entry.children.push(next);}
        }walk(document,null);return {nodes,width:innerWidth,height:innerHeight,scrollHeight:document.documentElement.scrollHeight};''')
        trace['source_sha256']=hashlib.sha256(source).hexdigest()
        trace['browser']=self.capabilities['browserVersion']
        trace['oracle_code_sha256']=ORACLE_CODE_SHA256
        trace['environment_fingerprint']=ORACLE_ENVIRONMENT
        trace['build_id']=self.capabilities.get('moz:buildID')
        out.with_suffix('.json').write_text(json.dumps(trace,ensure_ascii=False,indent=2)+'\n')
        image=self.command('/screenshot',method='GET')
        out.with_suffix('.png').write_bytes(base64.b64decode(image))
        assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==trace['source_sha256']
        return trace
    def close(self):
        if hasattr(self,'ws'):self.ws.close()
        if self.session:
            try:self.command('',method='DELETE')
            except Exception:pass
        self.proc.terminate()
        try:self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
        self.log.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('input');parser.add_argument('output');parser.add_argument('--firefox',required=True);parser.add_argument('--geckodriver',required=True);parser.add_argument('--width',type=int,default=800);parser.add_argument('--height',type=int,default=600);args=parser.parse_args()
    oracle=Gecko(args.firefox,args.geckodriver,pathlib.Path(args.output).parent)
    try:
        result=oracle.capture(args.input,args.width,args.height,args.output);print(json.dumps({'browser':result['browser'],'source_sha256':result['source_sha256'],'nodes':len(result['nodes'])}))
    finally:oracle.close()
