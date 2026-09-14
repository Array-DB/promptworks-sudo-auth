export class PromptWorksAuth {
  constructor({baseUrl,clientKey}) {
    if (!baseUrl?.startsWith('https://') && !baseUrl?.startsWith('http://127.0.0.1') && !baseUrl?.startsWith('http://localhost')) throw new Error('PromptWorks remote baseUrl must use HTTPS');
    if (!clientKey) throw new Error('clientKey is required');
    this.baseUrl=baseUrl.replace(/\/$/,'');this.clientKey=clientKey;
  }
  async call(path,opt={}) {
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),10000);
    try {
      const r=await fetch(this.baseUrl+path,{...opt,signal:controller.signal,headers:{'content-type':'application/json',authorization:`Bearer ${this.clientKey}`,...opt.headers}});
      const b=await r.json().catch(()=>({}));if(!r.ok)throw Error(`PromptWorks ${r.status}: ${JSON.stringify(b)}`);return b;
    } finally { clearTimeout(timer); }
  }
  createRequest({userId,service,device='Browser',location='Unknown',action='',ttlSeconds=60}) {
    return this.call('/v1/auth/requests',{method:'POST',body:JSON.stringify({userId,service,device,location,action,ttlSeconds})});
  }
  getRequest(id){return this.call('/v1/auth/requests/'+encodeURIComponent(id));}
  async waitForDecision(id,{timeoutMs=65000,pollMs=1000}={}){const end=Date.now()+timeoutMs;while(Date.now()<end){const r=await this.getRequest(id);if(r.status!=='pending')return r;await new Promise(x=>setTimeout(x,pollMs));}return{id,status:'timeout'};}
}
