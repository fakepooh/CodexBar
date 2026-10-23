// Trusted stdin transport, never a model tool. MOCK is compile-time test-only.
const fs=require('fs'),cp=require('child_process'),crypto=require('crypto'),http=require('http'),os=require('os');
const CLI_ARGS=/* CLI_ARGS */, MOCK=/* MOCK */, DENIAL_PROBE=/* DENIAL_PROBE */;
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function exact(n){const b=Buffer.alloc(n);let at=0;while(at<n){const k=fs.readSync(0,b,at,n-at,null);if(!k)throw Error('frame');at+=k}return b}
function readFrame(max){const h=exact(4),n=h.readUInt32BE();h.fill(0);if(n<1||n>max)throw Error('frame');return exact(n)}
function emit(type,data){console.log(JSON.stringify({type,data}))}
async function main(){
 const raw=readFrame(1048576),input=JSON.parse(raw.toString('utf8'));raw.fill(0);
 if(typeof input.prompt!=='string'||Buffer.byteLength(input.prompt)>114688||sha(input.prompt)!==input.prompt_sha256)throw Error('prompt');
 if(/(?:github_pat_[A-Za-z0-9_]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})/.test(input.prompt))throw Error('secret');
 const home='/home/copilot/.copilot';
 if(process.env.COPILOT_HOME!==home||process.env.COPILOT_MODEL||process.env.COPILOT_AGENT_MODEL||
    (fs.existsSync(home)&&fs.readdirSync(home).length))throw Error('settings');
 const env={...process.env};let secret='',server=null,requests=0,mockReceipts=[];
 if(MOCK){
  if(!Object.values(os.networkInterfaces()).flat().every(x=>x.internal))throw Error('network');
  for(const name of Object.keys(env))if(/TOKEN|SECRET|API_KEY/.test(name))throw Error('credential');
  const sentinel='OFFLINE_PRIVATE_SENTINEL_745c0b';
  if(DENIAL_PROBE)fs.writeFileSync('/home/copilot/probe-private.txt',sentinel,{mode:0o600});
  server=http.createServer((req,res)=>{
   if(req.method==='GET'&&req.url==='/v1/models'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({object:'list',data:[{id:'offline-transport-stub',object:'model',owned_by:'offline-stub'}]}));return}
   if(req.method!=='POST'||req.url!=='/v1/chat/completions'){res.writeHead(404);res.end();return}
   requests++;if(requests>(DENIAL_PROBE?2:1)){res.writeHead(429);res.end();return}
   let chunks=[],size=0;
   req.on('data',b=>{size+=b.length;if(size>2097152)req.destroy();else chunks.push(b)});
   req.on('end',()=>{
    try{
     const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
     const user=(body.messages||[]).filter(x=>x.role==='user').flatMap(x=>typeof x.content==='string'?[x.content]:(x.content||[]).filter(y=>y.type==='text').map(y=>y.text));
     const exactPrompt=user.some(x=>x===input.prompt),embedded=user.some(x=>x.includes(input.prompt));
     const received=user.find(x=>x.includes(input.prompt));
     const delivered=received?received.slice(received.indexOf(input.prompt),received.indexOf(input.prompt)+input.prompt.length):null;
     const evidence=delivered?JSON.parse(delivered.split('HISTORICAL_EVIDENCE_JSON\n')[1]):null;
     const toolResults=(body.messages||[]).filter(x=>x.role==='tool').map(x=>typeof x.content==='string'?x.content:JSON.stringify(x.content)).join('\n');
     mockReceipts.push({request_number:requests,endpoint:'loopback-stub',method:'POST',path:req.url,
       received_model:body.model,received_prompt_sha256:delivered?sha(delivered):null,
       source_pages:(evidence?.source_pages||[]).map(page=>({path:page.path,side:page.side,commit:page.commit,blob_oid:page.blob_oid,page:page.page,line_start:page.line_start,line_end:page.line_end,content_sha256:sha(page.content)})),
       exact_user_text:exactPrompt,unmodified_prompt_present:embedded,request_bytes:size,
       authentication_header_present:!!req.headers.authorization,
       denial_probe:DENIAL_PROBE,private_sentinel_leaked:toolResults.includes(sentinel),
       read_permission_denied:!!toolResults&&/denied|not permitted|not allowed|permission/i.test(toolResults),
       tools:(body.tools||[]).map(x=>x.function?.name||x.name)});
     const text=JSON.stringify({offline_stub:true,findings:[],not_a_benchmark:true});
     res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache'});
     const requestTool=DENIAL_PROBE&&requests===1;
     const deltas=requestTool?[{role:'assistant',tool_calls:[{index:0,id:'offline-read-denial',type:'function',function:{name:'view',arguments:JSON.stringify({path:'/home/copilot/probe-private.txt'})}}]}]:[{role:'assistant',content:''},{content:text}];
     for(const chunk of deltas)res.write('data: '+JSON.stringify({id:'offline-stub',object:'chat.completion.chunk',created:0,model:'offline-transport-stub',choices:[{index:0,delta:chunk,finish_reason:null}]})+'\n\n');
     res.write('data: '+JSON.stringify({id:'offline-stub',object:'chat.completion.chunk',created:0,model:'offline-transport-stub',choices:[{index:0,delta:{},finish_reason:requestTool?'tool_calls':'stop'}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}})+'\n\n');
     res.end('data: [DONE]\n\n');
    }catch{res.writeHead(400);res.end()}
   });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  Object.assign(env,{COPILOT_OFFLINE:'true',COPILOT_PROVIDER_TYPE:'openai',COPILOT_PROVIDER_BASE_URL:'http://127.0.0.1:'+server.address().port+'/v1',COPILOT_PROVIDER_WIRE_API:'completions',COPILOT_PROVIDER_MODEL_ID:'offline-transport-stub',COPILOT_PROVIDER_WIRE_MODEL:'offline-transport-stub',COPILOT_PROVIDER_MAX_PROMPT_TOKENS:'131072',COPILOT_PROVIDER_MAX_OUTPUT_TOKENS:'4096'});
 }else{
  const token=readFrame(1024);if(!/^github_pat_[A-Za-z0-9_]+$/.test(token.toString('ascii')))throw Error('credential');
  secret=token.toString('ascii');token.fill(0);env.COPILOT_GITHUB_TOKEN=secret;
 }
 emit('v2.transport_prepared',{prompt_sha256:input.prompt_sha256,prompt_bytes:Buffer.byteLength(input.prompt),channel:'initial_user_prompt',mock:MOCK,requested_selection:MOCK?'offline-stub-only':'auto',settings_model:null,environment_model:null,home_empty:true});
 const child=cp.spawn('/usr/local/bin/copilot',[...CLI_ARGS,'-p',input.prompt],{env,stdio:['ignore','pipe','pipe'],shell:false});
 delete env.COPILOT_GITHUB_TOKEN;
 let stdout=[],stderr=[],bytes=0,timedOut=false;
 const collect=target=>b=>{bytes+=b.length;if(bytes>8388608)child.kill('SIGKILL');else target.push(b)};
 child.stdout.on('data',collect(stdout));child.stderr.on('data',collect(stderr));
 const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},MOCK?45000:600000);
 const code=await new Promise(resolve=>{child.once('error',()=>resolve(73));child.once('close',c=>resolve(Number.isInteger(c)?c:1))});clearTimeout(timer);
 function scrub(s){if(secret)s=s.split(secret).join('[REDACTED]');return s.replace(/\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+/g,'[REDACTED]')}
 process.stdout.write(scrub(Buffer.concat(stdout).toString('utf8')));process.stderr.write(scrub(Buffer.concat(stderr).toString('utf8')));secret='';
 const usage='/home/copilot/v2-usage.json';
 if(fs.existsSync(usage)&&fs.statSync(usage).size<=1048576){try{emit('v2.captured_usage',JSON.parse(fs.readFileSync(usage,'utf8')))}catch{emit('v2.usage_error',{sanitized:true})}}
 if(server){server.close();emit('v2.mock_endpoint',{requests,receipts:mockReceipts,real_model_requests:0})}
 emit('v2.transport_finished',{cli_exit_code:code,timed_out:timedOut,mock:MOCK,automatic_retry:false});
 process.exitCode=code;
}
main().catch(()=>{emit('v2.transport_rejected',{sanitized:true});process.exitCode=70});
