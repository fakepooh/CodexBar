// Offline-only receiver audit. Prepended to the UNCHANGED frozen mock sender.
// The ephemeral MAC key is read privately from stdin, never sent to the CLI.
(function () {
 const fs=require('fs'), crypto=require('crypto'), http=require('http'), os=require('os');
 const epoch=process.hrtime.bigint();
 const timing=stage=>process.stderr.write(JSON.stringify({type:'attestation.timing',stage,
  elapsed_ms:Number(process.hrtime.bigint()-epoch)/1000000})+'\n');
 timing('wrapper_started');
 if(!Object.values(os.networkInterfaces()).flat().every(x=>x.internal))throw Error('offline only');
 const exact=n=>{const b=Buffer.alloc(n);let at=0;while(at<n){const k=fs.readSync(0,b,at,n-at,null);if(!k)throw Error('audit frame');at+=k}return b};
 const n=exact(4).readUInt32BE();if(n>524288||n<1)throw Error('audit size');
 const raw=exact(n), config=JSON.parse(raw.toString());raw.fill(0);
 timing('audit_frame_read');
 const keyBytes=Buffer.from(config.key,'hex');delete config.key;
 if(keyBytes.length!==32)throw Error('audit key');
 const key=crypto.createSecretKey(keyBytes);keyBytes.fill(0);
 const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
 const root='/opt/copilot-pkg-cache/pkg/linux-arm64/1.0.98/';
 const native=require(root+'prebuilds/linux-arm64/runtime.node');
 timing('native_loaded');
 if(sha(fs.readFileSync(root+'cli-main.js'))!=='151c2e2a37ddb2514fc5cdbd5c473f9aeeb1a74d59e5062f3921a46d12a8f1c2')throw Error('pinned CLI');
 // Forward filtering by the actual pinned native serializer, never unmasking.
 const filtered=text=>JSON.parse(native.processSecretFilterFilterJsonString(JSON.stringify({content:text}))).content;
 const cp=require('child_process'),spawn=cp.spawn;
 cp.spawn=function(...args){timing('cli_spawn_requested');
  if(config.fault==='corrupt'){
   if(args[0]!=='/usr/local/bin/copilot')throw Error('fault scope');
   args[1]=args[1].slice();const i=args[1].indexOf('-p');
   if(i<0||args[1][i+1]!==config.prompt)throw Error('fault input');
   args[1][i+1]='!'+config.prompt.slice(1);
  }
  const child=spawn.apply(cp,args);
  child.once('spawn',()=>timing('cli_spawned'));child.once('close',()=>timing('cli_closed'));return child};
 let requests=0;
 const create=http.createServer;
 http.createServer=function(listener){return create.call(http,(req,res)=>{
  res.once('finish',()=>timing('http_response_finished'));
  if(req.method==='POST'){
   timing('http_post_received');
   let chunks=[],bytes=0,oversized=false;requests++;
   req.on('data',chunk=>{bytes+=chunk.length;if(bytes>2097152)oversized=true;else chunks.push(chunk)});
   req.on('end',()=>{
    timing('http_body_complete');
    let data={version:'source-delivery-attestation-v1.0.0',nonce:config.nonce,
     freeze_sha256:config.freeze_sha256,request_number:requests,
     method:req.method,path:req.url,authenticated_header_present:!!req.headers.authorization,
     wire_bytes:bytes,wire_sha256:sha(Buffer.concat(chunks)),complete:false};
    try{
     if(oversized)throw Error('oversize');
     const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
     const users=(body.messages||[]).filter(x=>x.role==='user').flatMap(x=>typeof x.content==='string'?[x.content]:(x.content||[]).filter(x=>x.type==='text').map(x=>x.text));
     const matches=users.filter(x=>x.includes(config.prompt));
     if(matches.length!==1||matches[0].split(config.prompt).length!==2)throw Error('exact payload missing');
     // Hash actual received bytes, not the expected input/metadata.
     const start=matches[0].indexOf(config.prompt), delivered=matches[0].slice(start,start+config.prompt.length);
     const evidence=JSON.parse(delivered.split('\n\nHISTORICAL_EVIDENCE_JSON\n')[1]);
     Object.assign(data,{complete:true,prompt_sha256:sha(delivered),prompt_bytes:Buffer.byteLength(delivered),
      pages:evidence.source_pages.map(({content,...meta})=>({...meta,content_sha256:sha(content)})),
      canonical_telemetry_sha256:sha(filtered(config.prompt)),
      transformed_telemetry_sha256:sha(filtered(matches[0])),
      native_filter_sha256:sha(fs.readFileSync(root+'prebuilds/linux-arm64/runtime.node')),
      tools:(body.tools||[]).map(x=>x.function?.name||x.name)});
     timing('native_redaction_complete');
    }catch{data.complete=false}
    // Sign the exact serialized data bytes; base64 prevents ambiguous JSON canonicalization.
    const payload=Buffer.from(JSON.stringify(data));
    console.log(JSON.stringify({type:'attestation.receiver',data:{payload:payload.toString('base64'),
     mac:crypto.createHmac('sha256',key).update(payload).digest('hex')}}));
    timing('receiver_receipt_emitted');
   });
  }
  if(config.fault==='no_response'&&req.method==='POST')return;
  return listener(req,res);
 })};
})();
