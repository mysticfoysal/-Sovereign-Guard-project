(() => {
  const C = window.CryptoScratch;
  const STORE = "sg_secure_demo_db";
  const SESSION = "sg_session";
  const MAC_KEY = "server-side-hmac-secret-kept-outside-database";
  const MASTER = { publicKey: { e: "65537", n: "2999890001" }, privateKey: { d: "2264951309", n: "2999890001" } };
  const $ = id => document.getElementById(id);
  const uid = p => p + "_" + Date.now().toString(36) + "_" + Math.floor(Math.random()*1e6).toString(36);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  let db, current = null, pending = null;

  function save(){ localStorage.setItem(STORE, JSON.stringify(db)); }
  function seal(x){ return C.RSA.encrypt(JSON.stringify(x), MASTER.publicKey); }
  function unseal(x){ return JSON.parse(C.RSA.decrypt(x, MASTER.privateKey)); }
  function active(type){ return db.keys[type].find(k => k.active); }
  function key(type,id){ return db.keys[type].find(k => k.id === id); }
  function audit(action, actor="system"){ db.audit.unshift({at:new Date().toISOString(), actor, action}); db.audit=db.audit.slice(0,25); save(); }

  function canonicalUser(u){ return JSON.stringify({id:u.id,role:u.role,fields:u.fields,salt:u.salt,hash:u.hash,otp:u.otp,rsaKeyId:u.rsaKeyId}); }
  function canonicalPost(p){ return JSON.stringify({id:p.id,owner:p.owner,fields:p.fields,eccKeyId:p.eccKeyId,created:p.created,updated:p.updated}); }
  function userMac(u){ return C.hmac(MAC_KEY, canonicalUser(u)); }
  function postMac(p){ return C.hmac(MAC_KEY, canonicalPost(p)); }
  function verifyUser(u){ return userMac(u) === u.mac; }
  function verifyPost(p){ return postMac(p) === p.mac; }

  function rotateKeys(log=true){
    db.keys.rsa.forEach(k=>k.active=false); db.keys.ecc.forEach(k=>k.active=false);
    const r=C.RSA.generate(), e=C.ECC.generate();
    db.keys.rsa.unshift({id:uid("rsa"),type:"RSA",active:true,created:new Date().toISOString(),publicKey:r.publicKey,sealedPrivate:seal(r.privateKey)});
    db.keys.ecc.unshift({id:uid("ecc"),type:"ECC",active:true,created:new Date().toISOString(),publicKey:e.publicKey,sealedPrivate:seal(e.privateKey)});
    if(log) audit("Rotated active RSA and ECC keys", current?.username || "admin");
    save();
  }
  function encUserFields(obj, rsa=active("rsa")){ const o={}; Object.entries(obj).forEach(([k,v])=>o[k]={alg:"RSA",keyId:rsa.id,c:C.RSA.encrypt(String(v),rsa.publicKey)}); return o; }
  function decUser(u){ if(!verifyUser(u)) throw Error("MAC verification failed for user record"); const out={}; Object.entries(u.fields).forEach(([k,b])=>{out[k]=C.RSA.decrypt(b.c, unseal(key("rsa",b.keyId).sealedPrivate));}); return out; }
  function encPostFields(obj, ecc=active("ecc")){ const o={}; Object.entries(obj).forEach(([k,v])=>o[k]={alg:"ECC",keyId:ecc.id,c:C.ECC.encrypt(String(v),ecc.publicKey)}); return o; }
  function decPost(p){ if(!verifyPost(p)) throw Error("MAC verification failed for post record"); const out={}; Object.entries(p.fields).forEach(([k,b])=>{out[k]=C.ECC.decrypt(b.c, unseal(key("ecc",b.keyId).sealedPrivate));}); return out; }
  function decOtp(u){ return C.RSA.decrypt(u.otp.c, unseal(key("rsa",u.otp.keyId).sealedPrivate)); }

  function createUser({name,username,email,phone,password,role}){
    if(findUser(username,true)||findUser(email,true)) throw Error("Username or email already exists");
    const rsa=active("rsa"), salt=C.randomHex(16), secret=C.randomHex(10);
    const u={id:uid("usr"),role,rsaKeyId:rsa.id,fields:encUserFields({name,username,email,phone},rsa),salt,hash:C.passwordHash(password,salt),otp:{alg:"RSA",keyId:rsa.id,c:C.RSA.encrypt(secret,rsa.publicKey)},created:new Date().toISOString()};
    u.mac=userMac(u); db.users.push(u); audit(`Registered ${role} '${username}'`); save(); return u;
  }
  function createPost(owner,title,tags,body){ const p={id:uid("post"),owner,eccKeyId:active("ecc").id,fields:encPostFields({title,tags,body}),created:new Date().toISOString(),updated:new Date().toISOString()}; p.mac=postMac(p); db.posts.unshift(p); audit("Created encrypted post", current?.username || "seed"); save(); return p; }
  function findUser(id,silent=false){ for(const u of db.users){ try{ const f=decUser(u); if(f.username.toLowerCase()===id.toLowerCase()||f.email.toLowerCase()===id.toLowerCase()) return {u,f}; }catch(e){ if(!silent)toast(e.message); } } return null; }

  function init(){
    db=JSON.parse(localStorage.getItem(STORE)||"null");
    if(!db){ db={version:1,users:[],posts:[],keys:{rsa:[],ecc:[]},audit:[]}; rotateKeys(false); const admin=createUser({name:"Sovereign Admin",username:"admin",email:"admin@sovereign.guard",phone:"01700000000",password:"Admin@12345",role:"admin"}); const user=createUser({name:"Regular User",username:"user",email:"user@sovereign.guard",phone:"01800000000",password:"User@12345",role:"user"}); createPost(user.id,"Encrypted first post","rsa,ecc,security","This social post is stored as ECC ciphertext and protected with a from-scratch HMAC tag."); audit("Seeded classroom demo accounts"); save(); }
    bind(); validateSession()?showApp("dashboard"):showAuth();
  }

  function makeSession(u,f){ const payload={uid:u.id,role:u.role,username:f.username,iat:Date.now(),exp:Date.now()+30*60*1000,nonce:C.randomHex(8)}; const body=btoa(JSON.stringify(payload)), sig=C.RSA.sign(body, MASTER.privateKey), mac=C.hmac(MAC_KEY, body+"."+sig); sessionStorage.setItem(SESSION, `${body}.${sig}.${mac}`); current={id:u.id,role:u.role,username:f.username}; audit("Session created after 2FA", f.username); }
  function validateSession(){ const t=sessionStorage.getItem(SESSION); if(!t)return false; const [body,sig,mac]=t.split("."); if(C.hmac(MAC_KEY,body+"."+sig)!==mac || !C.RSA.verify(body,sig,MASTER.publicKey))return false; const p=JSON.parse(atob(body)); if(p.exp<Date.now())return false; current={id:p.uid,role:p.role,username:p.username}; return true; }

  function toast(msg){ $("toast").textContent=msg; $("toast").classList.remove("hidden"); setTimeout(()=>$("toast").classList.add("hidden"),3500); }
  function showAuth(){ $("auth").classList.remove("hidden"); $("otp").classList.add("hidden"); $("app").classList.add("hidden"); $("nav").classList.add("hidden"); }
  function showOtp(u,f){ pending={u,f}; $("auth").classList.add("hidden"); $("otp").classList.remove("hidden"); $("otpCodeDemo").textContent=C.otp(decOtp(u)); }
  function showApp(view){ $("auth").classList.add("hidden"); $("otp").classList.add("hidden"); $("app").classList.remove("hidden"); $("nav").classList.remove("hidden"); $("who").textContent=current.username; $("role").textContent=current.role; document.querySelectorAll(".admin-only").forEach(x=>x.classList.toggle("hidden",current.role!=="admin")); switchView(view); }
  function switchView(view){ if((view==="keys"||view==="rbac")&&current.role!=="admin") return toast("RBAC denied: admin only"); document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden")); $(view).classList.remove("hidden"); document.querySelectorAll("nav button[data-view]").forEach(b=>b.classList.toggle("active",b.dataset.view===view)); $("title").textContent={dashboard:"Dashboard",posts:"Posts",profile:"Profile",storage:"Encrypted Storage",keys:"Key Management",rbac:"RBAC Admin"}[view]; render(); }
  function render(){ renderStats(); renderAudit(); renderPosts(); renderProfile(); renderStorage(); renderKeys(); renderUsers(); }
  function renderStats(){ $("userCount").textContent=db.users.length; $("postCount").textContent=db.posts.length; $("keyCount").textContent=db.keys.rsa.length+db.keys.ecc.length; const ok=db.users.every(verifyUser)&&db.posts.every(verifyPost); $("macStatus").textContent=ok?"OK":"ALERT"; $("macStatus").style.color=ok?"var(--ok)":"var(--danger)"; }
  function renderAudit(){ $("audit").innerHTML=db.audit.slice(0,current?.role==="admin"?12:5).map(a=>`<div class="log"><b>${esc(a.action)}</b><br><span class="meta">${a.at} | ${esc(a.actor)}</span></div>`).join(""); }
  function renderPosts(){ const list=current?.role==="admin"?db.posts:db.posts.filter(p=>p.owner===current?.id); $("postList").innerHTML=list.map(p=>{try{const f=decPost(p), owner=decUser(db.users.find(u=>u.id===p.owner)).username; return `<div class="post"><h4>${esc(f.title)}</h4><div class="meta">owner: ${esc(owner)} | tags: ${esc(f.tags)} | key: ${p.eccKeyId}</div><p>${esc(f.body)}</p><button class="ghost" onclick="SG.edit('${p.id}')">Edit</button> <button class="ghost" onclick="SG.del('${p.id}')">Delete</button></div>`;}catch(e){return `<div class="post"><b>Integrity alert</b><p>${esc(e.message)}</p></div>`;}}).join("")||"<p class='small'>No posts yet.</p>"; }
  function renderProfile(){ if(!current)return; const u=db.users.find(x=>x.id===current.id); try{ const f=decUser(u); $("proName").value=f.name; $("proEmail").value=f.email; $("proPhone").value=f.phone; $("profileCipher").textContent=JSON.stringify(u.fields,null,2).slice(0,1600); }catch(e){toast(e.message);} }
  function renderStorage(){ $("rawDb").textContent=JSON.stringify(db,null,2); }
  function renderKeys(){ if(current?.role!=="admin")return; $("keyList").innerHTML=[...db.keys.rsa,...db.keys.ecc].map(k=>`<div class="key"><b>${k.type}</b> ${k.active?"ACTIVE":"OLD"}<br><span class="meta">id: ${k.id}<br>created: ${k.created}<br>public: ${esc(JSON.stringify(k.publicKey))}<br>sealed private: ${k.sealedPrivate.slice(0,100)}...</span></div>`).join(""); }
  function renderUsers(){ if(current?.role!=="admin")return; $("users").innerHTML=db.users.map(u=>{try{const f=decUser(u); return `<div class="user"><b>${esc(f.username)}</b> - ${u.role}<br><span class="meta">${esc(f.email)} | MAC: ${verifyUser(u)?"OK":"FAILED"}</span></div>`;}catch(e){return `<div class="user">MAC failed: ${e.message}</div>`;}}).join(""); }

  function bind(){
    $("showLogin").onclick=()=>{ $("loginForm").classList.remove("hidden"); $("registerForm").classList.add("hidden"); $("showLogin").classList.add("active"); $("showRegister").classList.remove("active"); };
    $("showRegister").onclick=()=>{ $("registerForm").classList.remove("hidden"); $("loginForm").classList.add("hidden"); $("showRegister").classList.add("active"); $("showLogin").classList.remove("active"); };
    $("regRole").onchange=()=>$("inviteWrap").classList.toggle("hidden",$("regRole").value!=="admin");
    $("registerForm").onsubmit=e=>{e.preventDefault(); try{ if($("regRole").value==="admin"&&$("invite").value!=="SOVEREIGN-ADMIN")throw Error("Invalid admin invite code"); createUser({name:$("regName").value,username:$("regUser").value,email:$("regEmail").value,phone:$("regPhone").value,password:$("regPw").value,role:$("regRole").value}); e.target.reset(); $("showLogin").click(); toast("Account stored as RSA ciphertext with salted password hash."); }catch(err){toast(err.message);} };
    $("loginForm").onsubmit=e=>{e.preventDefault(); const found=findUser($("loginId").value.trim()); if(!found)return toast("User not found"); if(C.passwordHash($("loginPw").value,found.u.salt)!==found.u.hash)return toast("Password verification failed"); showOtp(found.u,found.f); };
    $("otpForm").onsubmit=e=>{e.preventDefault(); if($("otpCode").value.trim()!==C.otp(decOtp(pending.u)))return toast("Second factor failed"); makeSession(pending.u,pending.f); pending=null; e.target.reset(); showApp("dashboard"); };
    $("logout").onclick=()=>{sessionStorage.removeItem(SESSION);current=null;showAuth();}; document.querySelectorAll("nav button[data-view]").forEach(b=>b.onclick=()=>switchView(b.dataset.view));
    $("postForm").onsubmit=e=>{e.preventDefault(); if(!validateSession())return toast("Invalid session"); const id=$("postId").value; if(id){ const p=db.posts.find(x=>x.id===id); if(current.role!=="admin"&&p.owner!==current.id)return toast("RBAC denied"); p.fields=encPostFields({title:$("postTitle").value,tags:$("postTags").value,body:$("postBody").value}); p.eccKeyId=active("ecc").id; p.updated=new Date().toISOString(); p.mac=postMac(p); audit("Updated encrypted post",current.username); } else createPost(current.id,$("postTitle").value,$("postTags").value,$("postBody").value); save(); e.target.reset(); $("postId").value=""; $("cancelPost").classList.add("hidden"); render(); toast("Post saved as ECC ciphertext."); };
    $("cancelPost").onclick=()=>{$("postForm").reset();$("postId").value="";$("cancelPost").classList.add("hidden");};
    $("profileForm").onsubmit=e=>{e.preventDefault(); if(!validateSession())return toast("Invalid session"); const u=db.users.find(x=>x.id===current.id), f=decUser(u); u.fields=encUserFields({name:$("proName").value,username:f.username,email:$("proEmail").value,phone:$("proPhone").value}); u.rsaKeyId=active("rsa").id; u.mac=userMac(u); save(); audit("Updated encrypted profile",current.username); render(); toast("Profile re-encrypted with RSA.");};
    $("rotate").onclick=()=>{ if(current.role!=="admin")return toast("RBAC denied"); rotateKeys(true); render(); toast("Keys rotated. New writes use new public keys; old keys remain sealed for old records."); };
    $("tamper").onclick=()=>{ if(db.posts[0]){db.posts[0].fields.title.c=db.posts[0].fields.title.c.replace(/[0-9]/,"9"); save(); render(); toast("Tampering simulated. MAC status should detect the change.");} };
  }
  window.SG={edit(id){const p=db.posts.find(x=>x.id===id); if(current.role!=="admin"&&p.owner!==current.id)return toast("RBAC denied"); const f=decPost(p); $("postId").value=id; $("postTitle").value=f.title; $("postTags").value=f.tags; $("postBody").value=f.body; $("cancelPost").classList.remove("hidden"); switchView("posts");},del(id){const p=db.posts.find(x=>x.id===id); if(current.role!=="admin"&&p.owner!==current.id)return toast("RBAC denied"); db.posts=db.posts.filter(x=>x.id!==id); save(); audit("Deleted post",current.username); render();}};
  document.addEventListener("DOMContentLoaded", init);
})();
