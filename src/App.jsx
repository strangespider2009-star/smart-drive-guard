import React, { useEffect, useState } from "react";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";

const api = async (url, options = {}) => {
  const res = await fetch(url, { credentials: "include", ...options, headers: options.body instanceof FormData ? options.headers : { "Content-Type": "application/json", ...(options.headers || {}) } });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
};
const post = (url, body) => api(url, { method: "POST", body: JSON.stringify(body) });

export default function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [menu, setMenu] = useState(false);
  const [data, setData] = useState({ vehicles: [], drivers: [], biometrics: [], logs: [] });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const me = await api("/api/me"); setUser(me.user);
    if (me.user) setData(await api("/api/dashboard"));
  }
  useEffect(() => { refresh().catch(e => setError(e.message)); }, []);
  async function act(fn) {
    setError(""); setNotice(""); setBusy(true);
    try { await fn(); await refresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  if (!user) return <Auth onDone={refresh} />;
  const nav = [
    ["dashboard", "Dashboard", "▦"], ["vehicles", "My Vehicle", "🚘"],
    ["drivers", "Manage Drivers", "♙"], ["family", "Family Members", "♧"],
    ["biometrics", "Manage Dummy Biometrics", "◎"], ["history", "Access History", "◷"]
  ];
  return <div className="shell">
    <header className="topbar">
      <button className="menuBtn" onClick={() => setMenu(!menu)}>☰</button>
      <div className="brand"><span className="brandMark">SG</span><span>SMART DRIVE <b>GUARD</b></span></div>
      <div className="topRight"><span className="userTag">{user.name} · {user.role}</span><button className="ghost" onClick={() => act(async () => {
        const options = await post("/api/passkey/register-options", {});
        const credential = await startRegistration({ optionsJSON: options });
        await post("/api/passkey/register-verify", credential);
        setNotice("Passkey registered on this device.");
      })}>Register passkey</button><button className="ghost" onClick={() => act(async () => { await post("/api/auth/logout", {}); setUser(null); })}>Logout</button></div>
    </header>
    {menu && <div className="drawerBackdrop" onClick={() => setMenu(false)}><aside className="drawer" onClick={e => e.stopPropagation()}><h3>Navigation</h3>{nav.map(n => <button key={n[0]} className={page===n[0]?"navItem active":"navItem"} onClick={() => {setPage(n[0]);setMenu(false);}}>{n[2]}　{n[1]}</button>)}</aside></div>}
    <main className="main">
      <div className="welcome"><div><div className="eyebrow">VEHICLE ACCESS MANAGEMENT</div><h1>{nav.find(n=>n[0]===page)?.[1] || "Dashboard"}</h1><p>Manage authorised drivers and demonstration verification.</p></div><span className="online"><i/> SYSTEM ONLINE</span></div>
      {error && <div className="alert error">{error}</div>}{notice && <div className="alert success">{notice}</div>}
      {page==="dashboard" && <Dashboard data={data} user={user} setPage={setPage} />}
      {page==="vehicles" && <Vehicles data={data} act={act} />}
      {page==="drivers" && <Drivers data={data} act={act} kind="driver" />}
      {page==="family" && <Drivers data={data} act={act} kind="family" />}
      {page==="biometrics" && <Biometrics data={data} act={act} />}
      {page==="history" && <History data={data} />}
      {page==="verify" && <Verify data={data} act={act} setNotice={setNotice} />}
      <footer>SMART DRIVE GUARD · Educational prototype · Not for controlling a real vehicle</footer>
    </main>
  </div>;
}

function Auth({ onDone }) {
  const [mode,setMode]=useState("register"), [name,setName]=useState("Demo Owner"), [email,setEmail]=useState("owner@example.com"), [password,setPassword]=useState("DemoPass123!"), [role,setRole]=useState("owner"), [error,setError]=useState(""), [busy,setBusy]=useState(false);
  async function submit(e) {
    e.preventDefault(); setError(""); setBusy(true);
    try {
      const url=mode==="register"?"/api/auth/register":"/api/auth/login";
      await post(url, mode==="register"?{name,email,password,role}:{email,password});
      await onDone();
    } catch(e) {setError(e.message);} finally {setBusy(false);}
  }
  async function passkeyLogin() {
    setError(""); setBusy(true);
    try {
      const options=await post("/api/passkey/auth-options",{email});
      const response=await startAuthentication({optionsJSON:options});
      await post("/api/passkey/auth-verify",response);
      await onDone();
    } catch(e) {setError(e.message || "Passkey login failed.");} finally {setBusy(false);}
  }
  return <div className="authPage"><div className="authCard"><div className="logoLarge">SG</div><div className="eyebrow center">SMART DRIVE GUARD</div><h1>{mode==="register"?"Create your account":"Welcome back"}</h1><p className="muted">Secure vehicle access management</p>
    <form onSubmit={submit}>
      {mode==="register" && <><label>Full name<input value={name} onChange={e=>setName(e.target.value)} required /></label><label>Account type<select value={role} onChange={e=>setRole(e.target.value)}><option value="owner">Vehicle owner</option><option value="driver">Driver</option></select></label></>}
      <label>Email address<input type="email" value={email} onChange={e=>setEmail(e.target.value)} required /></label>
      <label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} minLength="8" required /></label>
      {error && <div className="alert error">{error}</div>}
      <button className="primary full" disabled={busy}>{busy?"Please wait…":mode==="register"?"Create account":"Sign in"}</button>
    </form>
    <button className="secondary full" disabled={busy} onClick={passkeyLogin}>Sign in with passkey / device biometrics</button>
    <p className="switch">{mode==="register"?"Already registered?":"New to Smart Drive Guard?"} <button onClick={()=>setMode(mode==="register"?"login":"register")}>{mode==="register"?"Sign in":"Create account"}</button></p>
    <small className="muted">Passkeys require HTTPS (or localhost) and a compatible device/browser. Register a passkey after signing in.</small>
  </div></div>;
}

function Dashboard({data,user,setPage}) {
  return <><div className="stats"><Stat n={data.vehicles.length} label="Vehicles"/><Stat n={data.drivers.length} label="Drivers & family"/><Stat n={data.biometrics.length} label="Dummy profiles"/><Stat n={data.logs.filter(x=>x.accessGranted).length} label="Demo approvals"/></div>
    <div className="grid2"><section className="panel heroPanel"><div className="eyebrow">ACCESS CONTROL</div><h2>Verification overview</h2><p className="muted">Three independent conditions are evaluated for the exhibition prototype.</p><div className="logic"><span>BIOMETRIC</span><b>AND</b><span>LICENCE</span><b>AND</b><span>OWNER APPROVAL</span></div><button className="primary" onClick={()=>setPage("verify")}>Open verification demo</button></section>
    <section className="panel"><h2>Quick actions</h2><div className="quick"><button onClick={()=>setPage("vehicles")}>＋ Add vehicle</button><button onClick={()=>setPage("drivers")}>＋ Add driver</button><button onClick={()=>setPage("family")}>＋ Add family member</button><button onClick={()=>setPage("biometrics")}>◎ Manage dummy biometrics</button></div></section></div>
    <section className="panel"><h2>Recent activity</h2>{data.logs.length?data.logs.slice(0,5).map(l=><div className="listRow" key={l.id}><span>{l.accessGranted?"✓":"×"}　Access check</span><span className={l.accessGranted?"good":"bad"}>{l.accessGranted?"GRANTED":"DENIED"}</span></div>):<p className="muted">No verification events yet.</p>}</section>
  </>;
}
function Stat({n,label}) {return <div className="stat"><strong>{n}</strong><span>{label}</span></div>;}

function Vehicles({data,act}) {
  const [vehicleName,setName]=useState("Demo Car"),[registration,setReg]=useState("DEMO-001");
  return <div className="grid2"><section className="panel"><h2>Register vehicle</h2><form onSubmit={e=>{e.preventDefault();act(()=>post("/api/vehicles",{vehicleName,registration}));}}><label>Vehicle name<input value={vehicleName} onChange={e=>setName(e.target.value)} required/></label><label>Registration (demo)<input value={registration} onChange={e=>setReg(e.target.value)}/></label><button className="primary">Add vehicle</button></form></section><section className="panel"><h2>My vehicles</h2>{data.vehicles.map(v=><div className="listRow" key={v.id}><span><b>{v.vehicleName}</b><small>{v.registration} · {v.bluetoothName}</small></span><span className="pill">Registered</span></div>)}{!data.vehicles.length&&<p className="muted">No vehicles added.</p>}</section></div>;
}

function Drivers({data,act,kind}) {
  const [form,setForm]=useState({name:"",email:"",phone:"",licenceNumber:"",expiryDate:"",relationship:"",biometricProfileId:"",vehicleId:"",kind});
  const change=e=>setForm({...form,[e.target.name]:e.target.value});
  async function submit(e) {
    e.preventDefault(); const fd=new FormData(); Object.entries(form).forEach(([k,v])=>fd.append(k,v));
    const file=e.target.licence.files[0]; if(file)fd.append("licence",file);
    await act(()=>api("/api/drivers",{method:"POST",body:fd}));
    setForm({...form,name:"",email:"",phone:"",licenceNumber:"",expiryDate:""});
    e.target.reset();
  }
  const list=data.drivers.filter(d=>d.kind===kind);
  return <div className="grid2"><section className="panel"><h2>{kind==="family"?"Add family member":"Add authorised driver"}</h2><form onSubmit={submit}>
    <label>Full name<input name="name" value={form.name} onChange={change} required/></label><label>Email<input name="email" type="email" value={form.email} onChange={change}/></label><label>Phone (optional)<input name="phone" value={form.phone} onChange={change}/></label>
    {kind==="family"&&<label>Relationship<input name="relationship" value={form.relationship} onChange={change} placeholder="e.g. Parent, sibling"/></label>}
    <label>Driving licence number (demo)<input name="licenceNumber" value={form.licenceNumber} onChange={change} required/></label><label>Licence expiry date<input type="date" name="expiryDate" value={form.expiryDate} onChange={change} required/></label>
    <label>Vehicle<select name="vehicleId" value={form.vehicleId} onChange={change} required><option value="">Select vehicle</option>{data.vehicles.map(v=><option value={v.id} key={v.id}>{v.vehicleName}</option>)}</select></label>
    <label>Dummy biometric profile<select name="biometricProfileId" value={form.biometricProfileId} onChange={change}><option value="">Select profile</option>{data.biometrics.map(b=><option value={b.id} key={b.id}>{b.profileName}</option>)}</select></label>
    <label>Licence file (sample only)<input type="file" name="licence" accept=".pdf,.png,.jpg,.jpeg"/></label>
    <button className="primary">Submit for owner approval</button>
  </form></section><section className="panel"><h2>{kind==="family"?"Family members":"Drivers"} ({list.length})</h2>{list.map(d=><div className="person" key={d.id}><div><b>{d.name}</b><small>{d.licenceNumber} · Expires {d.expiryDate}</small><span className="pill">{d.status}</span></div><div className="actions"><button className="mini goodBtn" onClick={()=>act(()=>api(`/api/drivers/${d.id}/approval`,{method:"PATCH",body:JSON.stringify({approved:true})}))}>Approve</button><button className="mini dangerBtn" onClick={()=>act(()=>api(`/api/drivers/${d.id}/approval`,{method:"PATCH",body:JSON.stringify({approved:false})}))}>Reject</button><button className="mini" onClick={()=>act(()=>api(`/api/drivers/${d.id}`,{method:"DELETE"}))}>Delete</button></div></div>)}{!list.length&&<p className="muted">No records yet.</p>}</section></div>;
}

function Biometrics({data,act}) {
  const [profileName,setName]=useState("Demo Biometric 01"),[fp,setFp]=useState(true),[face,setFace]=useState(true),[match,setMatch]=useState(true);
  return <div className="grid2"><section className="panel"><h2>Add dummy biometric profile</h2><p className="muted">These are simulated flags for your project demonstration, not actual biometric templates.</p><form onSubmit={e=>{e.preventDefault();act(()=>post("/api/biometrics",{profileName,fingerprintRegistered:fp,faceRegistered:face,simulatedMatch:match}));}}><label>Profile name<input value={profileName} onChange={e=>setName(e.target.value)} required/></label><label className="check"><input type="checkbox" checked={fp} onChange={e=>setFp(e.target.checked)}/> Fingerprint marked registered</label><label className="check"><input type="checkbox" checked={face} onChange={e=>setFace(e.target.checked)}/> Face marked registered</label><label className="check"><input type="checkbox" checked={match} onChange={e=>setMatch(e.target.checked)}/> Simulated match passes</label><button className="primary">Save dummy profile</button></form></section><section className="panel"><h2>Manage profiles</h2>{data.biometrics.map(p=><div className="person" key={p.id}><div><b>{p.profileName}</b><small>Fingerprint: {p.fingerprintRegistered?"Yes":"No"} · Face: {p.faceRegistered?"Yes":"No"} · Match: {p.simulatedMatch?"Pass":"Fail"}</small><span className="pill">{p.status}</span></div><div className="actions"><button className="mini" onClick={()=>act(()=>api(`/api/biometrics/${p.id}`,{method:"PATCH",body:JSON.stringify({status:p.status==="active"?"disabled":"active"})}))}>{p.status==="active"?"Disable":"Enable"}</button><button className="mini dangerBtn" onClick={()=>act(()=>api(`/api/biometrics/${p.id}`,{method:"DELETE"}))}>Delete</button></div></div>)}{!data.biometrics.length&&<p className="muted">No dummy profiles created.</p>}</section></div>;
}

function Verify({data,act,setNotice}) {
  const [vehicleId,setVehicle]=useState(data.vehicles[0]?.id||""),[driverId,setDriver]=useState(""),[localBio,setBio]=useState(false),[result,setResult]=useState(null);
  async function run() { await act(async()=>{const r=await post("/api/access/check",{vehicleId,driverId,localBiometricPassed:localBio});setResult(r);setNotice(r.accessGranted?"Demo verification passed.":"Demo verification denied.");});}
  return <section className="panel"><h2>Verification demonstration</h2><p className="muted">This page evaluates sample records and a local user-confirmed test flag. It does not verify a real driving licence or unlock a real vehicle.</p><label>Vehicle<select value={vehicleId} onChange={e=>setVehicle(e.target.value)}><option value="">Select vehicle</option>{data.vehicles.map(v=><option value={v.id} key={v.id}>{v.vehicleName}</option>)}</select></label><label>Driver<select value={driverId} onChange={e=>setDriver(e.target.value)}><option value="">Select driver</option>{data.drivers.map(d=><option value={d.id} key={d.id}>{d.name}</option>)}</select></label><label className="check"><input type="checkbox" checked={localBio} onChange={e=>setBio(e.target.checked)}/> Simulate successful local biometric prompt</label><button className="primary" disabled={!vehicleId||!driverId} onClick={run}>Run verification</button>
    {result&&<div className="result"><h3>{result.accessGranted?"ACCESS GRANTED":"ACCESS DENIED"}</h3>{["Biometric","Licence","Owner approval"].map((x,i)=><div className="listRow" key={x}>{x}<b className={result.logic[i]?"good":"bad"}>{result.logic[i]?"PASS":"FAIL"}</b></div>)}<p className="muted">Logic: A AND B AND C</p></div>}
  </section>;
}
function History({data}) {return <section className="panel"><h2>Access history</h2>{data.logs.map(l=><div className="listRow" key={l.id}><span>{new Date(l.createdAt).toLocaleString()}</span><b className={l.accessGranted?"good":"bad"}>{l.accessGranted?"GRANTED":"DENIED"}</b></div>)}{!data.logs.length&&<p className="muted">No access history yet.</p>}</section>;}
