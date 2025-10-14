import React, { useState } from "react";
const API = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export default function App(){
  const [apiKey, setApiKey] = useState("ADMIN_DEMO_KEY");
  const [logs, setLogs] = useState([]);
  const [msg, setMsg] = useState("");

  const hdrs = ()=> ({ "Content-Type":"application/json", "X-API-Key": apiKey });

  async function fetchLogs(){
    try{
      const r = await fetch(`${API}/log/list`, { headers: hdrs() });
      if(!r.ok){ setMsg("Auth/perm error"); return; }
      setLogs(await r.json());
      setMsg("Loaded");
    }catch(e){ setMsg("Network error"); }
  }

  async function writeDemo(){
    try{
      const body = { case_id:"CASE-1234", action:"note_added", details:{ note:"Called victim; awaiting documents", email:"bob@example.com", phone:"+91 9999999999" } };
      const r = await fetch(`${API}/log/write`, { method:"POST", headers: hdrs(), body: JSON.stringify(body) });
      if(!r.ok){ setMsg("Write failed"); return; }
      setMsg("Wrote entry"); fetchLogs();
    }catch(e){ setMsg("Network error"); }
  }

  async function exportLogs(mask=true, fmt="json"){
    const r = await fetch(`${API}/export/logs`, { method:"POST", headers: hdrs(), body: JSON.stringify({mask, format:fmt}) });
    if(!r.ok){ setMsg("Export denied"); return; }
    const j = await r.json();
    const blob = new Blob([j.content], {type: fmt==="csv"?"text/csv":"application/json"});
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href=url; a.download=j.filename; a.click(); URL.revokeObjectURL(url);
  }

  async function verifyChain(){
    const r = await fetch(`${API}/verify/chain`);
    const j = await r.json(); setMsg(`Chain ok=${j.ok} count=${j.count}`);
  }

  return (
    <div style={{fontFamily:"Inter, system-ui", margin:"24px"}}>
      <h1>Tamper‑Evident Audit Log</h1>
      <div style={{display:"flex", gap:8, alignItems:"center", flexWrap:"wrap"}}>
        <label>API Key:</label>
        <input value={apiKey} onChange={e=>setApiKey(e.target.value)} style={{width:280}}/>
        <button onClick={fetchLogs}>Load Logs</button>
        <button onClick={writeDemo}>Write Demo Entry</button>
        <button onClick={()=>exportLogs(true,"json")}>Export Masked JSON</button>
        <button onClick={()=>exportLogs(false,"json")}>Export Unmasked JSON</button>
        <button onClick={()=>exportLogs(true,"csv")}>Export Masked CSV</button>
        <button onClick={verifyChain}>Verify Chain</button>
        <span style={{marginLeft:12}}>{msg}</span>
      </div>
      <table width="100%" cellPadding="4" style={{marginTop:16, borderCollapse:"collapse"}}>
        <thead><tr><th>ID</th><th>TS</th><th>Actor</th><th>Action</th><th>Case</th><th>Details</th><th>Hash</th></tr></thead>
        <tbody>
          {logs.map(l=>(
            <tr key={l.id} style={{borderTop:"1px solid #ddd"}}>
              <td>{l.id}</td><td>{l.ts}</td><td>{l.actor}</td><td>{l.action}</td><td>{l.case_id}</td>
              <td><code style={{fontSize:12}}>{JSON.stringify(l.details)}</code></td>
              <td><code style={{fontSize:12}}>{l.hash.slice(0,16)}…</code></td>
            </tr>
          ))}
        </tbody>
      </table>
      <p style={{marginTop:8, color:"#666"}}>Roles: admin/auditor can export unmasked; investigator gets masked only.</p>
      <p>Demo keys: ADMIN_DEMO_KEY / AUDITOR_DEMO_KEY / INVESTIGATOR_DEMO_KEY</p>
    </div>
  );
}
