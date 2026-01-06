// static/app.js
const STATE = {
  outDir: "out_runs_b/7a",
  topnRaw: [],
  topnMode: "urls", // urls|domains|keywords
  lastNeedle: "",
  lastCtx: null,
  lastMitre: null,
};

function qs(id){ return document.getElementById(id); }
function setStatus(s){ qs("status").textContent = s; }

function esc(s){
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

async function apiGet(path, params){
  const u = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([k,v]) => u.searchParams.set(k, String(v)));
  const r = await fetch(u.toString());
  if (!r.ok){
    const t = await r.text();
    throw new Error(`${r.status} ${r.statusText} :: ${t}`);
  }
  return await r.json();
}

/* ---------------- Tabs ---------------- */
function activateTab(tabId){
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
  const p = document.getElementById(tabId);
  if (p) p.classList.add("active");

  document.querySelectorAll("#mainTabs .tab").forEach(b => b.classList.remove("active"));
  const btn = document.querySelector(`#mainTabs .tab[data-tab="${tabId}"]`);
  if (btn) btn.classList.add("active");
}

function activateTopnTab(mode){
  STATE.topnMode = mode;
  document.querySelectorAll("#topnTabs .stab").forEach(b => b.classList.remove("active"));
  const btn = document.querySelector(`#topnTabs .stab[data-topn="${mode}"]`);
  if (btn) btn.classList.add("active");
  renderTopnTable(); // re-render with current mode
}

/* -------------- TopN classify (UI-side) -------------- */
const RE_URL = /\bhttps?:\/\/[^\s"'<>]+/ig;
const RE_DOMAIN = /\b(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|xn--[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/ig;
const RE_IP = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function isLocalhost(x){ return /^localhost\b/i.test(x) || /^127\./.test(x) || /^0\.0\.0\.0$/.test(x); }
function isPunycode(x){ return /\bxn--/i.test(x); }

function classifyValue(v){
  const s = String(v || "");
  const lower = s.toLowerCase();

  // URL
  if (lower.startsWith("http://") || lower.startsWith("https://")) return "urls";

  // IP
  if (RE_IP.test(s)) return "keywords"; // 기본은 키워드, (allowIpAsUrl 켜면 url로 승격)
  return "keywords";
}

function normalizeUrl(u){
  try{
    // 끝의 구두점 같은거 제거
    u = u.replace(/[)\],.]+$/g, "");
    return u;
  }catch{ return u; }
}

function buildTopnBuckets(){
  const allowLocalhost = qs("allowLocalhost").checked;
  const allowPunycode = qs("allowPunycode").checked;
  const allowIpAsUrl = qs("allowIpAsUrl").checked;

  const urls = [];
  const domains = [];
  const keywords = [];

  for (const it of STATE.topnRaw){
    const v0 = String(it.value || "");
    const c = Number(it.count || 0);

    // url 후보
    if (v0.toLowerCase().startsWith("http://") || v0.toLowerCase().startsWith("https://")){
      const u = normalizeUrl(v0);
      if (!allowLocalhost && isLocalhost(u)) { keywords.push({value:v0,count:c}); continue; }
      if (!allowPunycode && isPunycode(u)) { keywords.push({value:v0,count:c}); continue; }
      urls.push({value:u,count:c});
      continue;
    }

    // ip 후보 → url로 승격 옵션
    if (allowIpAsUrl && RE_IP.test(v0)){
      urls.push({value:`http://${v0}`,count:c});
      continue;
    }

    // domain 후보
    const m = v0.match(RE_DOMAIN);
    if (m && m.length === 1 && m[0] === v0){
      if (!allowLocalhost && isLocalhost(v0)) { keywords.push({value:v0,count:c}); continue; }
      if (!allowPunycode && isPunycode(v0)) { keywords.push({value:v0,count:c}); continue; }
      domains.push({value:v0,count:c});
      continue;
    }

    keywords.push({value:v0,count:c});
  }

  return { urls, domains, keywords };
}

/* -------------- Context rendering + highlight -------------- */
function highlightNeedleAll(line, needle){
  if (!needle) return esc(line);
  const re = new RegExp(escapeRegExp(needle), "ig");
  return esc(line).replace(re, (m)=>`<mark class="hit">${m}</mark>`);
}

// URL만 urlhit 로 감싸기 (hit 라인 안에서 URL 토큰만)
function highlightUrls(line){
  const safe = esc(line);
  return safe.replace(RE_URL, (m)=>`<mark class="urlhit">${esc(m)}</mark>`);
}

function escapeRegExp(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function clearFocusStyles(){
  document.querySelectorAll(".hitBlock.focused").forEach(el => el.classList.remove("focused"));
  document.querySelectorAll(".hitCaret").forEach(el => el.remove());
}

function pulseAllMarksWithin(el){
  const marks = el.querySelectorAll("mark.hit, mark.urlhit");
  marks.forEach((m,i)=>{
    setTimeout(()=>{
      m.classList.add("pulse");
      setTimeout(()=>m.classList.remove("pulse"), 900);
    }, i * 80);
  });
}

function focusHit(hitIndex){
  const el = document.querySelector(`[data-hit-index="${hitIndex}"]`);
  if (!el) return;

  clearFocusStyles();

  el.classList.add("focused");
  el.scrollIntoView({ behavior: "smooth", block: "start" });

  setTimeout(() => {
    const firstMark = el.querySelector("mark.hit, mark.urlhit");
    if (!firstMark) return;

    let caret = el.querySelector(".hitCaret");
    if (!caret) {
      caret = document.createElement("div");
      caret.className = "hitCaret";
      caret.textContent = "▼";
      el.insertBefore(caret, el.firstChild);
    }

    firstMark.scrollIntoView({ behavior: "smooth", block: "center" });

    // 동일 hit 블록 내 mark 전부 pulse (요청사항)
    pulseAllMarksWithin(el);
  }, 180);

  setTimeout(() => el.classList.remove("focused"), 1800);
}

function renderContextWithHighlight(ctx){
  const out = qs("ctxOut");
  out.innerHTML = "";

  const needle = ctx.needle || "";
  qs("ctxMeta").textContent = `hits=${(ctx.hits||[]).length} | truncated=${ctx.truncated ? "yes":"no"} | radius=${ctx.radius}`;

  if (!ctx.hits || !ctx.hits.length){
    out.innerHTML = `<div class="meta">(no hits)</div>`;
    return;
  }

  ctx.hits.forEach(h => {
    const wrap = document.createElement("div");
    wrap.className = "hitBlock";
    wrap.dataset.hitIndex = String(h.hit_index);

    const head = document.createElement("div");
    head.className = "hitHead";
    head.innerHTML = `
      <div class="mono">#${h.hit_index} ${esc(h.file)} : ${esc(String(h.line_no))}</div>
      <div class="hitActions">
        <button class="btnSm" data-copy="${esc(needle)}">Copy needle</button>
      </div>
    `;
    wrap.appendChild(head);

    const pre = document.createElement("pre");
    pre.className = "pre hitPre";

    const lines = h.lines || [];
    const matchOff = Number(h.match_line_offset ?? 0);

    const htmlLines = lines.map((line, idx) => {
      // 1) urlhit 먼저
      let s = highlightUrls(line);
      // 2) needle(hit) 전체 강조
      s = s.replace(new RegExp(escapeRegExp(esc(needle)), "ig"), (m)=>`<mark class="hit">${m}</mark>`);
      // 위 replace가 esc된 needle 기반이라 과할 수 있어서, 아래처럼 안전하게 한번 더:
      s = highlightNeedleAll(line, needle);
      // 마지막으로 urlhit 적용 (needle 강조 뒤에도 url 강조 유지)
      s = highlightUrls(s.replaceAll("&amp;","&amp;")); // noop-ish; keep order safe

      const ln = h.start_line + idx;
      const cls = (idx === matchOff) ? "hitLine" : "ctxLine";
      return `<div class="${cls}"><span class="ln">${ln}</span><span class="tx">${s}</span></div>`;
    }).join("");

    pre.innerHTML = htmlLines;
    wrap.appendChild(pre);

    out.appendChild(wrap);
  });

  // copy buttons
  out.querySelectorAll("button[data-copy]").forEach(btn => {
    btn.addEventListener("click", async ()=>{
      const t = btn.getAttribute("data-copy") || "";
      try{
        await navigator.clipboard.writeText(t);
        setStatus("copied");
      }catch(e){
        setStatus("copy failed");
      }
    });
  });
}

/* -------------- Loaders -------------- */
async function loadRun(){
  STATE.outDir = qs("outDir").value.trim();
  setStatus("loading run...");
  const data = await apiGet("/api/run", { out_dir: STATE.outDir });
  setStatus("preview ok");
  return data;
}

async function loadTopN(){
  setStatus("loading topn...");
  const top_n = Number(qs("topnN").value || 30);
  const min_len = Number(qs("topnMinLen").value || 6);

  const data = await apiGet("/api/dex/topn", { out_dir: STATE.outDir, top_n, min_len });
  STATE.topnRaw = data.items || [];
  qs("topnMeta").textContent = `dex=${data.dex} | items=${STATE.topnRaw.length}`;
  renderTopnTable();
  setStatus("dex topn ok");
}

function renderTopnTable(){
  const tb = qs("topnTbody");
  tb.innerHTML = "";

  const buckets = buildTopnBuckets();
  const rows = buckets[STATE.topnMode] || [];

  if (!rows.length){
    tb.innerHTML = `<tr><td colspan="3" style="color:#9db1d1;">(empty)</td></tr>`;
    return;
  }

  rows.forEach((it, idx)=>{
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="colN">${esc(String(it.count||0))}</td>
      <td class="mono">${esc(it.value||"")}</td>
      <td>
        <button class="btnSm" data-needle="${esc(it.value||"")}">Context</button>
        <button class="btnSm" data-copy="${esc(it.value||"")}">Copy</button>
      </td>
    `;
    tb.appendChild(tr);
  });

  // actions
  tb.querySelectorAll("button[data-copy]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      const t = btn.getAttribute("data-copy") || "";
      try{
        await navigator.clipboard.writeText(t);
        setStatus("copied");
      }catch{ setStatus("copy failed"); }
    });
  });

  tb.querySelectorAll("button[data-needle]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      const needle = btn.getAttribute("data-needle") || "";
      qs("needle").value = needle;

      // TopN 클릭 시 Context 탭으로 자동 이동 (요청사항)
      activateTab("tabContext");

      await loadContext(needle);

      // 첫 hit 자동 포커스 (요청사항)
      if (STATE.lastCtx && STATE.lastCtx.hits && STATE.lastCtx.hits.length){
        focusHit(STATE.lastCtx.hits[0].hit_index);
      }
    });
  });
}

async function loadContext(needleOverride){
  setStatus("loading ctx...");
  const needle = (needleOverride ?? qs("needle").value).trim();
  const radius = Number(qs("radius").value || 3);
  if (!needle){
    setStatus("needle required");
    return;
  }
  const ctx = await apiGet("/api/dex/context", { out_dir: STATE.outDir, needle, radius });
  STATE.lastCtx = ctx;
  renderContextWithHighlight(ctx);
  setStatus("ctx ok");
}

async function loadTree(){
  setStatus("loading tree...");
  const filter = (qs("treeFilter").value || "").trim().toLowerCase();
  const data = await apiGet("/api/decrypted/tree", { out_dir: STATE.outDir, max_files: 3000 });

  const list = qs("treeList");
  list.innerHTML = "";
  const files = data.files || [];
  const shown = files.filter(f => !filter || String(f.rel||"").toLowerCase().includes(filter));

  shown.forEach(f=>{
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = f.rel;
    div.addEventListener("click", ()=>previewFile(f.rel));
    list.appendChild(div);
  });

  setStatus(`tree ok (${shown.length}/${files.length})`);
}

async function previewFile(rel){
  setStatus("preview...");
  const data = await apiGet("/api/decrypted/preview", { out_dir: STATE.outDir, rel, max_bytes: 4096 });
  qs("previewMeta").textContent = `${data.rel} | bytes=${data.bytes}`;
  qs("previewHex").textContent = data.hex_head;
  setStatus("preview ok");
}

async function loadMitre(){
  setStatus("mitre...");
  const data = await apiGet("/api/mitre", { out_dir: STATE.outDir });
  STATE.lastMitre = data;
  qs("mitreBox").textContent = JSON.stringify(data, null, 2);
  applyMitreRender();
  setStatus("mitre ok");
}

function applyMitreRender(){
  const data = STATE.lastMitre || {};
  const techniques0 = (data.mitre && data.mitre.techniques) ? data.mitre.techniques : [];
  const rows0 = data.tag_mitre_rows || [];

  const q = (qs("mitreSearch").value || "").trim().toLowerCase();
  const sort = qs("mitreSort").value;

  let techniques = techniques0.slice();
  if (q){
    techniques = techniques.filter(t=>{
      const a = String(t.technique_id||"").toLowerCase();
      const b = String(t.reason||"").toLowerCase();
      return a.includes(q) || b.includes(q);
    });
  }

  if (sort === "id_asc") techniques.sort((a,b)=>String(a.technique_id||"").localeCompare(String(b.technique_id||"")));
  if (sort === "id_desc") techniques.sort((a,b)=>String(b.technique_id||"").localeCompare(String(a.technique_id||"")));
  if (sort === "w_desc") techniques.sort((a,b)=>Number(b.weight||0)-Number(a.weight||0));
  if (sort === "w_asc") techniques.sort((a,b)=>Number(a.weight||0)-Number(b.weight||0));

  qs("mitreMeta").textContent = `techniques=${techniques.length}/${techniques0.length} | tag_mitre_rows=${rows0.length}`;

  // techniques table
  const tb1 = qs("mitreTechTbody");
  tb1.innerHTML = "";
  if (!techniques.length){
    tb1.innerHTML = `<tr><td colspan="3" style="color:#9db1d1;">(empty)</td></tr>`;
  } else {
    techniques.forEach(t=>{
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${esc(t.technique_id||"")}</td>
        <td class="colN">${esc(String(t.weight ?? ""))}</td>
        <td>${esc(t.reason||"")}</td>
      `;
      tb1.appendChild(tr);
    });
  }

  // mapping table
  const tb2 = qs("mitreTagTbody");
  tb2.innerHTML = "";
  if (!rows0.length){
    tb2.innerHTML = `<tr><td colspan="5" style="color:#9db1d1;">(empty)</td></tr>`;
  } else {
    rows0.forEach(r=>{
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${esc(r.tag||"")}</td>
        <td>${esc(r.sev||"")}</td>
        <td class="mono">${esc(r.mitre||"")}</td>
        <td>${esc(r.source||"")}</td>
        <td>${esc(r.reason||"")}</td>
      `;
      tb2.appendChild(tr);
    });
  }
}

async function loadIoc(){
  setStatus("ioc...");
  const data = await apiGet("/api/ioc", { out_dir: STATE.outDir });
  qs("iocBox").textContent = JSON.stringify(data, null, 2);
  qs("iocMeta").textContent = `urls=${(data.urls||[]).length} domains=${(data.domains||[]).length} ips=${(data.ips||[]).length} emails=${(data.emails||[]).length}`;
  setStatus("ioc ok");
}

async function loadRaw(){
  setStatus("raw...");
  const data = await apiGet("/api/raw", { out_dir: STATE.outDir });
  qs("rawBox").textContent = JSON.stringify(data, null, 2);
  qs("rawMeta").textContent = "ok";
  setStatus("raw ok");
}

/* ----------------- wiring ----------------- */
window.addEventListener("DOMContentLoaded", ()=>{
  // tabs
  document.querySelectorAll("#mainTabs .tab").forEach(btn=>{
    btn.addEventListener("click", ()=>activateTab(btn.dataset.tab));
  });

  // topn subtabs
  document.querySelectorAll("#topnTabs .stab").forEach(btn=>{
    btn.addEventListener("click", ()=>activateTopnTab(btn.dataset.topn));
  });

  // buttons
  qs("btnLoad").addEventListener("click", loadRun);
  qs("btnLoadTopN").addEventListener("click", async ()=>{
    await loadRun();
    await loadTopN();
  });

  qs("btnContext").addEventListener("click", ()=>loadContext());
  qs("btnTree").addEventListener("click", loadTree);
  qs("btnMitre").addEventListener("click", loadMitre);
  qs("btnIoc").addEventListener("click", loadIoc);
  qs("btnRaw").addEventListener("click", loadRaw);

  // mitre filter/sort reactive
  qs("mitreSearch").addEventListener("input", ()=>applyMitreRender());
  qs("mitreSort").addEventListener("change", ()=>applyMitreRender());

  // toggles re-render topn
  ["allowLocalhost","allowPunycode","allowIpAsUrl"].forEach(id=>{
    qs(id).addEventListener("change", ()=>renderTopnTable());
  });

  // init
  STATE.outDir = qs("outDir").value.trim();
  setStatus("ready");
});
