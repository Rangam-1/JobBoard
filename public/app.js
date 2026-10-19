const trackEl = document.getElementById('track');
const modeEl = document.getElementById('mode');
const keywordEl = document.getElementById('keyword');
const jobsEl = document.getElementById('jobs');
const statusEl = document.getElementById('status');
const countEl = document.getElementById('count');
const titleEl = document.getElementById('resultsTitle');
const subtitleEl = document.getElementById('resultsSubtitle');
const portalsEl = document.getElementById('portals');
const recruiterSearchesEl = document.getElementById('recruiterSearches');
const buttonEl = document.getElementById('searchBtn');
const accountPanel = document.getElementById('accountPanel');
const accountTitle = document.getElementById('accountTitle');
const accountMessage = document.getElementById('accountMessage');
const renewBtn = document.getElementById('renewBtn');
const logoutBtn = document.getElementById('logoutBtn');
const resultsSection = document.getElementById('resultsSection');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const formatDate = value => { if (!value) return ''; const d = new Date(value); return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}); };
function renderJob(j) {
  const initial = (j.company || '?').trim().charAt(0).toUpperCase();
  const desc = j.description || 'Open the listing to view responsibilities, requirements and application details.';
  const date = formatDate(j.postedAt);
  return `<article class="job-card"><div class="job-top"><div class="company-mark">${esc(initial)}</div><div><h3 class="job-title">${esc(j.title)}</h3><div class="company">${esc(j.company)}</div></div></div><div class="meta"><span class="pill">${esc(j.location || 'India / Remote')}</span>${j.remote ? '<span class="pill remote">Remote</span>' : ''}${date ? `<span class="pill">${esc(date)}</span>` : ''}</div><p class="description">${esc(desc)}</p><div class="job-foot"><span class="source">Source: ${esc(j.source)}</span><a class="apply-link" href="${esc(j.url)}" target="_blank" rel="noopener noreferrer">View job ↗</a></div></article>`;
}
function renderPortals(links) {
  portalsEl.innerHTML = links.map(p => `<a class="portal-card" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.name)}<span>Search listings ↗</span></a>`).join('');
}

function renderRecruiterSearches(track, mode, keyword = '') {
  const location = mode === 'remote' ? '(remote OR "work from home" OR worldwide)' : mode === 'india' ? '(India OR Bengaluru OR Hyderabad OR Pune OR Chennai OR Mumbai)' : '(India OR remote OR "work from home")';
  const extra = keyword ? ` "${keyword}"` : '';
  const queries = [
    { name: 'Google: LinkedIn hiring posts', query: `site:linkedin.com/posts ${track} (hiring OR "we are hiring" OR "send your resume" OR "share your CV") ${location} past week${extra}` },
    { name: 'Google: recruiter contact emails', query: `site:linkedin.com/posts ${track} (recruiter OR hiring OR "send resume" OR "email your CV") (email OR gmail OR outlook) ${location} past week${extra}` },
    { name: 'LinkedIn: recent posts', url: `https://www.linkedin.com/search/results/content/?keywords=${encodeURIComponent(`${track} hiring ${mode === 'remote' ? 'remote' : 'India'} ${keyword} past week`)}` },
    { name: 'Google: company hiring announcements', query: `${track} hiring "send your resume" OR "email your CV" ${location} past week${extra}` }
  ];
  recruiterSearchesEl.innerHTML = queries.map(item => {
    const url = item.url || `https://www.google.com/search?q=${encodeURIComponent(item.query)}`;
    return `<a class="portal-card" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(item.name)}<span>Search recent posts ↗</span></a>`;
  }).join('');
}

async function searchJobs() {
  const track = trackEl.value;
  const mode = modeEl.value;
  const search = keywordEl.value.trim();
  titleEl.textContent = `Latest ${track} jobs`;
  subtitleEl.textContent = (mode === 'remote' ? 'Remote roles that match your selected category.' : mode === 'india' ? 'Roles located in India.' : 'India-based and remote roles from connected feeds.') + ' Posted in the last 7 days · Newest first · Feeds refresh every 6 hours.';
  jobsEl.innerHTML = '';
  statusEl.textContent = 'Searching available job feeds…';
  countEl.textContent = 'Loading…';
  buttonEl.disabled = true;
  buttonEl.textContent = 'Searching…';
  try {
    const params = new URLSearchParams({track, mode, search});
    const res = await fetch(`/api/jobs?${params}`);
    const data = await res.json();
    if (res.status === 401) { accountMessage.textContent = 'Please register or log in to search jobs.'; accountPanel.hidden = false; throw new Error('Please register or log in to search jobs.'); }
    if (res.status === 403 && data.code === 'SUBSCRIPTION_EXPIRED') { showExpired(data.user); throw new Error(data.error || 'Your access has expired.'); }
    if (!res.ok) throw new Error(data.error || 'Could not load jobs');
    renderPortals(data.links || []);
    renderRecruiterSearches(track, mode, search);
    countEl.textContent = `${data.total} jobs found`;
    if (data.jobs.length) {
      jobsEl.innerHTML = data.jobs.map(renderJob).join('');
      statusEl.textContent = `Showing ${data.jobs.length} matching listings. Filter: last ${data.discovery?.postingWindowDays || 7} days; sorted newest first. Last feed refresh: ${data.discovery?.refreshedAt ? new Date(data.discovery.refreshedAt).toLocaleString() : 'pending'}. Open a listing on its source site to confirm details and apply.`;
    } else {
      statusEl.innerHTML = 'No matching listings came back from the connected feeds this time. Try a broader keyword or use the portal searches below.';
    }
    if (!data.sourceStatus?.adzunaConfigured) {
      statusEl.innerHTML += ' Adzuna is optional: add its API credentials to .env to enable another India-focused feed.';
    }
  } catch (err) {
    statusEl.textContent = `Could not load jobs: ${err.message}. Check your internet connection or try again shortly.`;
    countEl.textContent = 'Search unavailable';
  } finally {
    buttonEl.disabled = false;
    buttonEl.innerHTML = 'Find jobs <span>↗</span>';
  }
}
buttonEl.addEventListener('click', searchJobs);
[trackEl, modeEl].forEach(el => el.addEventListener('change', () => { titleEl.textContent = `Latest ${trackEl.value} jobs`; }));
keywordEl.addEventListener('keydown', e => { if (e.key === 'Enter') searchJobs(); });

function showExpired(user) {
  accountPanel.hidden = false;
  accountTitle.textContent = 'Your 30-day access has expired';
  accountMessage.textContent = `Signed in as ${user?.email || 'user'}. You can request renewal; the administrator will contact you about payment.`;
  renewBtn.hidden = false;
  resultsSection.hidden = true;
}
async function loadAccount() {
  try {
    const res = await fetch('/api/me');
    if (res.status === 503) return;
    if (!res.ok) { accountPanel.hidden = true; return; }
    const user = await res.json();
    accountPanel.hidden = false;
    accountTitle.textContent = user.status === 'EXPIRED' ? 'Access expired' : 'Your account';
    const expires = new Date(Number(user.expiresAt) * 1000).toLocaleDateString();
    accountMessage.textContent = `${user.email} · ${user.status === 'EXPIRED' ? 'Expired' : 'Access expires'} ${expires} · Renewal: ${user.renewalStatus}`;
    if (user.status === 'EXPIRED') { renewBtn.hidden = false; resultsSection.hidden = true; }
    else { renewBtn.hidden = true; resultsSection.hidden = false; }
  } catch (_) { /* Auth may not be configured during local UI preview. */ }
}
renewBtn.addEventListener('click', async () => {
  renewBtn.disabled = true;
  try {
    const res = await fetch('/api/renewal-request', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    const data = await res.json();
    accountMessage.textContent = data.message || data.error || 'Request submitted.';
  } catch (_) { accountMessage.textContent = 'Could not submit the request. Please try again.'; }
  finally { renewBtn.disabled = false; }
});
logoutBtn.addEventListener('click', async () => { await fetch('/auth/logout', { method: 'POST' }); window.location.href = '/'; });
loadAccount();
