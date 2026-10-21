'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');

const crypto = require('crypto');
const { CognitoJwtVerifier } = require('aws-jwt-verify');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');

const app = express();
const PORT = Number(process.env.PORT || 3000);
// Job-discovery defaults: only jobs posted in the last 7 days, newest first, refresh every 6 hours.
const JOB_POSTED_WITHIN_DAYS = Math.max(1, Number(process.env.JOB_POSTED_WITHIN_DAYS || 7));
const JOB_REFRESH_INTERVAL_HOURS = Math.max(1, Number(process.env.JOB_REFRESH_INTERVAL_HOURS || 6));
const JOB_REFRESH_INTERVAL_MS = JOB_REFRESH_INTERVAL_HOURS * 60 * 60 * 1000;
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => { // Minimal cookie parser for the HttpOnly Cognito session cookie
  req.cookies = {};
  String(req.headers.cookie || '').split(';').forEach(part => { const i = part.indexOf('='); if (i > 0) req.cookies[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim()); });
  next();
});

const AUTH_CONFIGURED = ['AWS_REGION','COGNITO_USER_POOL_ID','COGNITO_CLIENT_ID','COGNITO_CLIENT_SECRET','COGNITO_DOMAIN','DYNAMODB_USERS_TABLE','PUBLIC_BASE_URL'].every(k => process.env[k]);
const baseUrl = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const callbackUrl = `${baseUrl}/auth/callback`;
const cookieSecure = baseUrl.startsWith('https://');
const cookieOptions = { httpOnly: true, secure: cookieSecure, sameSite: 'lax', path: '/', maxAge: 8 * 60 * 60 * 1000 };
let ddb, verifier, idVerifier;
if (AUTH_CONFIGURED) {
  const raw = new DynamoDBClient({ region: process.env.AWS_REGION });
  ddb = DynamoDBDocumentClient.from(raw);
  verifier = CognitoJwtVerifier.create({ userPoolId: process.env.COGNITO_USER_POOL_ID, tokenUse: 'access', clientId: process.env.COGNITO_CLIENT_ID });
  idVerifier = CognitoJwtVerifier.create({ userPoolId: process.env.COGNITO_USER_POOL_ID, tokenUse: 'id', clientId: process.env.COGNITO_CLIENT_ID });
}
const userTable = () => process.env.DYNAMODB_USERS_TABLE;
const userKey = sub => ({ userId: sub });
const addDays = (date, days) => new Date(date.getTime() + days * 86400000);
async function getOrCreateUser(claims) {
  const now = new Date();
  const result = await ddb.send(new GetCommand({ TableName: userTable(), Key: userKey(claims.sub), ConsistentRead: true }));
  if (result.Item) return result.Item;
  const item = { userId: claims.sub, email: claims.email || claims.username || claims.sub, status: 'ACTIVE', registeredAt: now.toISOString(), expiresAt: Math.floor(addDays(now, 30).getTime()/1000), renewalStatus: 'NONE' };
  await ddb.send(new PutCommand({ TableName: userTable(), Item: item, ConditionExpression: 'attribute_not_exists(userId)' })).catch(async err => { if (err.name === 'ConditionalCheckFailedException') return; throw err; });
  const again = await ddb.send(new GetCommand({ TableName: userTable(), Key: userKey(claims.sub), ConsistentRead: true }));
  return again.Item || item;
}
function requireConfigured(_req, res, next) { if (!AUTH_CONFIGURED) return res.status(503).json({ error: 'Authentication is not configured. Set Cognito and DynamoDB environment variables.' }); next(); }
async function authenticated(req, res, next) {
  try {
    if (!AUTH_CONFIGURED) return res.status(503).json({ error: 'Authentication is not configured.' });
    const token = req.cookies?.ijh_access || req.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Please sign in.', code: 'AUTH_REQUIRED' });
    req.claims = await verifier.verify(token);
    req.user = await getOrCreateUser(req.claims);
    next();
  } catch (e) { return res.status(401).json({ error: 'Your session is invalid or expired. Please sign in again.', code: 'AUTH_REQUIRED' }); }
}
function activeSubscription(req, res, next) {
  if (!req.user || req.user.status !== 'ACTIVE' || Number(req.user.expiresAt) <= Math.floor(Date.now()/1000)) {
    return res.status(403).json({ error: 'Your 30-day access has expired. Submit a renewal request to the site administrator.', code: 'SUBSCRIPTION_EXPIRED', user: req.user ? { email: req.user.email, expiresAt: req.user.expiresAt, renewalStatus: req.user.renewalStatus } : null });
  }
  next();
}
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

app.get('/auth/login', requireConfigured, (req, res) => {
  const state = crypto.randomBytes(24).toString('hex');
  res.cookie('ijh_oauth_state', state, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
  const screenHint = req.query.signup === '1' ? '&screen_hint=signup' : '';
  const url = `https://${process.env.COGNITO_DOMAIN}/oauth2/authorize?response_type=code&client_id=${encodeURIComponent(process.env.COGNITO_CLIENT_ID)}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=${encodeURIComponent('openid email')}&state=${state}${screenHint}`;
  res.redirect(url);
});
app.get('/auth/callback', requireConfigured, async (req, res) => {
  try {
    if (!req.query.code || !req.query.state || req.query.state !== req.cookies?.ijh_oauth_state) return res.status(400).send('Invalid sign-in state. Please return to the home page and try again.');
    const basic = Buffer.from(`${process.env.COGNITO_CLIENT_ID}:${process.env.COGNITO_CLIENT_SECRET}`).toString('base64');
    const tokenRes = await fetch(`https://${process.env.COGNITO_DOMAIN}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: process.env.COGNITO_CLIENT_ID, code: String(req.query.code), redirect_uri: callbackUrl }) });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok || !tokens.access_token) return res.status(401).send('Sign-in failed. Please return to the home page and try again.');
    const claims = await verifier.verify(tokens.access_token);
    const idClaims = await idVerifier.verify(tokens.id_token);
    await getOrCreateUser({ ...claims, email: idClaims.email, username: idClaims.email || idClaims['cognito:username'] || claims.sub });
    res.clearCookie('ijh_oauth_state', { path: '/' });
    res.cookie('ijh_access', tokens.access_token, cookieOptions);
    res.redirect('/');
  } catch (e) { console.error('Cognito callback failed:', e.message); res.status(500).send('Unable to complete sign-in. Check server configuration and try again.'); }
});
app.post('/auth/logout', (req, res) => { res.clearCookie('ijh_access', { path: '/' }); res.json({ ok: true }); });
app.get('/api/me', requireConfigured, authenticated, async (req, res) => {
  const u = req.user;
  res.json({ authenticated: true, email: u.email, status: Number(u.expiresAt) <= Math.floor(Date.now()/1000) ? 'EXPIRED' : u.status, registeredAt: u.registeredAt, expiresAt: u.expiresAt, renewalStatus: u.renewalStatus || 'NONE' });
});
app.post('/api/renewal-request', requireConfigured, authenticated, async (req, res) => {
  const now = new Date().toISOString();
  await ddb.send(new UpdateCommand({ TableName: userTable(), Key: userKey(req.claims.sub), UpdateExpression: 'SET renewalStatus = :pending, renewalRequestedAt = :now', ExpressionAttributeValues: { ':pending': 'PENDING', ':now': now } }));
  res.json({ ok: true, message: 'Renewal request submitted. The administrator will contact you about paid renewal.' });
});

const TRACKS = {
  'AWS DevOps': ['AWS DevOps', 'DevOps Engineer AWS', 'Cloud DevOps Engineer', 'Platform Engineer AWS', 'SRE AWS'],
  'SAP ABAP': ['SAP ABAP', 'ABAP Developer', 'SAP Technical Consultant', 'S/4HANA ABAP'],
  'TOSCA Testing': ['Tricentis Tosca', 'TOSCA Test Automation', 'Tosca Automation Engineer', 'Tosca QA'],
  'Quadient Inspire': ['Quadient Inspire', 'GMC Inspire', 'Customer Communications Management', 'CCM Developer']
};
const ALLOWED_TRACKS = Object.keys(TRACKS);
const clean = (s, max = 120) => String(s || '').replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, max);
const isIndiaOrRemote = job => {
  const loc = `${job.location || ''} ${job.country || ''}`.toLowerCase();
  const remote = /remote|work from home|anywhere|distributed|india remote/.test(loc) || /remote|work from home|anywhere/.test(String(job.title || '').toLowerCase());
  const india = /india|bengaluru|bangalore|hyderabad|pune|chennai|mumbai|gurugram|gurgaon|noida|delhi|kolkata|kochi|ahmedabad|indore|jaipur|thiruvananthapuram|visakhapatnam|coimbatore/.test(loc);
  return remote || india;
};
const normalize = (j, source) => ({
  id: String(j.id || j.url || `${source}-${j.title}-${j.company}`).slice(0, 500),
  title: clean(j.title, 220) || 'Untitled role',
  company: clean(j.company || j.company_name || j.companyName || 'Company not listed', 180),
  location: clean(j.location || j.candidate_required_location || j.city || 'India / Remote', 180),
  description: clean((j.description || j.description_text || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' '), 700),
  url: safeUrl(j.url || j.redirect_url || j.apply_url || j.job_url),
  source,
  postedAt: j.created || j.created_at || j.publication_date || j.date || null,
  remote: /remote|work from home|anywhere/i.test(`${j.location || ''} ${j.candidate_required_location || ''} ${j.title || ''}`)
});
function safeUrl(value) {
  try { const u = new URL(String(value || '')); return ['https:', 'http:'].includes(u.protocol) ? u.href : ''; }
  catch { return ''; }
}
async function fetchJson(url, timeoutMs = 9000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'IndiaJobHub/1.0 (job search aggregator)' } });
    if (!res.ok) throw new Error(`Source returned ${res.status}`);
    return await res.json();
  } finally { clearTimeout(timer); }
}
function makeSearchLinks(track, mode) {
  const q = encodeURIComponent(`"${track}" (India OR remote OR "work from home")`);
  const locations = mode === 'remote' ? 'remote India' : 'India';
  const lq = encodeURIComponent(`${track} ${locations}`);
  return [
    { name: 'LinkedIn Jobs', url: `https://www.linkedin.com/jobs/search/?keywords=${lq}&location=India` },
    { name: 'Naukri', url: `https://www.naukri.com/${encodeURIComponent(track.toLowerCase().replace(/\s+/g, '-'))}-jobs` },
    { name: 'Indeed India', url: `https://in.indeed.com/jobs?q=${lq}` },
    { name: 'Google Jobs / company career pages', url: `https://www.google.com/search?q=${q}+jobs+careers` },
    { name: 'Foundit', url: `https://www.foundit.in/search/${encodeURIComponent(track)}-jobs` }
  ];
}
async function getAdzuna(track) {
  const { ADZUNA_APP_ID, ADZUNA_APP_KEY } = process.env;
  if (!ADZUNA_APP_ID || !ADZUNA_APP_KEY) return [];
  const what = encodeURIComponent(TRACKS[track].join(' OR '));
  const url = `https://api.adzuna.com/v1/api/jobs/in/search/1?app_id=${encodeURIComponent(ADZUNA_APP_ID)}&app_key=${encodeURIComponent(ADZUNA_APP_KEY)}&results_per_page=30&what=${what}&content-type=application/json`;
  const data = await fetchJson(url);
  return (data.results || []).map(j => normalize({ ...j, location: j.location?.display_name || 'India' }, 'Adzuna'));
}
async function getArbeitnow(track) {
  // Public API. It is global; filter to India/remote and relevant titles below.
  const data = await fetchJson('https://www.arbeitnow.com/api/job-board-api');
  const terms = TRACKS[track].map(x => x.toLowerCase());
  return (data.data || []).filter(j => {
    const title = `${j.title || ''} ${j.description || ''}`.toLowerCase();
    return terms.some(t => title.includes(t.toLowerCase())) && (j.remote || /india|remote/i.test(`${j.location || ''} ${j.title || ''}`));
  }).map(j => normalize({ ...j, location: j.remote ? (j.location ? `${j.location} · Remote` : 'Remote') : j.location }, 'Arbeitnow'));
}
async function getRemotive(track) {
  const terms = TRACKS[track].map(x => x.toLowerCase());
  const data = await fetchJson('https://remotive.com/api/remote-jobs?limit=100');
  return (data.jobs || []).filter(j => {
    const title = `${j.title || ''} ${j.description || ''} ${j.category || ''}`.toLowerCase();
    const match = terms.some(t => title.includes(t));
    const loc = `${j.candidate_required_location || ''} ${j.title || ''}`.toLowerCase();
    return match && (!j.candidate_required_location || /worldwide|anywhere|india|remote/i.test(loc));
  }).map(j => normalize({ ...j, location: j.candidate_required_location || 'Remote · check country eligibility' }, 'Remotive'));
}
// In-memory cache avoids calling job-source APIs on every page visit.
const jobCache = new Map();
const refreshInProgress = new Map();
let lastRefreshStartedAt = null;
let lastRefreshCompletedAt = null;
async function refreshTrackJobs(track) {
  if (refreshInProgress.has(track)) return refreshInProgress.get(track);
  const task = (async () => {
    const startedAt = new Date().toISOString();
    const sources = await Promise.allSettled([getAdzuna(track), getArbeitnow(track), getRemotive(track)]);
    let jobs = sources.flatMap(s => s.status === 'fulfilled' ? s.value : []);
    const cutoff = Date.now() - JOB_POSTED_WITHIN_DAYS * 24 * 60 * 60 * 1000;
    // Exclude listings without a parseable posting date: we cannot prove they are within the selected window.
    jobs = jobs.filter(j => {
      if (!j.url || !isIndiaOrRemote(j) || !j.postedAt) return false;
      const posted = Date.parse(j.postedAt);
      return Number.isFinite(posted) && posted <= Date.now() && posted >= cutoff;
    });
    const seen = new Set();
    jobs = jobs.filter(j => {
      const k = `${j.title.toLowerCase()}|${j.company.toLowerCase()}|${j.url}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    jobs.sort((a, b) => Date.parse(b.postedAt) - Date.parse(a.postedAt));
    const result = {
      jobs,
      refreshedAt: new Date().toISOString(),
      refreshStartedAt: startedAt,
      sources: {
        adzuna: sources[0].status === 'fulfilled' ? 'ok' : 'unavailable',
        arbeitnow: sources[1].status === 'fulfilled' ? 'ok' : 'unavailable',
        remotive: sources[2].status === 'fulfilled' ? 'ok' : 'unavailable'
      }
    };
    jobCache.set(track, result);
    lastRefreshCompletedAt = result.refreshedAt;
    return result;
  })().finally(() => refreshInProgress.delete(track));
  refreshInProgress.set(track, task);
  return task;
}
async function refreshAllTracks() {
  lastRefreshStartedAt = new Date().toISOString();
  console.log(`[job-discovery] Refresh started; window=${JOB_POSTED_WITHIN_DAYS} days; interval=${JOB_REFRESH_INTERVAL_HOURS} hours`);
  await Promise.allSettled(ALLOWED_TRACKS.map(refreshTrackJobs));
  console.log(`[job-discovery] Refresh finished at ${lastRefreshCompletedAt || 'no successful source results'}`);
}
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'India Job Hub' }));
app.get('/api/job-discovery-config', (_req, res) => res.json({
  postingWindowDays: JOB_POSTED_WITHIN_DAYS,
  sort: process.env.JOB_SORT === 'oldest' ? 'oldest' : 'newest',
  refreshIntervalHours: JOB_REFRESH_INTERVAL_HOURS,
  lastRefreshStartedAt,
  lastRefreshCompletedAt,
  nextScheduledRefreshAt: lastRefreshCompletedAt ? new Date(Date.parse(lastRefreshCompletedAt) + JOB_REFRESH_INTERVAL_MS).toISOString() : null,
  source: 'Configured job APIs; portal search links are provided separately'
}));
app.get('/api/jobs', requireConfigured, authenticated, activeSubscription, async (req, res) => {
  const track = clean(req.query.track, 60);
  const mode = ['india', 'remote', 'all'].includes(req.query.mode) ? req.query.mode : 'all';
  const search = clean(req.query.search, 100).toLowerCase();
  if (!ALLOWED_TRACKS.includes(track)) return res.status(400).json({ error: 'Choose a supported job category.', allowedTracks: ALLOWED_TRACKS });
  let cached = jobCache.get(track);
  if (!cached) cached = await refreshTrackJobs(track);
  const currentCutoff = Date.now() - JOB_POSTED_WITHIN_DAYS * 24 * 60 * 60 * 1000;
  let jobs = cached.jobs.filter(j => { const posted = Date.parse(j.postedAt); return Number.isFinite(posted) && posted <= Date.now() && posted >= currentCutoff; });
  if (mode === 'remote') jobs = jobs.filter(j => j.remote || /remote|work from home|anywhere/i.test(j.location));
  if (mode === 'india') jobs = jobs.filter(j => /india|bengaluru|bangalore|hyderabad|pune|chennai|mumbai|gurugram|gurgaon|noida|delhi|kolkata|kochi|ahmedabad|indore|jaipur|thiruvananthapuram|visakhapatnam|coimbatore/i.test(j.location));
  if (search) jobs = jobs.filter(j => `${j.title} ${j.company} ${j.location} ${j.description}`.toLowerCase().includes(search));
  // Re-sort after filtering to preserve the configured newest-first order.
  jobs.sort((a, b) => process.env.JOB_SORT === 'oldest' ? Date.parse(a.postedAt) - Date.parse(b.postedAt) : Date.parse(b.postedAt) - Date.parse(a.postedAt));
  res.set('Cache-Control', 'private, max-age=60');
  res.json({
    track, mode, total: jobs.length, jobs: jobs.slice(0, 100), links: makeSearchLinks(track, mode),
    discovery: { postingWindowDays: JOB_POSTED_WITHIN_DAYS, sort: process.env.JOB_SORT === 'oldest' ? 'oldest' : 'newest', refreshIntervalHours: JOB_REFRESH_INTERVAL_HOURS, refreshedAt: cached.refreshedAt, sourceStatus: cached.sources },
    sourceStatus: { adzunaConfigured: Boolean(process.env.ADZUNA_APP_ID && process.env.ADZUNA_APP_KEY), publicSources: ['Arbeitnow', 'Remotive'] },
    note: 'Only listings with a parseable posting date inside the selected window are shown. Results depend on provider API coverage and terms. Portal links open official search pages; this app does not scrape LinkedIn or Naukri.'
  });
});

// ATS_ANALYZER_INTEGRATION_V1
const atsUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!['.pdf', '.docx', '.txt'].includes(ext)) {
      return cb(new Error('Upload a PDF, DOCX, or TXT resume.'));
    }
    cb(null, true);
  }
});

const ATS_SKILLS = [
  'aws', 'amazon web services', 'terraform', 'jenkins', 'docker',
  'kubernetes', 'linux', 'python', 'bash', 'ci/cd', 'github actions',
  'cloudformation', 'ec2', 's3', 'iam', 'vpc', 'lambda', 'cloudwatch',
  'sql', 'etl', 'data warehouse', 'data quality', 'testing', 'automation',
  'tosca', 'tricentis', 'sap', 'abap', 'quadient', 'inspire',
  'communication', 'leadership', 'agile', 'git', 'ansible', 'prometheus',
  'grafana', 'incident management', 'monitoring', 'deployment'
];

function atsNormalize(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9+#./\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function atsContains(text, term) {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp('(^|[^a-z0-9])' + escaped + '([^a-z0-9]|$)', 'i').test(text);
}

function atsExtractTerms(value) {
  const normalized = atsNormalize(value);
  const fromSkills = ATS_SKILLS.filter(skill => atsContains(normalized, skill));
  const ignored = new Set([
    'with','from','that','this','have','will','your','role','work','team',
    'years','using','used','into','responsible','experience','required',
    'skills','ability','strong'
  ]);
  const counts = new Map();

  for (const word of normalized.split(' ')) {
    if (word.length >= 4 && !ignored.has(word)) {
      counts.set(word, (counts.get(word) || 0) + 1);
    }
  }

  const frequent = [...counts.entries()]
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([word]) => word);

  return [...new Set([...fromSkills, ...frequent])].slice(0, 35);
}

async function atsExtractResumeText(file) {
  const ext = path.extname(file.originalname || '').toLowerCase();

  if (ext === '.txt') return file.buffer.toString('utf8');

  if (ext === '.docx') {
    const result = await mammoth.extractRawText({ buffer: file.buffer });
    return result.value || '';
  }

  if (ext === '.pdf') {
    const result = await pdfParse(file.buffer);
    return result.text || '';
  }

  throw new Error('Unsupported resume format.');
}

app.post(
  '/api/ats/analyze',
  requireConfigured,
  authenticated,
  activeSubscription,
  (req, res, next) => {
    atsUpload.single('resume')(req, res, err => {
      if (!err) return next();

      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'Resume must be 5 MB or smaller.' });
      }

      return res.status(400).json({ error: err.message || 'Invalid upload.' });
    });
  },
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Please upload a resume file.' });
      }

      const resumeText = await atsExtractResumeText(req.file);

      if (!resumeText.trim()) {
        return res.status(400).json({
          error: 'No readable text found. If this is a scanned PDF, use an OCR-readable version.'
        });
      }

      const jobDescription = String(req.body.jobDescription || '').slice(0, 30000);
      const normalizedResume = atsNormalize(resumeText);

      const jobTerms = jobDescription.trim()
        ? atsExtractTerms(jobDescription)
        : ATS_SKILLS.filter(skill => atsContains(normalizedResume, skill));

      const matchedKeywords = jobTerms.filter(term => atsContains(normalizedResume, term));
      const missingKeywords = jobTerms.filter(term => !matchedKeywords.includes(term));

      const keywordScore = jobTerms.length
        ? Math.round(matchedKeywords.length / jobTerms.length * 100)
        : 0;

      const sectionChecks = [
        ['contact details', /email|@|phone|mobile|linkedin/i.test(resumeText)],
        ['work experience', /experience|employment|professional history/i.test(resumeText)],
        ['skills section', /skills|technologies|technical expertise/i.test(resumeText)],
        ['education', /education|university|college|degree|bachelor|master/i.test(resumeText)]
      ];

      const sectionScore = Math.round(
        sectionChecks.filter(([, found]) => found).length / sectionChecks.length * 100
      );

      const score = jobDescription.trim()
        ? Math.round(keywordScore * 0.8 + sectionScore * 0.2)
        : sectionScore;

      const recommendations = [];

      if (!sectionChecks[0][1]) recommendations.push(
        'Add clear contact details, including a professional email address.'
      );
      if (!sectionChecks[1][1]) recommendations.push(
        'Add a clearly labelled work experience section with achievements.'
      );
      if (!sectionChecks[2][1]) recommendations.push(
        'Add a skills section using relevant skills you genuinely have.'
      );
      if (!sectionChecks[3][1]) recommendations.push(
        'Add your education and relevant certifications.'
      );
      if (jobDescription.trim() && missingKeywords.length) recommendations.push(
        'Where accurate, reflect relevant missing job-description terms in your skills or experience.'
      );
      if (!jobDescription.trim()) recommendations.push(
        'Paste a target job description for a more useful keyword comparison.'
      );
      if (resumeText.length < 500) recommendations.push(
        'Your resume text looks short; check that the entire resume was extracted.'
      );
      if (!recommendations.length) recommendations.push(
        'Keep the resume tailored to the role and support skills with measurable achievements.'
      );

      res.set('Cache-Control', 'no-store');
      return res.json({
        score,
        summary: jobDescription.trim()
          ? `Estimated score ${score}/100 using keyword coverage and basic section checks. This is not an employer ATS score.`
          : `Basic resume structure score ${score}/100. Add a job description for keyword comparison.`,
        matchedKeywords,
        missingKeywords,
        recommendations,
        metrics: {
          keywordCoverage: keywordScore,
          sectionCoverage: sectionScore,
          extractedCharacters: resumeText.length
        }
      });
    } catch (error) {
      // Never log resume text or the uploaded document itself.
      console.error('ATS analysis error:', error.message);
      return res.status(400).json({
        error: 'Unable to read this resume. Check the file format and try again.'
      });
    }
  }
);

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => {
  console.log(`India Job Hub running on port ${PORT}`);
  // Refresh once at startup, then repeat every six hours (configurable via environment).
  refreshAllTracks().catch(err => console.error('[job-discovery] Initial refresh failed:', err.message));
  const refreshTimer = setInterval(() => refreshAllTracks().catch(err => console.error('[job-discovery] Scheduled refresh failed:', err.message)), JOB_REFRESH_INTERVAL_MS);
  if (typeof refreshTimer.unref === 'function') refreshTimer.unref();
});
