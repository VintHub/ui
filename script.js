// Automatically build header and footer on DOM load
document.addEventListener('DOMContentLoaded', () => {
    renderHeader();
    renderFooter();

    // Handle search page hash on load if present
    const hash = window.location.hash.substring(1);
    if (hash && document.getElementById('cveInput')) { 
        document.getElementById('cveInput').value = decodeURIComponent(hash).replace(/[–—−‑‒―]/g, '-').replace(/,/g, '\n'); 
        startAnalysis();
    }

    // Handle clear button visibility based on input content
    const searchInput = document.getElementById('cve-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', updateClearButtonVisibility);
        updateClearButtonVisibility(); // Initial check on load
    }

    // Details page initialization & hash change binding
    if (document.body.dataset.page === 'details') {
        window.onhashchange = startDetailsAnalysis;
        startDetailsAnalysis();
    }
});

// ==========================================
// SHARED HELPER FOR UNIFIED API
// ==========================================

async function fetchUnifiedCveData(cveId) {
    const parts = cveId.split('-');
    const year = parts[1];
    try {
        const res = await fetch(`https://lucacapacci.github.io/cve/${year}/${cveId}.json`);
        if (!res.ok) return null;
        return await res.json();
    } catch (e) {
        console.error(`Failed to fetch CVE data for ${cveId}:`, e);
        return null;
    }
}

function getBestCvss(cvssList) {
    if (!cvssList || !Array.isArray(cvssList) || cvssList.length === 0) return {};
    if (cvssList.length === 1) return cvssList[0];

    const getVersion = (item) => {
        const vec = item.vectorString || String(item.version || "");
        const match = vec.match(/(?:CVSS:)?(\d+)(?:\.(\d+))?/i);
        if (match) {
            const major = parseInt(match[1], 10);
            const minor = match[2] ? parseInt(match[2], 10) : 0;
            return major + (minor / 10);
        }
        return 0;
    };

    const getSourcePriority = (item) => {
        const src = (item.source || "").trim().toUpperCase();
        if (src === "NVD") return 1;                  // Exactly "NVD"
        if (src === "CVELIST (CNA)") return 2;      // Exactly "CVELIST (CNA)"
        return 3;                                   // Everything else
    };

    const sorted = [...cvssList].map((item, index) => ({
        item,
        index,
        version: getVersion(item),
        sourcePrio: getSourcePriority(item)
    }));

    sorted.sort((a, b) => {
        if (b.version !== a.version) {
            return b.version - a.version; // Newer version first
        }
        if (a.sourcePrio !== b.sourcePrio) {
            return a.sourcePrio - b.sourcePrio; // Exact "NVD" (1) then exact "CVELIST (CNA)" (2) then others (3)
        }
        return a.index - b.index; // Stable sort preserving original order
    });

    return sorted[0].item;
}

function updateClearButtonVisibility() {
    const inputEl = document.getElementById('cve-search-input');
    const clearBtn = document.querySelector('.clear-btn');
    if (!inputEl || !clearBtn) return;

    if (inputEl.value.trim() === '') {
        clearBtn.style.display = 'none';
    } else {
        clearBtn.style.display = ''; // Reverts to default CSS layout when text is present
    }
}

function renderHeader() {
    const currentPage = document.body.dataset.page || 'home';

    const navLinks = [
        { name: 'Home', href: 'index.html', key: 'home' },
        { name: 'Search', href: 'search.html', key: 'search', onclick: "scrollToSearch()" },
        { name: 'News', href: 'news.html', key: 'news', onclick: "scrollToSection('sightings-section')" },
        { name: 'API', href: 'api.html', key: 'api', onclick: "scrollToSection('api-section')" },
        { name: 'About', href: 'about.html', key: 'about' }
    ];

    let navHtml = '';
    navLinks.forEach(link => {
        const isActive = currentPage === link.key ? 'active-nav' : '';
        const onclickAttr = link.onclick ? `onclick="${link.onclick}"` : '';
        const badgeHtml = link.badge ? `<span class="tag-new">${link.badge}</span>` : '';
        const styleAttr = link.key === 'api' ? 'style="position: relative;"' : '';

        navHtml += `<a href="${link.href}" class="nav-link ${isActive}" ${onclickAttr} ${styleAttr}>${link.name}${badgeHtml}</a>`;
    });

    const headerHtml = `
        <header>
            <div class="header-inner">
                <a href="index.html" class="brand-logo">
                    <img src="vinthub.svg" alt="Vulnerability Intelligence Hub">
                    <div class="brand-title-group">
                        <span class="brand-title">VULNERABILITY</span>
                        <span class="brand-subtitle">Intelligence Hub</span>
                    </div>
                </a>
                <nav class="main-nav">
                    ${navHtml}
                </nav>
            </div>
        </header>
    `;

    document.body.insertAdjacentHTML('afterbegin', headerHtml);
}

function renderFooter() {
    const footerContainer = document.getElementById('footer-container');
    if (!footerContainer) return;

    const currentYear = new Date().getFullYear();

    footerContainer.innerHTML = `
        <footer>
            <div class="footer-inner">
                <span class="footer-brand">Vinthub © ${currentYear}</span>
                <nav class="footer-nav">
                    <a href="about.html">About & FAQ</a>
                    <a href="https://github.com/lucacapacci/Vulnerability-Intelligence-Hub/" target="_blank" rel="noopener">GitHub</a>
                    <a href="https://github.com/lucacapacci/Vulnerability-Intelligence-Hub/blob/main/LICENSE" target="_blank" rel="noopener">Apache 2.0</a>
                </nav>
            </div>
        </footer>
    `;
}

// Search trigger
function executeAnalysis() {
    const inputEl = document.getElementById('cve-search-input');
    if (!inputEl) return;

    const inputVal = inputEl.value.replace(/[–—−‑‒―]/g, '-');
    const matches = inputVal.match(/cve-\d{4}-\d+/gi) || [];
    const uniqueCves = [...new Set(matches.map(id => id.toUpperCase()))];

    if (uniqueCves.length === 0) {
        alert("Please enter at least one valid CVE ID (e.g., CVE-2026-63030).");
        return;
    }

    window.open('search.html#' + uniqueCves.join(','), '_blank');
}

function clearSearchInput() {
    const inputEl = document.getElementById('cve-search-input');
    if (inputEl) {
        inputEl.value = '';
        updateClearButtonVisibility();
    }
}

// Code Tab Switcher
function switchApiTab(tab) {
    ['curl', 'python'].forEach(t => {
        const tabEl = document.getElementById(`tab-${t}`);
        const codeEl = document.getElementById(`code-${t}`);
        if (tabEl) tabEl.classList.remove('active');
        if (codeEl) codeEl.classList.add('hidden');
    });

    const targetTab = document.getElementById(`tab-${tab}`);
    const targetCode = document.getElementById(`code-${tab}`);
    if (targetTab) targetTab.classList.add('active');
    if (targetCode) targetCode.classList.remove('hidden');
}

function copyCodeSnippet() {
    let textToCopy = '';
    const curlEl = document.getElementById('code-curl');
    const pyEl = document.getElementById('code-python');
    const jsEl = document.getElementById('code-js');

    if (curlEl && !curlEl.classList.contains('hidden')) {
        textToCopy = curlEl.innerText;
    } else if (pyEl && !pyEl.classList.contains('hidden')) {
        textToCopy = pyEl.innerText;
    } else if (jsEl && !jsEl.classList.contains('hidden')) {
        textToCopy = jsEl.innerText;
    } else if (curlEl) {
        textToCopy = curlEl.innerText;
    }

    const tempTextArea = document.createElement('textarea');
    tempTextArea.value = textToCopy;
    document.body.appendChild(tempTextArea);
    tempTextArea.select();
    document.execCommand('copy');
    document.body.removeChild(tempTextArea);

    const copyTextSpan = document.getElementById('copy-code-text');
    if (copyTextSpan) {
        copyTextSpan.innerText = 'Copied!';
        setTimeout(() => { copyTextSpan.innerText = 'Copy'; }, 2000);
    }
}

function showToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerText = msg;
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.transform = 'translateY(0)'; }, 10);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(0.5rem)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function scrollToSearch() {
    const searchSection = document.getElementById('search-section');
    const searchInput = document.getElementById('cve-search-input');
    if (searchSection) searchSection.scrollIntoView({ behavior: 'smooth' });
    if (searchInput) searchInput.focus();
}

function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
}

// ==========================================
// SEARCH PAGE LOGIC
// ==========================================

let globalData = [];
let currentSort = { col: 'score', desc: true };

const capitalize = (str) => {
    if (!str) return "";
    return str.split(/[\s_]+/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
};

const ssvcMap = {
    "Exploitation": { key: "E", values: { "none": "N", "poc": "P", "active": "A" } },
    "Automatable": { key: "A", values: { "no": "N", "yes": "Y" } },
    "Technical Impact": { key: "T", values: { "partial": "P", "total": "T" } }
};

const getSSVCDecision = (vector) => {
    if (!vector || vector === "N/A") return { label: "N/A", key: "N/A" };
    
    const decisionVector = vector.includes('/') ? vector.split('/').slice(1).join('/') : vector;

    const map = {
        "E:N/A:N/T:P": { label: "Track", key: "T" }, "E:N/A:N/T:T": { label: "Track*", key: "R" },
        "E:N/A:Y/T:P": { label: "Attend", key: "A" }, "E:N/A:Y/T:T": { label: "Attend", key: "A" },
        "E:P/A:N/T:P": { label: "Track*", key: "R" }, "E:P/A:N/T:T": { label: "Attend", key: "A" },
        "E:P/A:Y/T:P": { label: "Attend", key: "A" }, "E:P/A:Y/T:T": { label: "Attend", key: "A" },
        "E:A/A:N/T:P": { label: "Attend", key: "A" }, "E:A/A:N/T:T": { label: "Act", key: "C" },
        "E:A/A:Y/T:P": { label: "Act", key: "C" }, "E:A/A:Y/T:T": { label: "Act", key: "C" }
    };
    return map[decisionVector] || { label: "N/A", key: "N/A" };
};

function cleanPocLinks(urls) {
    if (!urls || urls.length === 0) return [];
    let normalized = urls.map(u => {
        let clean = u.trim().replace(/\/$/, "");
        if (clean.includes("securityfocus.com/bid/")) {
            clean = `https://web.archive.org/web/2018/${clean.replace(/^http:\/\//, "https://")}`;
        }
        return clean;
    });
    let uniqueMap = new Map();
    normalized.forEach(url => {
        let purePath = url.replace(/^https?:\/\//, "");
        let isHttps = url.startsWith("https");
        if (!uniqueMap.has(purePath)) {
            uniqueMap.set(purePath, url);
        } else {
            if (isHttps) uniqueMap.set(purePath, url);
        }
    });
    return [...new Set(Array.from(uniqueMap.values()))];
}

function getCvssSeverity(score) {
    if (typeof score !== 'number' || score < 0 || score > 10) return "Invalid Score";
    if (score === 0.0) return "None";
    if (score <= 3.9) return "Low";
    if (score <= 6.9) return "Medium";
    if (score <= 8.9) return "High";
    return "Critical";
}

async function startAnalysis() {
    const cveInputEl = document.getElementById('cveInput');
    if (!cveInputEl) return;

    let input = cveInputEl.value.replace(/[–—−‑‒―]/g, '-');
    cveInputEl.value = input;
    const status = document.getElementById('status');
    if (status) status.innerText = "Working...";
    
    const matches = input.match(/cve-\d{4}-\d+/gi) || [];
    const uniqueCves = [...new Set(matches.map(id => id.toUpperCase()))];
    globalData = [];
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;

    if (uniqueCves.length === 0) {
        if (status) status.innerText = "No CVEs found.";
        return;
    }
    tbody.innerHTML = `<tr><td colspan="14" style="text-align:center; padding: 4rem; color: #94a3b8;">Scanning database...</td></tr>`;

    let processedCount = 0;
    for (const cveId of uniqueCves) {
        processedCount++;
        if (status) status.innerText = `Working... ${processedCount} out of ${uniqueCves.length} done [${Math.round((processedCount / uniqueCves.length) * 100)}%]`;
        
        const data = await fetchUnifiedCveData(cveId);
        if (!data) {
            globalData.push({ 
                cveId, isInvalid: true, published: "—", products: "—", cwe: "—", capec: "—",
                sev: "—", score: 0, vector: "—", ssvc: "—", 
                ssvcDecision: { label: "—", key: "N/A" }, 
                epss: "—", epssVal: 0, kev: "-", knownRansomware: false, pocs: [] 
            });
            renderTable();
            continue; 
        }

        const published = data.published_date?.nvd || data.published_date?.cveorg || "Unpublished";
        const products = data.products || "N/A";
        
        const cvssObj = getBestCvss(data.cvss);
        const score = cvssObj.baseScore || 0;
        const vector = cvssObj.vectorString || "N/A";
        const sev = (cvssObj.baseSeverity || getCvssSeverity(score)).toUpperCase();

        const epssVal = data.epss?.score || 0;
        const epss = data.epss?.score !== undefined ? (data.epss.score * 100).toFixed(3) + "%" : "N/A";

        const kevInfo = data.cisa_kev || {};
        const isKev = kevInfo.in_cisa_kev || false;
        const kev = isKev ? (kevInfo.added_date || "Yes") : "-";
        const knownRansomware = kevInfo.ransomware_campaign_use || false;

        const pocs = cleanPocLinks(data.pocs || []);
        const cwe = (data.cwe || []).map(c => c.id || c).join(', ') || "N/A";
        const capec = (data.capec || []).map(c => c.id || c).join(', ') || "N/A";

        let ssvcVec = "N/A";
        const ssvcFactors = data.ssvc?.factors;
        if (ssvcFactors) {
            const eVal = ssvcMap.Exploitation.values[(ssvcFactors.Exploitation || "").toLowerCase()] || "N";
            const aVal = ssvcMap.Automatable.values[(ssvcFactors.Automatable || "").toLowerCase()] || "N";
            const tVal = (ssvcFactors["Technical Impact"] || "").toLowerCase() === "total" ? "T" : "P";
            ssvcVec = `CISA:2.0.3/E:${eVal}/A:${aVal}/T:${tVal}`;
        } else if (data.bod_sla?.factors) {
            const f = data.bod_sla.factors;
            const eVal = f.in_cisa_kev === "Yes" ? "A" : (pocs.length > 0 ? "P" : "N");
            const aVal = f.automatable === "Yes" ? "Y" : "N";
            const tVal = f.technical_impact === "Total" ? "T" : "P";
            ssvcVec = `CISA:2.0.3/E:${eVal}/A:${aVal}/T:${tVal}`;
        }
        const decision = getSSVCDecision(ssvcVec);

        globalData.push({ 
            cveId, published, products, cwe, capec,
            sev, score, vector, ssvc: ssvcVec, ssvcDecision: decision, 
            epss, epssVal, kev, knownRansomware, pocs 
        });
        renderTable();
    }
    if (status) status.innerText = `Analysis complete. Vulnerabilities: ${globalData.length}`;
}

function renderTable() {
    const filterEl = document.getElementById('tableFilter');
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;

    const filter = filterEl ? filterEl.value.toLowerCase() : '';
    let displayData = globalData.filter(item => Object.values(item).some(val => String(val?.label || val).toLowerCase().includes(filter)));

    const getBOD2604SLA = (ssvcVec, isKev) => {
        if (!ssvcVec || ssvcVec === "N/A") {
            return { ext: "N/A", int: "N/A", extColor: "#94a3b8", extBg: "#1e293b", intColor: "#94a3b8", intBg: "#1e293b" };
        }

        const parts = ssvcVec.split('/');
        const aPart = parts.find(p => p.startsWith('A:'));
        const tPart = parts.find(p => p.startsWith('T:'));
        
        const isA = aPart ? aPart.split(':')[1] === 'Y' : false;
        const isT = tPart ? tPart.split(':')[1] === 'T' : false;
        const isK = isKev;

        const getSla = (isPublic, isK, isA, isT) => {
            if (isK && isT) return "3 Days + Triage";
            if (isPublic) {
                if (!isK && isA && isT) return "3 Days";
                if (!isK && !isA && !isT) return "60 Days";
                return "14 Days"; 
            } else {
                if ((isK && !isT) || (!isK && isA && isT)) return "14 Days";
                if (!isK && !isA && !isT) return "Next Upgrade";
                return "60 Days"; 
            }
        };

        const extSla = getSla(true, isK, isA, isT);
        const intSla = getSla(false, isK, isA, isT);

        return { ext: extSla, int: intSla };
    };

    displayData.sort((a, b) => {
        let valA = a[currentSort.col], valB = b[currentSort.col];
        if (currentSort.col === 'ssvcDecision') { valA = valA.label; valB = valB.label; }
        if (currentSort.col === 'pocs') { valA = valA.length; valB = valB.length; }
        if (currentSort.col === 'bod') {
            const bodA = getBOD2604SLA(a.ssvc, a.kev !== '-').ext;
            const bodB = getBOD2604SLA(b.ssvc, b.kev !== '-').ext;
            const weight = { "3 Days + Triage": 1, "3 Days": 2, "14 Days": 3, "60 Days": 4, "Next Upgrade": 5, "N/A": 6 };
            valA = weight[bodA] || 7;
            valB = weight[bodB] || 7;
        }

        if (typeof valA === 'string') return currentSort.desc ? valB.localeCompare(valA) : valA.localeCompare(valB);
        return currentSort.desc ? valB - valA : valA - valB;
    });

    tbody.innerHTML = displayData.map(item => {
        if (item.isInvalid) {
            return `<tr>
                <td class="no-break"><b style="color:#ef4444">${item.cveId}</b></td>
                <td colspan="13" style="text-align:center; color:#94a3b8; letter-spacing: 0.1em; font-weight: bold; padding: 1rem; background: rgba(239, 68, 68, 0.05);">INVALID ID</td>
            </tr>`;
        }
        
        const isKev = item.kev !== '-';
        const bod = getBOD2604SLA(item.ssvc, isKev);
        
        return `
        <tr>
            <td class="no-break">
                <a href="./details.html#${item.cveId}" style="text-decoration: none;">
                    <b style="color:var(--brand-accent)">${item.cveId}</b>
                </a>
            </td>
            <td style="color:#94a3b8; font-size: 0.75rem;">${item.published}</td>
            <td class="products-cell">
                <div id="prod-text-${item.cveId}" class="products-text truncated">${item.products}</div>
                ${item.products.length > 200 ? `<span id="prod-btn-${item.cveId}" class="toggle-products" onclick="toggleProducts('${item.cveId}')">Show More</span>` : ''}
            </td>
            <td><span class="badge sev-${item.sev.replace('/', '')}">${item.sev}</span></td>
            <td><b style="color:#f1f5f9">${item.score > 0 ? item.score.toFixed(1) : '—'}</b></td>
            <td class="vector-cell">${item.vector}</td>
            <td><span class="badge ssvc-${item.ssvcDecision.key}">${item.ssvcDecision.label}</span></td>
            <td class="vector-cell">${item.ssvc}</td>
            <td>${item.epss}</td>
            <td>
                ${item.kev !== '-' ? `<span class="kev-warning">⚠️ ${item.kev}</span>` : ''}
                ${item.knownRansomware ? `<span class="ransom-badge">☣️ RANSOMWARE</span>` : (item.kev === '-' ? '—' : '')}
            </td>
            <td>
                ${item.pocs.length > 0 ? (
                    item.pocs.length <= 2 
                    ? item.pocs.map((url, idx) => `<a href="${url}" class="poc-btn" target="_blank" title="${url}">💀 ${idx + 1}</a>`).join('')
                    : item.pocs.slice(0, 2).map((url, idx) => `<a href="${url}" class="poc-btn" target="_blank" title="${url}">💀 ${idx + 1}</a>`).join('') + 
                      `<button class="poc-btn" onclick="showAllPocs('${item.cveId}')" style="background:#7f1d1d; color:white; border:none; cursor:pointer;">+${item.pocs.length - 2}</button>`
                ) : '—'}
            </td>
            <td>
                <div style="background: rgba(0, 0, 0, 0.2); font-size: 9px; padding: 4px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1);">
                    <div style="display: grid; grid-template-columns: auto 1fr; gap: 2px 6px; align-items: center;">
                        <span style="color: #94a3b8; text-align: right; padding-bottom: 5px;">PUB:</span>
                        <span style="text-align: left; font-weight: 600; padding-bottom: 5px;">${bod.ext}</span>
                        <span style="color: #94a3b8; text-align: right;">INT:</span>
                        <span style="text-align: left; font-weight: 600;">${bod.int}</span>
                    </div>
                </div>
            </td>
            <td>
                ${item.cwe === "N/A" ? "" : item.cwe.split(', ').map(c => `<a href="https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html" class="cwe-link" target="_blank">${c}</a>`).join(', ')}
                ${item.capec !== "N/A" && item.cwe !== "N/A" ? '<br/>' : ''}
                ${item.capec === "N/A" ? (item.cwe === "N/A" ? "N/A" : "") : item.capec.split(', ').map(c => `<a href="https://capec.mitre.org/data/definitions/${c.replace('CAPEC-', '')}.html" class="capec-link" target="_blank">${c}</a>`).join(', ')}
            </td>
            <td>
                <a class="btn-action btn-nvd" href="https://nvd.nist.gov/vuln/detail/${item.cveId}" target="_blank">NVD ↗</a>
                <a class="btn-action btn-cve" href="https://www.cve.org/CVERecord?id=${item.cveId}" target="_blank">CVE ↗</a>
                ${item.kev !== '-' ? `<a class="btn-action btn-kev-link" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${item.cveId}" target="_blank">KEV ↗</a>` : ''}
            </td>
        </tr>
    `;
    }).join('');
}

function sortTable(col) {
    if (currentSort.col === col) currentSort.desc = !currentSort.desc;
    else { currentSort.col = col; currentSort.desc = true; }
    renderTable();
}

function exportCSV() {
    const headers = ["VULN ID", "CVE/NVD Published", "Product", "Severity", "Score", "Vector", "SSVC Decision", "SSVC Vector", "BOD 26-04 Ext SLA", "BOD 26-04 Int SLA", "EPSS", "KEV", "Ransomware", "PoCs", "CWE", "CAPEC"];
    
    const rows = globalData.map(r => {
        return `"${r.cveId}","${r.published}","${r.products}","${r.sev}",${r.score},"${r.vector}","${r.ssvcDecision.label}","${r.ssvc}","N/A","N/A","${r.epss}","${r.kev}","${r.knownRansomware ? 'Known' : 'Unknown'}","${r.pocs.join('; ')}","${r.cwe}","${r.capec}"`;
    });
    
    const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `CVE_Intelligence_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
}

function generatePermalink() {
    const inputEl = document.getElementById('cveInput');
    if (!inputEl) return;
    const input = inputEl.value;
    const matches = input.match(/cve-\d{4}-\d+/gi) || [];
    const uniqueCves = [...new Set(matches.map(id => id.toUpperCase()))];
    if (uniqueCves.length === 0) return alert("No CVEs to link!");
    const url = `${window.location.origin}${window.location.pathname}#${uniqueCves.join(',')}`;
    navigator.clipboard.writeText(url).then(() => alert("Permalink copied to clipboard!"));
}

function showAllPocs(cveId) {
    const item = globalData.find(d => d.cveId === cveId);
    if (!item) return;
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const pocModal = document.getElementById('pocModal');

    if (modalTitle) modalTitle.innerText = `PoCs for ${cveId}`;
    if (modalBody) {
        modalBody.innerHTML = item.pocs.map((url, idx) => 
            `<a href="${url}" class="poc-btn" style="font-size: 13px;" target="_blank" title="${url}">💀 #${idx + 1}</a>`
        ).join('');
    }
    if (pocModal) pocModal.style.display = 'block';
}

function closePocModal() { 
    const pocModal = document.getElementById('pocModal');
    if (pocModal) pocModal.style.display = 'none'; 
}

window.addEventListener('click', (event) => {
    const pocModal = document.getElementById('pocModal');
    if (pocModal && event.target === pocModal) {
        closePocModal();
    }
});

function toggleProducts(cveId) {
    const textElement = document.getElementById(`prod-text-${cveId}`);
    const btnElement = document.getElementById(`prod-btn-${cveId}`);
    
    if (!textElement || !btnElement) return;

    if (textElement.classList.contains('truncated')) {
        textElement.classList.remove('truncated');
        btnElement.innerText = 'Show Less';
    } else {
        textElement.classList.add('truncated');
        btnElement.innerText = 'Show More';
    }
}

// ==========================================
// DETAILS PAGE LOGIC & CVSS PARSERS
// ==========================================

const cvss2Labels = {
    AV: { name: "Access Vector", N: "Network", A: "Adjacent", L: "Local" },
    AC: { name: "Access Complexity", L: "Low", M: "Medium", H: "High" },
    Au: { name: "Authentication", N: "None", S: "Single", M: "Multiple" },
    C: { name: "Confidentiality Impact", N: "None", P: "Partial", C: "Complete" },
    I: { name: "Integrity Impact", N: "None", P: "Partial", C: "Complete" },
    A: { name: "Availability Impact", N: "None", P: "Partial", C: "Complete" }
};

const cvss3Labels = {
    AV: { name: "Attack Vector", N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    AC: { name: "Attack Complexity", L: "Low", H: "High" },
    PR: { name: "Privileges Required", N: "None", L: "Low", H: "High" },
    UI: { name: "User Interaction", N: "None", R: "Required" },
    S: { name: "Scope", U: "Unchanged", C: "Changed" },
    C: { name: "Confidentiality Impact", N: "None", L: "Low", H: "High" },
    I: { name: "Integrity Impact", N: "None", L: "Low", H: "High" },
    A: { name: "Availability Impact", N: "None", L: "Low", H: "High" }
};

const cvss4Labels = {
    // Base Metrics
    AV: { name: "Attack Vector", N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    AC: { name: "Attack Complexity", L: "Low", H: "High" },
    AT: { name: "Attack Requirements", N: "None", P: "Present" },
    PR: { name: "Privileges Required", N: "None", L: "Low", H: "High" },
    UI: { name: "User Interaction", N: "None", P: "Passive", A: "Active" },
    VC: { name: "Vulnerability Confidentiality", H: "High", L: "Low", N: "None" },
    VI: { name: "Vulnerability Integrity", H: "High", L: "Low", N: "None" },
    VA: { name: "Vulnerability Availability", H: "High", L: "Low", N: "None" },
    SC: { name: "Subsequent Confidentiality", H: "High", L: "Low", N: "None" },
    SI: { name: "Subsequent Integrity", H: "High", L: "Low", N: "None" },
    SA: { name: "Subsequent Availability", H: "High", L: "Low", N: "None" },
    // Threat Metrics
    E: { name: "Exploitation", X: "Not Defined", U: "Unproven", P: "Proof-of-Concept", A: "Attacking" },
    // Environmental Requirements
    CR: { name: "Confidentiality Requirement", X: "Not Defined", L: "Low", M: "Medium", H: "High" },
    IR: { name: "Integrity Requirement", X: "Not Defined", L: "Low", M: "Medium", H: "High" },
    AR: { name: "Availability Requirement", X: "Not Defined", L: "Low", M: "Medium", H: "High" },
    // Modified Base Metrics
    MAV: { name: "Modified Attack Vector", X: "Not Defined", N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    MAC: { name: "Modified Attack Complexity", X: "Not Defined", L: "Low", H: "High" },
    MAT: { name: "Modified Attack Requirements", X: "Not Defined", N: "None", P: "Present" },
    MPR: { name: "Modified Privileges Required", X: "Not Defined", N: "None", L: "Low", H: "High" },
    MUI: { name: "Modified User Interaction", X: "Not Defined", N: "None", P: "Passive", A: "Active" },
    MVC: { name: "Modified Vulnerability Confidentiality", X: "Not Defined", H: "High", L: "Low", N: "None" },
    MVI: { name: "Modified Vulnerability Integrity", X: "Not Defined", H: "High", L: "Low", N: "None" },
    MVA: { name: "Modified Vulnerability Availability", X: "Not Defined", H: "High", L: "Low", N: "None" },
    MSC: { name: "Modified Subsequent Confidentiality", X: "Not Defined", H: "High", L: "Low", N: "None" },
    MSI: { name: "Modified Subsequent Integrity", X: "Not Defined", H: "High", L: "Low", N: "None" },
    MSA: { name: "Modified Subsequent Availability", X: "Not Defined", H: "High", L: "Low", N: "None" },
    // Supplementary Metrics
    S: { name: "Safety", X: "Not Defined", N: "Negligible", P: "Present" },
    AU: { name: "Automatable", X: "Not Defined", Y: "Yes", N: "No" },
    R: { name: "Recovery", X: "Not Defined", A: "Automatic", U: "User", I: "Irrecoverable" },
    V: { name: "Value Density", X: "Not Defined", D: "Diffuse", C: "Concentrated", F: "Focused" },
    RE: { name: "Response Effort", X: "Not Defined", L: "Low", M: "Moderate", H: "High" },
    U: { name: "Provider Urgency", X: "Not Defined", C: "Clear", G: "Green", A: "Amber", R: "Red" }
};

function parseCvssMetrics(vectorString) {
    if (!vectorString || vectorString === "N/A") return [];
    
    let parts = vectorString.split('/');
    let version = "";
    let metrics = parts;
    
    if (parts[0].startsWith("CVSS:")) {
        version = parts[0];
        metrics = parts.slice(1);
    }
    
    let labelsMap = cvss3Labels;
    const isV4 = version.startsWith("CVSS:4");
    const isV2 = version.startsWith("CVSS:2") || (!version.startsWith("CVSS:") && metrics.some(m => m.startsWith("Au:")));

    if (isV4) {
        labelsMap = cvss4Labels;
    } else if (isV2) {
        labelsMap = cvss2Labels;
    } else {
        labelsMap = cvss3Labels;
    }

    const results = [];
    metrics.forEach(item => {
        const [k, v] = item.split(':');
        if (!k || !v) return;
        
        const metricConfig = labelsMap[k];
        const label = metricConfig ? metricConfig.name : k;
        
        let value = "";
        if (metricConfig && metricConfig[v]) {
            value = metricConfig[v];
        } else if (v === 'X') {
            value = "Not Defined";
        } else {
            value = capitalize(v.toLowerCase());
        }
        
        results.push(`<div class="metric-item"><div class="metric-label">${label}</div><div class="metric-val">${value}</div></div>`);
    });
    
    return results;
}

function highlightJSON(jsonObj) {
    let json = JSON.stringify(jsonObj, null, 2);
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'json-number';
        if (/^"/.test(match)) {
            cls = /:$/.test(match) ? 'json-key' : 'json-string';
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

function compareVersions(v1, v2) {
    if (!v1 || !v2) return 0;
    if (!isNaN(v1) && !isNaN(v2)) {
        const n1 = Number(v1), n2 = Number(v2);
        if (n1 !== n2) return n1 > n2 ? 1 : -1;
        return 0;
    }
    const p1 = String(v1).split(/[\.\-_]/);
    const p2 = String(v2).split(/[\.\-_]/);
    for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
        const s1 = p1[i];
        const s2 = p2[i];
        if (s1 === undefined) return s2 === "0" ? 0 : -1;
        if (s2 === undefined) return s1 === "0" ? 0 : 1;
        const isNum1 = /^\d+$/.test(s1);
        const isNum2 = /^\d+$/.test(s2);
        if (isNum1 && isNum2) {
            const n1 = parseInt(s1, 10);
            const n2 = parseInt(s2, 10);
            if (n1 !== n2) return n1 > n2 ? 1 : -1;
        } else if (isNum1 || isNum2) {
            return isNum1 ? 1 : -1;
        } else {
            const cmp = s1.localeCompare(s2);
            if (cmp !== 0) return cmp < 0 ? -1 : 1;
        }
    }
    return 0;
}

function checkIsVulnerable(targetProduct, targetVersion, targetPlatform, rawAffected) {
    let matchedExplicitly = false;
    let isExplicitlyUnaffected = false;
    let matchedByDefault = false;
    let isUndetermined = false;
    const tProd = targetProduct.toLowerCase();
    
    if (rawAffected.nvd_cpes) {
        rawAffected.nvd_cpes.forEach(node => {
            if (!node.nodes) return;
            node.nodes.forEach(n => {
                if (!n.cpeMatch) return;
                n.cpeMatch.forEach(m => {
                    const parts = m.criteria.split(':');
                    if (parts.length >= 6) {
                        const cpeProd = parts[4].toLowerCase().replace(/_/g, ' ');
                        if (tProd === cpeProd || tProd.includes(cpeProd) || cpeProd.includes(tProd)) {
                            const exactVersion = parts[5];
                            const hasRange = m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding;
                            
                            if (exactVersion !== '*' && exactVersion !== '-') {
                                if (compareVersions(exactVersion, targetVersion) === 0) matchedExplicitly = true;
                            }
                            
                            if (hasRange) {
                                let inRange = true;
                                if (m.versionStartIncluding && compareVersions(targetVersion, m.versionStartIncluding) < 0) inRange = false;
                                if (m.versionStartExcluding && compareVersions(targetVersion, m.versionStartExcluding) <= 0) inRange = false;
                                if (m.versionEndIncluding && compareVersions(targetVersion, m.versionEndIncluding) > 0) inRange = false;
                                if (m.versionEndExcluding && compareVersions(targetVersion, m.versionEndExcluding) >= 0) inRange = false;
                                if (inRange) matchedExplicitly = true;
                            } else if (exactVersion === '*' || exactVersion === '-') {
                                isUndetermined = true;
                            }
                        }
                    }
                });
            });
        });
    }
    
    if (rawAffected.cna_affected) {
        for (const a of rawAffected.cna_affected) {
            const aProd = (a.product || "").toLowerCase();
            const aPkg = (a.packageName || "").toLowerCase();
            
            const prodMatch = aProd && (tProd === aProd || tProd.includes(aProd) || aProd.includes(tProd));
            const pkgMatch = aPkg && (tProd === aPkg || tProd.includes(aPkg) || aPkg.includes(tProd));

            if (prodMatch || pkgMatch) {
                let matchedAnyCnaVersion = false;
                if (a.versions && a.versions.length > 0) {
                    for (const v of a.versions) {
                        const start = v.version;
                        let inRange = false;

                        const isAll = start && start.toLowerCase() === 'all';
                        const isVague = !isAll && (!start || start === '*' || start === 'unspecified' || start === 'n/a' || start === '-' || start.toLowerCase().includes('custom') || start.toLowerCase().includes('reference'));
                        
                        if (isAll) {
                            inRange = true;
                        } else if (!isVague && !v.lessThan && !v.lessThanOrEqual) {
                            inRange = (compareVersions(targetVersion, start) === 0);
                        } else if (v.lessThan || v.lessThanOrEqual || (!isVague && start !== undefined)) {
                            inRange = true;
                            if (start && !isVague) {
                                if (compareVersions(targetVersion, start) < 0) inRange = false;
                            }
                            if (v.lessThan && v.lessThan !== '*') {
                                if (compareVersions(targetVersion, v.lessThan) >= 0) inRange = false;
                            }
                            if (v.lessThanOrEqual && v.lessThanOrEqual !== '*') {
                                if (compareVersions(targetVersion, v.lessThanOrEqual) > 0) inRange = false;
                            }
                        } else if (isVague) {
                            isUndetermined = true;
                        }

                        if (inRange) {
                            matchedAnyCnaVersion = true;
                            if (v.status === "unaffected") {
                                isExplicitlyUnaffected = true;
                            } else if (v.status === "affected") {
                                matchedExplicitly = true;
                            }
                        }
                    }
                }

                if (!matchedAnyCnaVersion && a.defaultStatus === "affected") {
                    matchedByDefault = true;
                }
            }
        }
    }
    
    if (isExplicitlyUnaffected) return "not_vulnerable";
    if (matchedExplicitly || matchedByDefault) return "vulnerable";
    if (isUndetermined) return "undetermined";
    return "not_vulnerable";
}

async function startDetailsAnalysis() {
    const hash = decodeURIComponent(window.location.hash.substring(1)).toUpperCase().replace(/[–—−‑‒―]/g, '-');
    const input = hash.match(/CVE-\d{4}-\d+/) ? hash : null;
    if (!input) return;

    document.getElementById('loading').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('kevRansomware').style.display = 'none';

    const data = await fetchUnifiedCveData(input);
    if (!data) {
        document.getElementById('loading').innerHTML = `<span style="color:red">Error: CVE Data not found</span>`;
        return;
    }

    document.getElementById('displayDesc').innerText = data.description || "Description not available.";
    document.getElementById('displayProducts').innerText = data.products || "N/A";

    let rawAffected = data.affected || {};
    const vcSection = document.getElementById('versionCheckerSection');
    const btnRaw = document.getElementById('btnViewAffectedRaw');
    const preRaw = document.getElementById('rawAffectedData');

    if (Object.keys(rawAffected).length > 0) {
        vcSection.style.display = 'block';
        const vcProduct = document.getElementById('vcProduct');
        const productsList = (data.products || "").split(',').map(p => p.trim()).filter(Boolean);
        
        vcProduct.innerHTML = (productsList.length === 1 ? '' : '<option value="">Select a product...</option>') + 
            productsList.map(p => `<option value="${p.toLowerCase()}">${p}</option>`).join('');

        document.getElementById('vcSubmit').onclick = () => {
            const prod = vcProduct.value;
            const ver = document.getElementById('vcVersion').value.trim();
            const resDiv = document.getElementById('vcResult');
            
            if (!prod || !ver) {
                resDiv.innerText = "⚠️ Please select a product and enter a version number.";
                resDiv.style.color = "#94a3b8";
                return;
            }
            
            const status = checkIsVulnerable(prod, ver, null, rawAffected); 
            
            if (status === "vulnerable") {
                resDiv.innerText = "VULNERABLE: the provided version falls within the affected ranges.";
                resDiv.style.color = "var(--brand-critical)";
            } else if (status === "undetermined") {
                resDiv.innerText = "UNDETERMINED: Vulnerability status cannot be strictly determined due to a lack of precise version data in the original record.";
                resDiv.style.color = "var(--ssvc-track)";
            } else {
                resDiv.innerText = "NOT VULNERABLE: the provided version is outside known affected ranges.";
                resDiv.style.color = "#4ade80";
            }
        };

        btnRaw.style.display = 'inline-block';
        btnRaw.textContent = 'View all affected versions';
        preRaw.style.display = 'none';
        preRaw.innerHTML = highlightJSON(rawAffected);
        
        btnRaw.onclick = () => {
            if (preRaw.style.display === 'none') {
                preRaw.style.display = 'block';
                btnRaw.textContent = 'Hide all affected versions';
                btnRaw.style.background = 'var(--brand-accent)';
            } else {
                preRaw.style.display = 'none';
                btnRaw.textContent = 'View all affected versions';
                btnRaw.style.background = 'var(--brand-input)';
            }
        };
    } else {
        vcSection.style.display = 'none';
        btnRaw.style.display = 'none';
        preRaw.style.display = 'none';
    }

    const cvssObj = getBestCvss(data.cvss);
    const score = cvssObj.baseScore || 0;
    const sev = (cvssObj.baseSeverity || getCvssSeverity(score)).toUpperCase();
    const vector = cvssObj.vectorString || "N/A";

    document.getElementById('displayScore').innerText = score > 0 ? score.toFixed(1) : '—';
    document.getElementById('displaySevBadge').innerText = sev;
    document.getElementById('displaySevBadge').className = `badge-large sev-${sev.replace('/', '')}`;
    document.getElementById('displayVector').innerText = vector;

    // Use vector parser to populate metrics breakdown
    const metricsHtml = parseCvssMetrics(vector);
    document.getElementById('displayMetrics').innerHTML = metricsHtml.length > 0 ? metricsHtml.join('') : '<div class="metric-item">No extra metrics available</div>';

    let weaknessHtml = [];
    (data.cwe || []).forEach(c => {
        const id = c.id || c;
        const desc = c.description || "";
        weaknessHtml.push(`<div class="weakness-item"><a href="https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html" class="cwe-link" target="_blank">${id}</a>${desc ? `<div class="weakness-desc">${desc}</div>` : ''}</div>`);
    });
    (data.capec || []).forEach(c => {
        const id = c.id || c;
        const desc = c.description || "";
        weaknessHtml.push(`<div class="weakness-item"><a href="https://capec.mitre.org/data/definitions/${id.replace('CAPEC-', '')}.html" class="capec-link" style="color: #fca5a5" target="_blank">${id}</a>${desc ? `<div class="weakness-desc">${desc}</div>` : ''}</div>`);
    });
    document.getElementById('weaknessContainer').innerHTML = weaknessHtml.length > 0 ? weaknessHtml.join('') : "N/A";

    const finalPocs = cleanPocLinks(data.pocs || []);
    document.getElementById('pocContainer').innerHTML = finalPocs.length > 0 ? finalPocs.map((url, i) => `<a href="${url}" class="poc-link" target="_blank">💀 #${i+1}</a>`).join('') : "-";

    const refs = data.references || [];
    document.getElementById('refList').innerHTML = refs.length > 0 ? refs.map(url => `<li><a href="${url}" target="_blank">${url}</a></li>`).join('') : "-";

    const epssVal = data.epss?.score;
    document.getElementById('displayEpss').innerText = epssVal !== undefined ? (epssVal * 100).toFixed(3) + "%" : "N/A";

    const kevInfo = data.cisa_kev || {};
    const isKev = kevInfo.in_cisa_kev || false;
    let kevMarkup = "";
    if (isKev) {
        document.getElementById('kevAlert').style.display = 'flex';
        document.getElementById('kevDate').innerText = `Added: ${kevInfo.added_date || 'N/A'}`;
        if (kevInfo.ransomware_campaign_use) {
            document.getElementById('kevRansomware').style.display = 'flex';
        }
        kevMarkup = `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${input}" class="btn-action" style="background:#7f1d1d" target="_blank">CISA KEV ↗</a>`;
    }

    const ssvcDisplayMap = {
        Exploitation: { N: "None", P: "PoC", A: "Active", none: "None", poc: "PoC", active: "Active" },
        Automatable: { N: "No", Y: "Yes", no: "No", yes: "Yes" },
        "Technical Impact": { P: "Partial", T: "Total", partial: "Partial", total: "Total" }
    };

    let ssvcVec = "N/A";
    let ssvcMeta = [];
    const ssvcFactors = data.ssvc?.factors;
    if (ssvcFactors) {
        let exploitation = ssvcFactors.Exploitation || "N";
        let automatable = ssvcFactors.Automatable || "N";
        let techImpact = ssvcFactors["Technical Impact"] || "Partial";

        if (isKev && exploitation.toLowerCase() !== "active") exploitation = "Active";

        const expVal = ssvcDisplayMap.Exploitation[exploitation] || capitalize(exploitation);
        const autVal = ssvcDisplayMap.Automatable[automatable] || capitalize(automatable);
        const tecVal = ssvcDisplayMap["Technical Impact"][techImpact] || capitalize(techImpact);

        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Exploitation</div><div class="metric-val">${expVal}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">${autVal}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">${tecVal}</div></div>`);

        const eChar = ssvcMap.Exploitation.values[exploitation.toLowerCase()] || "N";
        const aChar = ssvcMap.Automatable.values[automatable.toLowerCase()] || "N";
        const tChar = techImpact.toLowerCase() === "total" ? "T" : "P";
        ssvcVec = `CISA:2.0.3/E:${eChar}/A:${aChar}/T:${tChar}`;
    }

    const dec = getSSVCDecision(ssvcVec);
    document.getElementById('displaySsvcDec').innerText = dec.label;
    document.getElementById('displaySsvcDec').className = `badge-large ssvc-${dec.key}`;
    document.getElementById('displaySsvcVector').innerText = ssvcVec;
    document.getElementById('ssvcExpansion').innerHTML = ssvcMeta.join('');

    const bod = data.bod_sla || {};
    document.getElementById('bodSlaPublic').innerText = bod.public || "N/A";
    document.getElementById('bodSlaInternal').innerText = bod.internal || "N/A";
    document.getElementById('bodExpansion').innerHTML = `
        <div class="metric-item"><div class="metric-label">In KEV</div><div class="metric-val">${isKev ? "Yes" : "No"}</div></div>
        <div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">${bod.factors?.automatable || "No"}</div></div>
        <div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">${bod.factors?.technical_impact || "Partial"}</div></div>
    `;

    document.getElementById('displayId').innerText = input;
    const pubDate = data.published_date?.nvd || data.published_date?.cveorg || "Unpublished";
    document.getElementById('displayPubDate').innerText = pubDate;
    document.getElementById('linkContainer').innerHTML = `<a href="https://nvd.nist.gov/vuln/detail/${input}" class="btn-action" style="background:#475569" target="_blank">NVD ↗</a><a href="https://www.cve.org/CVERecord?id=${input}" class="btn-action" style="background:#312e81" target="_blank">CVE.org ↗</a>${kevMarkup}`;

    let articles = data.news || [];
    articles.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    const newsContainer = document.getElementById('newsContainer');
    newsContainer.innerHTML = articles.length > 0 ? articles.map(art => `
        <li>
            <span class="article-date">${art.date}</span>
            <a href="${art.link}" target="_blank">${art.title}</a>
        </li>
    `).join('') : `<li><span style="color: #94a3b8">No news history available.</span></li>`;

    document.getElementById('loading').style.display = 'none';
    document.getElementById('dashboard').style.display = 'grid';
}

// ==========================================
// NEWS PAGE LOGIC
// ==========================================

let currentDate = new Date();
let maxAllowedDate = null;
const hashDate = window.location.hash.replace('#', '').trim();
if (/^\d{4}-\d{2}-\d{2}$/.test(hashDate)) {
    currentDate = new Date(`${hashDate}T00:00:00Z`);
    maxAllowedDate = hashDate;
} else {
    currentDate.setDate(currentDate.getDate() + 1);
}
let seenCves = new Set();

async function updateStatus(text, id = 'status-text') {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
    
    const btn = document.getElementById('loadMoreBtn');
    if (btn && btn.disabled) btn.innerText = text;
}

async function fetchCveDetailsData(input) {
    const data = await fetchUnifiedCveData(input);
    if (!data) throw new Error("CVE not found");

    const cvssObj = getBestCvss(data.cvss);
    const score = cvssObj.baseScore !== undefined ? cvssObj.baseScore : 0;
    const severity = (cvssObj.baseSeverity || getCvssSeverity(score)).toUpperCase();
    const vector = cvssObj.vectorString || "Vector N/A";
    
    const finalPocs = cleanPocLinks(data.pocs || []);
    let articles = (data.news || []).filter(art => !art.listOnly);
    const hasLaterDiscussion = maxAllowedDate && articles.length > 0 && articles.every(art => art.date > maxAllowedDate);

    if (maxAllowedDate) {
        articles = articles.filter(art => art.date <= maxAllowedDate);
    }
    articles.sort((a, b) => new Date(b.date) - new Date(a.date));

    const kevInfo = data.cisa_kev || {};
    const isKev = kevInfo.in_cisa_kev || false;
    const kevDate = kevInfo.added_date || "-";
    const knownRansomware = kevInfo.ransomware_campaign_use || false;
    const products = data.products || "N/A";

    return {
        id: input,
        score: score !== 0 ? score.toFixed(1) : "Score N/A",
        severity: severity,
        vector: vector,
        pocs: finalPocs,
        articles: articles,
        hasLaterDiscussion: hasLaterDiscussion,
        isKev: isKev,
        kevDate: kevDate,
        knownRansomware: knownRansomware,
        products: products
    };
}

async function fetchNextAvailableDay() {
    let loopSafety = 0;
    let dayCves = [];
    let foundDate = '';

    while (dayCves.length === 0 && loopSafety < 30) {
        loopSafety++;
        let y = currentDate.getUTCFullYear();
        let m = String(currentDate.getUTCMonth() + 1).padStart(2, '0');
        let d = String(currentDate.getUTCDate()).padStart(2, '0');
        let dateStr = `${y}-${m}-${d}`;
        
        let url = `https://lucacapacci.github.io/cve_news/news/${y}/${m}/${dateStr}.json?${Math.random().toString(36).substring(2, 10)}`;
        await updateStatus(`Checking news for ${dateStr}...`, 'status-text');

        try {
            let res = await fetch(url);
            if (res.ok) {
                let data = await res.json();
                for (let cve in data) {
                    const hasNewsArticle = Array.isArray(data[cve]) && data[cve].some(item => !item.listOnly);
                    if (hasNewsArticle && !seenCves.has(cve)) {
                        seenCves.add(cve);
                        dayCves.push({ id: cve, date: dateStr });
                    }
                }
                if (dayCves.length > 0) foundDate = dateStr;
            }
        } catch (e) { console.warn(`Could not fetch ${url}`); }
        
        currentDate.setUTCDate(currentDate.getUTCDate() - 1);
        if (foundDate) break;
    }
    
    return { date: foundDate, cves: dayCves };
}

async function renderDay(dayData) {
    const { date, cves } = dayData;
    if (!date || cves.length === 0) return;

    const dashboard = document.getElementById('dashboard');
    let processedDetails = [];
    
    let stats = {
        severities: {
            CRITICAL: { total: 0, kev: 0, poc: 0 },
            HIGH: { total: 0, kev: 0, poc: 0 },
            MEDIUM: { total: 0, kev: 0, poc: 0 },
            LOW: { total: 0, kev: 0, poc: 0 },
            INFO: { total: 0, kev: 0, poc: 0 },
            UNKNOWN: { total: 0, kev: 0, poc: 0 }
        },
        products: new Set()
    };

    for (let i = 0; i < cves.length; i++) {
        const cveId = cves[i].id;
        let percent = Math.round(((i + 1) / cves.length) * 100);
        await updateStatus(`Processing info for ${cveId}... (${percent}%)`);
        
        try {
            const details = await fetchCveDetailsData(cveId);
            if (details.hasLaterDiscussion) continue;

            processedDetails.push(details);

            let sev = details.severity || 'UNKNOWN';
            if (sev.includes('N/A') || sev === 'NONE') sev = 'UNKNOWN';
            if (stats.severities[sev] === undefined) sev = 'UNKNOWN';
            
            stats.severities[sev].total++;
            if (details.isKev) stats.severities[sev].kev++;
            if (details.pocs && details.pocs.length > 0) stats.severities[sev].poc++;
            
            if (details.products && details.products !== "N/A") {
                details.products.split(',').forEach(p => {
                    if (p.trim()) stats.products.add(p.trim());
                });
            }
        } catch (e) {
            console.warn(`Failed to process ${cveId}`, e);
        }
    }

    if (processedDetails.length === 0) return;

    let productsArr = Array.from(stats.products).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    let productsHtml = "None identified";
    
    if (productsArr.length > 0) {
        let productsLimit = 10;
        if (productsArr.length <= productsLimit) {
            productsHtml = `<span style="color: var(--text-main);">${productsArr.join(', ')}</span>`;
        } else {
            const firstN = productsArr.slice(0, productsLimit).join(', ');
            const rest = ', ' + productsArr.slice(productsLimit).join(', ');
            const safeDateId = date.replace(/-/g, '');
            
            productsHtml = `
                <span style="color: var(--text-main);">${firstN}</span><span id="more-prod-${safeDateId}" style="display: none; color: var(--text-main);">${rest}
                <a href="javascript:void(0)" onclick="document.getElementById('more-prod-${safeDateId}').style.display='none'; document.getElementById('btn-more-${safeDateId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-weight: bold; margin-left: 4px;">(show less)</a></span>
                <a id="btn-more-${safeDateId}" href="javascript:void(0)" onclick="document.getElementById('more-prod-${safeDateId}').style.display='inline'; this.style.display='none';" style="color: var(--accent); text-decoration: none; font-weight: bold; margin-left: 4px;"><br>+${productsArr.length - productsLimit} more...</a>
            `;
        }
    }

    const totalCves = processedDetails.length;
    const totalKev = Object.values(stats.severities).reduce((sum, s) => sum + s.kev, 0);
    const totalPoc = Object.values(stats.severities).reduce((sum, s) => sum + s.poc, 0);

    const renderTotal = () => {
        const kevText = totalKev > 0 ? `<span style="color:#fca5a5;">⚠️ KEV: ${totalKev}</span>` : '<span style="color:#bababa;">No KEV</span>';
        const pocText = totalPoc > 0 ? `<span style="color:#fb7185;">💀 PoC: ${totalPoc}</span>` : '<span style="color:#bababa;">No PoC</span>';
        return `
            <div class="metric-card metric-TOTAL">
                <div class="metric-num">${totalCves}</div>
                <div class="metric-label" style="color: #f8fafc;">Total CVEs</div>
                <div class="metric-extras">${kevText}${pocText}</div>
            </div>
        `;
    };

    const renderBadge = (label, key) => {
        const s = stats.severities[key];
        if (s.total === 0) return '';
        const kevText = s.kev > 0 ? `<span style="color:#fca5a5;">⚠️ KEV: ${s.kev}</span>` : '<span style="color:#bababa;">No KEV</span>';
        const pocText = s.poc > 0 ? `<span style="color:#fb7185;">💀 PoC: ${s.poc}</span>` : '<span style="color:#bababa;">No PoC</span>';
        return `
            <div class="metric-card metric-${key}">
                <div class="metric-num">${s.total}</div>
                <div class="metric-label">${label}</div>
                <div class="metric-extras">${kevText}${pocText}</div>
            </div>
        `;
    };

    const summaryHtml = `
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; margin-bottom: 0.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <h2 style="margin: 0 0 1rem 0; color: var(--text-main); font-size: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem;">
                🗓️ Last talked about on ${date}
            </h2>
            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1.25rem;">
                ${renderTotal()}
                ${renderBadge('CRITICAL', 'CRITICAL')}
                ${renderBadge('HIGH', 'HIGH')}
                ${renderBadge('MEDIUM', 'MEDIUM')}
                ${renderBadge('LOW', 'LOW')}
                ${renderBadge('INFO', 'INFO')}
                ${renderBadge('UNKNOWN', 'UNKNOWN')}
            </div>
            <div style="font-size: 0.95rem; color: var(--text-muted); line-height: 1.5;">
                <strong>Products:</strong> <span style="color: var(--text-main);">${productsHtml}</span>
            </div>
        </div>
    `;
    dashboard.insertAdjacentHTML('beforeend', summaryHtml);

    const sevRank = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'NONE': 1, 'UNKNOWN': 0 };
    processedDetails.sort((a, b) => {
        const scoreA = parseFloat(a.score) || 0;
        const scoreB = parseFloat(b.score) || 0;
        if (scoreB !== scoreA) return scoreB - scoreA;
        return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    });

    for (const details of processedDetails) {
        const pocHtml = details.pocs.length > 0 
            ? `<div class="poc-grid">${details.pocs.map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${i+1}</a>`).join('')}</div>` 
            : `<span style="color: var(--text-muted); font-size: 0.85rem;">No public PoCs</span>`;

        const articlesHtml = details.articles.length > 0
            ? details.articles.map(art => `
                <li>
                    <span class="article-date">${art.date}</span>
                    <a href="${art.link}" target="_blank">${art.title}</a>
                </li>
            `).join('')
            : `<li><span style="color: var(--text-muted)">No tracking history available.</span></li>`;
        
        const kevHtml = details.isKev ? `<span class="badge-large kev-badge" title="Added to CISA KEV on ${details.kevDate}">⚠️ KEV</span>` : '';
        const ransomwareHtml = details.knownRansomware ? `<span class="badge-large ransomware-badge" title="Known Ransomware Campaign Use">☣️ Ransomware</span>` : '';

        const cardHtml = `
            <div class="news-card">
                <div class="news-header-row">
                    <h2 class="hero-id"><a href="details.html#${details.id}" class="hero-id">${details.id}</a></h2>
                    <span class="badge-large sev-${details.severity}">${details.severity}</span>
                    <span class="score-display">${details.score}</span>
                    ${kevHtml}
                    ${ransomwareHtml}
                    <div class="vector-box" title="${details.vector}">${details.vector}</div>
                    
                    <div class="actions-group">
                        <a href="https://nvd.nist.gov/vuln/detail/${details.id}" class="btn-action" style="background:#475569" target="_blank">NVD Record ↗</a>
                        <a href="https://www.cve.org/CVERecord?id=${details.id}" class="btn-action" style="background:#312e81" target="_blank">CVE.org ↗</a>
                    </div>
                </div>
                <div class="news-header-row" style="gap: 1rem; margin-top: -0.5rem; width: 100%;">
                    <span style="font-size: 0.85rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; white-space: nowrap;">Affected Products:</span>
                    <span style="font-size: 0.9rem; word-break: break-word; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 12px; padding: 0.5rem 0.5rem;">${details.products}</span>
                </div>

                <div class="news-header-row" style="gap: 1rem; margin-top: -0.5rem;">
                    <span style="font-size: 0.85rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Proof of Concepts:</span>
                    ${pocHtml}
                </div>

                <div class="articles-section">
                    <div class="articles-label">Mentions in News</div>
                    <ul class="article-list">
                        ${articlesHtml}
                    </ul>
                </div>
            </div>
        `;
        dashboard.insertAdjacentHTML('beforeend', cardHtml);
    }
}

async function initNewsUI() {
    if (document.body.dataset.page !== 'news') return;
    try {
        const targetDay = await fetchNextAvailableDay();
        await renderDay(targetDay);
        
        const dashboardEl = document.getElementById('dashboard');
        document.getElementById('loading').style.display = 'none';
        dashboardEl.style.display = 'flex';
        dashboardEl.style.flexDirection = 'column';
        document.getElementById('loadMoreContainer').style.display = 'block';
    } catch(e) {
        document.getElementById('loading').innerHTML = `<span style="color:var(--high); font-weight:bold;">Error aggregating news: ${e.message}</span>`;
        console.error(e);
    }
}

async function loadMore() {
    const btn = document.getElementById('loadMoreBtn');
    btn.disabled = true;
    btn.innerText = "Loading...";

    try {
        const newDay = await fetchNextAvailableDay();
        
        if (!newDay.date || newDay.cves.length === 0) {
            btn.innerText = "No older news found";
            return;
        }

        await renderDay(newDay);
        
        btn.disabled = false;
        btn.innerText = "Load More ↓";
        await updateStatus("Ready.", "status-text"); 
        
    } catch(e) {
        btn.innerText = "Error Loading News";
        console.error(e);
    }
}

// Initialize News UI if page matches
document.addEventListener('DOMContentLoaded', () => {
    if (document.body.dataset.page === 'news') {
        initNewsUI();
    }
});
