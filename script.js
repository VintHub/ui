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
        const res = await fetch(`https://cve.vinthub.io/${year}/${cveId}`);
        if (!res.ok) return null;
        return await res.json();
    } catch (e) {
        console.error(`Failed to fetch CVE data for ${cveId}:`, e);
        return null;
    }
}

// Shared helper to sort any CVSS list consistently
function sortCvssList(cvssList) {
    const getVersion = (item) => {
        const vec = item.vectorString || String(item.version || "");
        const match = vec.match(/(?:CVSS:)?(\d+)(?:\.(\d+))?/i);
        if (match) {
            const major = parseInt(match[1], 10);
            const minor = match[2] ? parseInt(match[2], 10) : 0;
            return { num: major + (minor / 10), label: `${major}.${minor}` };
        }
        // Fallback for v2 or text-only versions
        if (/^AV:[NAL]\/AC:[LMH]\/Au:[NSM]\//i.test(vec) || (!vec.startsWith("CVSS:") && vec.includes("Au:"))) {
            return { num: 2.0, label: '2.0' };
        }
        return { num: 0, label: String(item.version || 'N/A') };
    };

    const getSourcePriority = (item) => {
        const src = (item.source || "").trim().toUpperCase();
        if (src === "NVD") return 1;
        if (src === "CVELIST (CNA)") return 2;
        return 3;
    };

    return [...cvssList]
        .map((item, index) => ({
            item,
            index,
            ver: getVersion(item),
            sourcePrio: getSourcePriority(item)
        }))
        .sort((a, b) => {
            if (b.ver.num !== a.ver.num) return b.ver.num - a.ver.num;
            if (a.sourcePrio !== b.sourcePrio) return a.sourcePrio - b.sourcePrio;
            return a.index - b.index;
        });
}

function getBestCvss(cvssList) {
    if (!cvssList || !Array.isArray(cvssList) || cvssList.length === 0) return {};
    return sortCvssList(cvssList)[0].item;
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
        { name: 'Search', href: 'search.html', key: 'search' },
        { name: 'News', href: 'news.html', key: 'news' },
        { name: 'API', href: 'api.html', key: 'api' },
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
                        <span class="brand-title">VINTHUB</span>
                        <span class="brand-subtitle">Vulnerability Intelligence Hub</span>
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
    tbody.innerHTML = `<tr><td colspan="13" style="text-align:center; padding: 4rem; color: #94a3b8;">Scanning database...</td></tr>`;

    let processedCount = 0;
    for (const cveId of uniqueCves) {
        processedCount++;
        if (status) status.innerText = `Working... ${processedCount} out of ${uniqueCves.length} done [${Math.round((processedCount / uniqueCves.length) * 100)}%]`;
        
        const data = await fetchUnifiedCveData(cveId);
        const isRejected = data && (data.state === "REJECTED" || data.status === "REJECTED" || data.cveMetadata?.state === "REJECTED" || data.cveMetadata?.status === "REJECTED");

        if (!data || isRejected) {
            globalData.push({ 
                cveId, isInvalid: !data, isRejected: !!isRejected, published: "—", products: "—", cwe: "—", capec: "—",
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

        const epssVal = typeof data.epss?.score === 'number' && !isNaN(data.epss.score) ? data.epss.score : 0;
        const epss = (typeof data.epss?.score === 'number' && !isNaN(data.epss.score)) ? (data.epss.score * 100).toFixed(3) + "%" : "N/A";

        const kevInfo = data.cisa_kev || {};
        const isKev = kevInfo.in_cisa_kev || false;
        const kev = isKev ? (kevInfo.added_date || "Yes") : "-";
        const knownRansomware = kevInfo.ransomware_campaign_use || false;

        const pocs = cleanPocLinks(data.pocs || []);
        const cwe = (data.cwe || []).map(c => c.id || c).join(', ') || "N/A";
        const capec = (data.capec || []).map(c => c.id || c).join(', ') || "N/A";

        let ssvcVec = "N/A";
        const ssvcFactors = data.ssvc?.factors;
        const rawExploitation = ssvcFactors?.Exploitation ?? ssvcFactors?.exploitation;
        const rawAutomatable = ssvcFactors?.Automatable ?? ssvcFactors?.automatable;
        const rawTechImpact = ssvcFactors?.["Technical Impact"] ?? ssvcFactors?.technical_impact;

        if (rawExploitation && rawAutomatable && rawTechImpact) {
            const eVal = ssvcMap.Exploitation.values[String(rawExploitation).toLowerCase()] || "N";
            const aVal = ssvcMap.Automatable.values[String(rawAutomatable).toLowerCase()] || "N";
            const tVal = String(rawTechImpact).toLowerCase() === "total" ? "T" : "P";
            ssvcVec = `SSVCv2/E:${eVal}/A:${aVal}/T:${tVal}`;
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
            return { ext: "N/A", int: "N/A" };
        }

        const parts = ssvcVec.split('/');
        const aPart = parts.find(p => p.startsWith('A:'));
        const tPart = parts.find(p => p.startsWith('T:'));

        if (!aPart || !tPart) {
            return { ext: "N/A", int: "N/A" };
        }

        const isA = aPart.split(':')[1] === 'Y';
        const isT = tPart.split(':')[1] === 'T';
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

        return { ext: getSla(true, isK, isA, isT), int: getSla(false, isK, isA, isT) };
    };

    displayData.sort((a, b) => {
        let valA = a[currentSort.col], valB = b[currentSort.col];
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
        if (item.isInvalid || item.isRejected) {
            const label = item.isRejected ? "REJECTED" : "INVALID ID";
            const color = item.isRejected ? "#f59e0b" : "#ef4444";
            const bg = item.isRejected ? "rgba(245, 158, 11, 0.05)" : "rgba(239, 68, 68, 0.05)";
            if (item.isInvalid) {
                return `<tr>
                    <td class="no-break"><b style="color:${color}">${item.cveId}</b></td>
                    <td colspan="12" style="text-align:center; color:${item.isRejected ? '#f59e0b' : '#94a3b8'}; letter-spacing: 0.1em; font-weight: bold; padding: 1rem; background: ${bg};">${label}</td>
                </tr>`;
            }
            else if (item.isRejected) {
                return `<tr>
                    <td class="no-break">
                        <a href="./details.html#${item.cveId}" style="text-decoration: none;">
                            <b style="color:${color}" onmouseover="this.style.color='#f1f5f9';" onmouseout="this.style.color='${color}';">${item.cveId}</b>
                        </a>
                    </td>
                    <td colspan="12" style="text-align:center; color:${item.isRejected ? '#f59e0b' : '#94a3b8'}; letter-spacing: 0.1em; font-weight: bold; padding: 1rem; background: ${bg};">${label}</td>
                </tr>`;

            }
        }
        
        const isKev = item.kev !== '-';
        const bod = getBOD2604SLA(item.ssvc, isKev);
        
        return `
        <tr>
            <td class="no-break">
                <a href="./details.html#${item.cveId}" style="text-decoration: none;">
                    <b style="color:var(--brand-accent)" onmouseover="this.style.color='#f1f5f9';" onmouseout="this.style.color='#3b82f6';">${item.cveId}</b>
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
    const headers = ["VULN ID", "CVE/NVD Published", "Product", "Severity", "Score", "CVSS Vector", "SSVC Vector", "BOD 26-04 Ext SLA", "BOD 26-04 Int SLA", "EPSS", "KEV", "Ransomware", "PoCs", "CWE", "CAPEC"];
    
    const rows = globalData.map(r => {
        return `"${r.cveId}","${r.published}","${r.products}","${r.sev}",${r.score},"${r.vector}","${r.ssvc}","N/A","N/A","${r.epss}","${r.kev}","${r.knownRansomware ? 'Known' : 'Unknown'}","${r.pocs.join('; ')}","${r.cwe}","${r.capec}"`;
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

    // Normalize by stripping any leading 'v' or 'V' (e.g., "V1.2.1.S0" -> "1.2.1.S0")
    v1 = String(v1).replace(/^v/i, '');
    v2 = String(v2).replace(/^v/i, '');

    if (!isNaN(v1) && !isNaN(v2)) {
        const n1 = Number(v1), n2 = Number(v2);
        if (n1 !== n2) return n1 > n2 ? 1 : -1;
        return 0;
    }
    
    // Tokenize segments to handle things like "3p1" -> [3, "p", 1]
    const tokenize = (str) => {
        return String(str).split(/([^\d]+)/).filter(Boolean).map(part => {
            return /^\d+$/.test(part) ? parseInt(part, 10) : part;
        });
    };

    const p1 = tokenize(v1);
    const p2 = tokenize(v2);
    
    for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
        const s1 = p1[i];
        const s2 = p2[i];
        
        // If v1 runs out of parts, check if remaining parts in v2 are > 0
        if (s1 === undefined) {
            for (let j = i; j < p2.length; j++) {
                if (typeof p2[j] === 'number' && p2[j] > 0) return -1;
            }
            return 0; 
        }
        
        // If v2 runs out of parts, check if remaining parts in v1 are > 0
        if (s2 === undefined) {
            for (let j = i; j < p1.length; j++) {
                if (typeof p1[j] === 'number' && p1[j] > 0) return 1;
            }
            return 0;
        }

        const isNum1 = typeof s1 === 'number';
        const isNum2 = typeof s2 === 'number';

        if (isNum1 && isNum2) {
            if (s1 !== s2) return s1 > s2 ? 1 : -1;
        } else if (isNum1 || isNum2) {
            // A number takes precedence over a suffix tag (e.g., 3 vs 3p1 -> 3 comes first, 3p1 is greater)
            if (isNum1) {
                // s1 is number, s2 is string (e.g. "3" vs "3p") -> base number is equal, but string suffix makes it a patch/sub-version
                // Actually, if comparing "3" and "3p1", tokenized: p1=[3], p2=[3, "p", 1]. 
                // At i=1, s1 is undefined. Handled by out-of-bounds check above.
            }
            return isNum1 ? -1 : 1; 
        } else {
            const cmp = String(s1).localeCompare(String(s2));
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
                        let start = v.version;
                        let inRange = false;

                        let lessThan = v.lessThan;

                        // Quick helper to parse strings like "< 6.8.172"
                        if (typeof start === 'string' && start.trim().startsWith('<')) {
                            lessThan = start.replace('<', '').trim();
                            start = undefined; // No lower bound constraint
                        }

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

function getSsvcDecisionBadgeClass(decisionLabel) {
    const normalized = String(decisionLabel || "").trim();
    const classMap = {
        "Track": "ssvc-T",
        "Track*": "ssvc-R",
        "Attend": "ssvc-A",
        "Act": "ssvc-C"
    };
    return classMap[normalized] || "sev-UNKNOWN";
}

function renderSsvcArrows() {
    const diagram = document.getElementById("ssvcDiagram");
    const svg = document.getElementById("ssvcSvgLayer");
    const source = document.getElementById("ssvcSource");
    if (!diagram || !svg || !source) return;

    const branches = Array.from(diagram.querySelectorAll(".ssvc-branch"));
    svg.querySelectorAll(".ssvc-arrow-path").forEach((el) => el.remove());

    const box = diagram.getBoundingClientRect();
    const sBox = source.getBoundingClientRect();
    if (!box.width || !sBox.width || branches.length === 0) return;

    const padding = 8;
    const curveTension = 0.5;
    const originSpread = 4;

    const startX = sBox.right - box.left + padding;
    const centerY = sBox.top - box.top + sBox.height / 2;

    branches.forEach((branch, i) => {
        const bBox = branch.getBoundingClientRect();
        const endX = bBox.left - box.left - padding;
        const endY = bBox.top - box.top + bBox.height / 2;

        const offset = (i - (branches.length - 1) / 2) * originSpread;
        const startY = centerY + offset;

        const dx = Math.max(12, endX - startX);
        const cp1x = startX + dx * curveTension;
        const cp2x = endX - dx * curveTension;

        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("class", "ssvc-arrow-path");
        path.setAttribute(
            "d",
            `M ${startX} ${startY} C ${cp1x} ${startY}, ${cp2x} ${endY}, ${endX} ${endY}`
        );
        path.setAttribute("marker-end", "url(#ssvc-open-arrow)");
        svg.appendChild(path);
    });
}

window.addEventListener('resize', () => {
    if (document.body.dataset.page === 'details') {
        requestAnimationFrame(renderSsvcArrows);
    }
});

async function startDetailsAnalysis() {
    const hash = decodeURIComponent(window.location.hash.substring(1)).toUpperCase().replace(/[–—−‑‒―]/g, '-');
    const input = hash.match(/CVE-\d{4}-\d+/) ? hash : null;
    if (!input) return;

    document.getElementById('loading').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('kevRansomware').style.display = 'none';

    let rejectedAlert = document.getElementById('rejectedAlert');
    if (rejectedAlert) rejectedAlert.style.display = 'none';

    const data = await fetchUnifiedCveData(input);
    if (!data) {
        document.getElementById('loading').innerHTML = `<span style="color:red">Error: CVE Data not found</span>`;
        return;
    }

    const isRejected = data.state === "REJECTED" || data.status === "REJECTED" || data.cveMetadata?.state === "REJECTED" || data.cveMetadata?.status === "REJECTED";
    const dashboardEl = document.getElementById('dashboard');

    if (isRejected) {
        if (!rejectedAlert) {
            rejectedAlert = document.createElement('div');
            rejectedAlert.id = 'rejectedAlert';
            rejectedAlert.style.cssText = 'display: flex; align-items: center; justify-content: space-between; background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; color: #f8fafc; gap: 1rem; flex-wrap: wrap; grid-column: 1 / -1;';
        }
        if (!dashboardEl.contains(rejectedAlert)) {
            dashboardEl.insertBefore(rejectedAlert, dashboardEl.firstChild);
        }
        rejectedAlert.style.display = 'flex';
        rejectedAlert.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">🚫</span>
                <div>
                    <div style="font-weight: bold; font-size: 1.1rem; color: #f59e0b;">CVE IS REJECTED</div>
                </div>
            </div>
        `;
    }

    document.getElementById('displayDesc').innerText = data.description || (isRejected ? "This record has been rejected." : "Description not available.");
    document.getElementById('displayProducts').innerText = data.products || "N/A";

    let titleContainer = document.getElementById('displayTitleContainer');
    const rawTitle = data.title;
    const hasValidTitle = rawTitle && typeof rawTitle === 'string' && rawTitle.trim() !== '' && rawTitle.trim().toUpperCase() !== 'N/A' && rawTitle.trim().toUpperCase() !== 'NONE';

    if (hasValidTitle) {
        if (!titleContainer) {
            titleContainer = document.createElement('div');
            titleContainer.id = 'displayTitleContainer';
            titleContainer.style.marginBottom = '1.25rem';
            titleContainer.innerHTML = `
                <div class="label">Title</div>
                <div id="displayTitle" style="font-size: 1rem; color: var(--text-main); line-height: 1.5; word-break: break-word;">${rawTitle}</div>
            `;
            const descEl = document.getElementById('displayDesc');
            const targetNode = descEl.previousElementSibling || descEl;
            targetNode.parentNode.insertBefore(titleContainer, targetNode);
        } else {
            document.getElementById('displayTitle').innerText = rawTitle;
            titleContainer.style.display = 'block';
        }
    } else {
        if (titleContainer) {
            titleContainer.style.display = 'none';
        }
    }

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
                resDiv.style.color = "var(--brand-high)";
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

    const cvssList = Array.isArray(data.cvss) ? data.cvss : [];
    const cvssObj = getBestCvss(cvssList);
    const score = cvssObj.baseScore || 0;
    const sev = (cvssObj.baseSeverity || getCvssSeverity(score)).toUpperCase();
    const vector = cvssObj.vectorString || "N/A";

    document.getElementById('displayScore').innerText = score > 0 ? score.toFixed(1) : '—';
    document.getElementById('displaySevBadge').innerText = sev;
    document.getElementById('displaySevBadge').className = `badge-large sev-${sev.replace('/', '')}`;
    document.getElementById('displayVector').innerText = vector;

    // Handle button next to "CVSS Score"
    const scoreEl = document.getElementById('displayScore');
    const scoreCard = scoreEl.closest('.card') || scoreEl.parentElement.parentElement;
    const scoreLabelEl = scoreCard ? scoreCard.querySelector('.label') : null;
    if (scoreLabelEl) {
        scoreLabelEl.style.display = 'inline-flex';
        scoreLabelEl.style.alignItems = 'center';
        scoreLabelEl.style.gap = '0.45rem';

        let extraCvssBtn = document.getElementById('extraCvssBtn');
        if (!extraCvssBtn) {
            extraCvssBtn = document.createElement('button');
            extraCvssBtn.id = 'extraCvssBtn';
            extraCvssBtn.type = 'button';
            extraCvssBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
            extraCvssBtn.style.cssText = 'display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; padding:0; border-radius:9999px; background:#475569; color:#f8fafc; border:none; cursor:pointer; flex-shrink:0; transition:background 0.15s ease;';
            extraCvssBtn.onmouseover = () => { extraCvssBtn.style.background = 'var(--brand-accent, #3b82f6)'; };
            extraCvssBtn.onmouseout = () => { extraCvssBtn.style.background = '#475569'; };
            scoreLabelEl.appendChild(extraCvssBtn);
        }
        extraCvssBtn.title = `View all CVSS scores (${cvssList.length})`;
        extraCvssBtn.onclick = () => showCvssModal(cvssList);
    }

    // Use vector parser to populate metrics breakdown
    const metricsHtml = parseCvssMetrics(vector);
    document.getElementById('displayMetrics').innerHTML = metricsHtml.length > 0 ? metricsHtml.join('') : '<div class="metric-item">N/A</div>';

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
    const safeId = input.replace(/[^a-zA-Z0-9]/g, '_');
    let pocHtml = `-`;
    if (finalPocs.length > 0) {
        const pocLimit = 10;
        if (finalPocs.length <= pocLimit) {
            pocHtml = `<div class="poc-grid">${finalPocs.map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${i+1}</a>`).join('')}</div>`;
        } else {
            const firstPocs = finalPocs.slice(0, pocLimit).map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${i+1}</a>`).join('');
            const restPocs = finalPocs.slice(pocLimit).map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${pocLimit + i + 1}</a>`).join('');
            pocHtml = `
                <div class="poc-grid">
                    ${firstPocs}
                    <span id="more-pocs-${safeId}" style="display: none;">
                        ${restPocs}
                    </span>
                    <a id="btn-pocs-${safeId}" href="javascript:void(0)" onclick="document.getElementById('more-pocs-${safeId}').style.display='contents'; this.style.display='none'; document.getElementById('btn-less-pocs-${safeId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: bold; align-self: center; margin-left: 4px;">+${finalPocs.length - pocLimit} more...</a>
                    <a id="btn-less-pocs-${safeId}" href="javascript:void(0)" onclick="document.getElementById('more-pocs-${safeId}').style.display='none'; this.style.display='none'; document.getElementById('btn-pocs-${safeId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: bold; align-self: center; display: none; margin-left: 4px;">(show less)</a>
                </div>
            `;
        }
    }
    document.getElementById('pocContainer').innerHTML = pocHtml;

    const refs = data.references || [];
    document.getElementById('refList').innerHTML = refs.length > 0 ? refs.map(url => `<li><a href="${url}" target="_blank">${url}</a></li>`).join('') : "-";

    const epssVal = data.epss?.score;
    document.getElementById('displayEpss').innerText = (typeof epssVal === 'number' && !isNaN(epssVal)) ? (epssVal * 100).toFixed(3) + "%" : "N/A";

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
    const rawExploitation = ssvcFactors?.Exploitation ?? ssvcFactors?.exploitation;
    const rawAutomatable = ssvcFactors?.Automatable ?? ssvcFactors?.automatable;
    const rawTechImpact = ssvcFactors?.["Technical Impact"] ?? ssvcFactors?.technical_impact;

    if (rawExploitation && rawAutomatable && rawTechImpact) {
        let exploitation = String(rawExploitation);
        let automatable = String(rawAutomatable);
        let techImpact = String(rawTechImpact);

        if (isKev && exploitation.toLowerCase() !== "active") exploitation = "Active";

        const expVal = ssvcDisplayMap.Exploitation[exploitation] || ssvcDisplayMap.Exploitation[exploitation.toLowerCase()] || capitalize(exploitation);
        const autVal = ssvcDisplayMap.Automatable[automatable] || ssvcDisplayMap.Automatable[automatable.toLowerCase()] || capitalize(automatable);
        const tecVal = ssvcDisplayMap["Technical Impact"][techImpact] || ssvcDisplayMap["Technical Impact"][techImpact.toLowerCase()] || capitalize(techImpact);

        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Exploitation</div><div class="metric-val">${expVal}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">${autVal}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">${tecVal}</div></div>`);

        const eChar = ssvcMap.Exploitation.values[exploitation.toLowerCase()] || "N";
        const aChar = ssvcMap.Automatable.values[automatable.toLowerCase()] || "N";
        const tChar = techImpact.toLowerCase() === "total" ? "T" : "P";
        ssvcVec = `SSVCv2/E:${eChar}/A:${aChar}/T:${tChar}`;
    } else if (ssvcFactors) {
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Exploitation</div><div class="metric-val">${rawExploitation ? (ssvcDisplayMap.Exploitation[rawExploitation] || ssvcDisplayMap.Exploitation[String(rawExploitation).toLowerCase()] || capitalize(String(rawExploitation))) : "N/A"}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">${rawAutomatable ? (ssvcDisplayMap.Automatable[rawAutomatable] || ssvcDisplayMap.Automatable[String(rawAutomatable).toLowerCase()] || capitalize(String(rawAutomatable))) : "N/A"}</div></div>`);
        ssvcMeta.push(`<div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">${rawTechImpact ? (ssvcDisplayMap["Technical Impact"][rawTechImpact] || ssvcDisplayMap["Technical Impact"][String(rawTechImpact).toLowerCase()] || capitalize(String(rawTechImpact))) : "N/A"}</div></div>`);
    }

    const setSsvcBranches = (decisions) => {
    const mapping = [
        { id: "ssvcDecHigh", key: "Mission & Well-being - High" },
        { id: "ssvcDecMedium", key: "Mission & Well-being - Medium" },
        { id: "ssvcDecLow", key: "Mission & Well-being - Low" }
    ];

    mapping.forEach(({ id, key }) => {
            const el = document.getElementById(id);
            if (!el) return;
            const val = decisions && decisions[key] ? String(decisions[key]).trim() : "N/A";
            el.innerText = val;
            el.className = `badge ssvc-decision-badge ${getSsvcDecisionBadgeClass(val)}`;
        });
    };

    setSsvcBranches(isRejected ? null : data.ssvc?.decisions);

    const ssvcVecEl = document.getElementById('displaySsvcVector');
    if (ssvcVec !== "N/A") {
        const todayDate = new Date().toISOString().split('T')[0];
        const cisaUrl = `https://www.cisa.gov/ssvc-calculator#${ssvcVec}/${todayDate}T00:00:00Z/`;
        ssvcVecEl.innerHTML = `<a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" title="Open in CISA SSVC Calculator" style="color: inherit; text-decoration: none; transition: color 0.15s ease;" onmouseover="this.style.color='var(--brand-accent)'; this.style.textDecoration='underline';" onmouseout="this.style.color='inherit'; this.style.textDecoration='none';">${ssvcVec}</a>`;
    } else {
        ssvcVecEl.innerText = "N/A";
    }

    document.getElementById('ssvcExpansion').innerHTML = ssvcMeta.join('');

    if (isRejected) {
        document.getElementById('displaySsvcDec').innerText = "N/A";
        document.getElementById('displaySsvcDec').className = 'badge-large ssvc-N/A';
        document.getElementById('displaySsvcVector').innerText = "N/A";
        document.getElementById('ssvcExpansion').innerHTML = "";

        document.getElementById('bodSlaPublic').innerText = "N/A";
        document.getElementById('bodSlaInternal').innerText = "N/A";
        document.getElementById('bodExpansion').innerHTML = "";

        document.getElementById('ssvcExpansion').innerHTML = ssvcMeta.join('');
    }

    const bod = data.bod_sla;
    document.getElementById('bodSlaPublic').innerText = bod?.public || "N/A";
    document.getElementById('bodSlaInternal').innerText = bod?.internal || "N/A";
    document.getElementById('bodExpansion').innerHTML = bod?.factors ? `
        <div class="metric-item"><div class="metric-label">In KEV</div><div class="metric-val">${bod.factors.in_cisa_kev || (isKev ? "Yes" : "No")}</div></div>
        <div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">${bod.factors.automatable || "N/A"}</div></div>
        <div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">${bod.factors.technical_impact || "N/A"}</div></div>
    ` : `
        <div class="metric-item"><div class="metric-label">In KEV</div><div class="metric-val">N/A</div></div>
        <div class="metric-item"><div class="metric-label">Automatable</div><div class="metric-val">N/A</div></div>
        <div class="metric-item"><div class="metric-label">Technical Impact</div><div class="metric-val">N/A</div></div>
    `;

    document.getElementById('displayId').innerText = input;
    const pubDate = data.published_date?.nvd || data.published_date?.cveorg || "Unpublished";
    document.getElementById('displayPubDate').innerText = pubDate;

    let articles = data.news || [];
    const parts = input.split('-');
    const year = parts[1];
    document.getElementById('linkContainer').innerHTML = `<a href="https://cve.vinthub.io/${year}/${input}" class="btn-action" style="background:#0f766e" target="_blank">JSON API ↗</a><a href="https://nvd.nist.gov/vuln/detail/${input}" class="btn-action" style="background:#475569" target="_blank">NVD ↗</a><a href="https://www.cve.org/CVERecord?id=${input}" class="btn-action" style="background:#312e81" target="_blank">CVE.org ↗</a>${kevMarkup}`;

    if (year) {
        try {
            const newsRes = await fetch(`https://news.vinthub.io/cves/${year}/${input}`);
            if (newsRes.ok) {
                const additionalNews = await newsRes.json();
                if (Array.isArray(additionalNews)) {
                    let articleMap = new Map();
                    [...articles, ...additionalNews].forEach(art => {
                        if (art && art.link) {
                            articleMap.set(art.link, art);
                        }
                    });
                    articles = Array.from(articleMap.values());
                }
            }
        } catch (e) {
            console.error(`Failed to fetch additional news for ${input}:`, e);
        }
    }
    articles.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
    
    const newsContainer = document.getElementById('newsContainer');
    newsContainer.innerHTML = articles.length > 0 ? articles.map(art => `
        <li>
            <span class="article-date">${art.date}</span>
            <a href="${art.link}" target="_blank">${art.title}</a>
        </li>
    `).join('') : `<li><span style="color: #94a3b8">No news history available.</span></li>`;

    document.getElementById('loading').style.display = 'none';
    document.getElementById('dashboard').style.display = 'grid';
    requestAnimationFrame(renderSsvcArrows);
}

function showCvssModal(cvssList) {
    let modal = document.getElementById('cvssModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'cvssModal';
        modal.style.cssText = 'display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.7); backdrop-filter:blur(2px);';
        modal.innerHTML = `
            <div style="background:var(--brand-card, #1e293b); border:1px solid var(--border-color, #334155); border-radius:12px; margin:8% auto; padding:1.5rem; width:92%; max-width:960px; color:var(--text-main, #f8fafc); box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-color, #334155); padding-bottom:0.75rem; margin-bottom:1rem;">
                    <h3 style="margin:0; font-size:1.15rem;">All CVSS Scores</h3>
                    <button id="closeCvssModal" style="background:none; border:none; color:#94a3b8; font-size:1.5rem; line-height:1; cursor:pointer;">&times;</button>
                </div>
                <div style="overflow-x:auto;">
                    <table style="width:100%; table-layout:auto; border-collapse:collapse; text-align:left; font-size:0.875rem;">
                        <thead>
                            <tr style="border-bottom:1px solid var(--border-color, #334155); color:#94a3b8; text-transform:uppercase; font-size:0.75rem;">
                                <th style="padding:0.6rem 0.75rem; width:75px; white-space:nowrap;">Version</th>
                                <th style="padding:0.6rem 0.75rem; width:65px; white-space:nowrap; text-align:center;">Score</th>
                                <th style="padding:0.6rem 0.75rem; width:105px; white-space:nowrap;">Severity</th>
                                <th style="padding:0.6rem 0.75rem;">Vector</th>
                                <th style="padding:0.6rem 0.75rem; width:180px;">Source</th>
                            </tr>
                        </thead>
                        <tbody id="cvssModalBody"></tbody>
                    </table>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        document.getElementById('closeCvssModal').onclick = () => { modal.style.display = 'none'; };
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.style.display = 'none';
        });
    }

    const parseVersion = (item) => {
        const vec = (item.vectorString || "").trim();
        const verField = String(item.version || "").trim();

        // 1. Check explicit CVSS:X.Y prefix in vectorString
        const prefixMatch = vec.match(/^CVSS:(\d+)(?:\.(\d+))?/i);
        if (prefixMatch) {
            const major = parseInt(prefixMatch[1], 10);
            const minor = prefixMatch[2] ? parseInt(prefixMatch[2], 10) : 0;
            return {
                num: major + (minor / 10),
                label: `${major}.${minor}`
            };
        }

        // 2. Check explicit version property on the object (e.g., "2.0", "3.1")
        const fieldMatch = verField.match(/^(\d+)(?:\.(\d+))?$/);
        if (fieldMatch) {
            const major = parseInt(fieldMatch[1], 10);
            const minor = fieldMatch[2] ? parseInt(fieldMatch[2], 10) : 0;
            return {
                num: major + (minor / 10),
                label: `${major}.${minor}`
            };
        }

        // 3. Detect unprefixed CVSS v2 vector (starts with AV: and has Au: or v2 format)
        if (/^AV:[NAL]\/AC:[LMH]\/Au:[NSM]\//i.test(vec) || (!vec.startsWith("CVSS:") && vec.includes("Au:"))) {
            return { num: 2.0, label: '2.0' };
        }

        return { num: 0, label: 'N/A' };
    };

    const sortedList = sortCvssList(cvssList);

    const tbody = document.getElementById('cvssModalBody');
    tbody.innerHTML = sortedList.map(({ item, ver }) => {
        const s = item.baseScore !== undefined && item.baseScore !== null ? Number(item.baseScore) : 0;
        const sev = (item.baseSeverity || getCvssSeverity(s)).toUpperCase();
        const vec = item.vectorString || 'N/A';
        const src = item.source || 'N/A';
        return `
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
                <td style="padding:0.65rem 0.75rem; width:75px; white-space:nowrap; color:#94a3b8; font-weight:600;">${ver.label}</td>
                <td style="padding:0.65rem 0.75rem; width:65px; white-space:nowrap; text-align:center; font-weight:bold;">${s > 0 ? s.toFixed(1) : '—'}</td>
                <td style="padding:0.65rem 0.75rem; width:105px; white-space:nowrap;"><span class="badge sev-${sev.replace('/', '')}">${sev}</span></td>
                <td style="padding:0.65rem 0.75rem; font-family:monospace; font-size:0.8rem; word-break:normal; overflow-wrap:anywhere;">${vec}</td>
                <td style="padding:0.65rem 0.75rem; width:180px; color:#cbd5e1;">${src}</td>
            </tr>
        `;
    }).join('');

    modal.style.display = 'block';
}

// ==========================================
// NEWS PAGE LOGIC
// ==========================================

let currentDate = new Date();
const hashDate = window.location.hash.replace('#', '').trim();
if (/^\d{4}-\d{2}-\d{2}$/.test(hashDate)) {
    currentDate = new Date(`${hashDate}T00:00:00Z`);
} else {
    currentDate.setDate(currentDate.getDate() + 1);
}
let cveDetailsCache = new Map();

let cveArticleHistory = new Map();

async function updateStatus(text, id = 'status-text') {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
    
    const btn = document.getElementById('loadMoreBtn');
    if (btn && btn.disabled) btn.innerText = text;
}

async function fetchCveDetailsData(input, newsFromNewsHub = [], fileDate = null) {
    const buildArticles = (baseNews) => {
        const history = cveArticleHistory.get(input) || new Map();
        // Only this day's hub articles may fall back to the file date (it is their real date).
        const dayNews = (newsFromNewsHub || [])
            .filter(art => !art.listOnly)
            .map(art => ({ ...art, date: art.date || fileDate }));
        // Same link already known (e.g. listed in two day files): keep ONE consistent date, the later one.
        // An undated entry never overwrites a known date either.
        [...history.values(), ...(baseNews || []), ...dayNews].forEach(art => {
            if (!art || !art.link) return;
            const prev = history.get(art.link);
            if (!prev || !prev.date) { history.set(art.link, art); return; }
            if (!art.date) { history.set(art.link, { ...art, date: prev.date }); return; }
            const later = new Date(art.date) > new Date(prev.date) ? art.date : prev.date;
            history.set(art.link, { ...art, date: later });
        });
        cveArticleHistory.set(input, history);
        return Array.from(history.values())
            .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
    };

    if (cveDetailsCache.has(input)) {
        const cached = cveDetailsCache.get(input);
        const { baseNews, ...rest } = cached;
        return { ...rest, articles: buildArticles(baseNews) };
    }

    const data = await fetchUnifiedCveData(input);

    const formatNewsDate = (dStr) => {
        if (!dStr) return "UNDEFINED";
        const parts = dStr.split('-');
        if (parts.length !== 3) return dStr;
        const [y, m, d] = parts;
        const months = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
        const monthName = months[parseInt(m, 10) - 1] || m;
        return `${d} ${monthName} ${y}`;
    };

    const baseNews = data ? (data.news || []).filter(art => !art.listOnly) : [];
    const articles = buildArticles(baseNews);

    if (!data) {
        return {
            id: input,
            score: "Score N/A",
            severity: "UNKNOWN",
            vector: "Vector N/A",
            pocs: [],
           articles: articles,
            isKev: false,
            kevDate: "-",
            knownRansomware: false,
            products: "N/A",
            vendors: "N/A"
        };
    }

    const cvssList = Array.isArray(data.cvss) ? data.cvss : [];
    const cvssObj = getBestCvss(cvssList);
    const hasScore = cvssObj.baseScore !== undefined && cvssObj.baseScore !== null;

    const score = hasScore ? cvssObj.baseScore : 0;
    const severity = hasScore ? (cvssObj.baseSeverity || getCvssSeverity(score)).toUpperCase() : "UNKNOWN";
    const vector = cvssObj.vectorString || "Vector N/A";
    
    const finalPocs = cleanPocLinks(data.pocs || []);
    
    const kevInfo = data.cisa_kev || {};
    const isKev = kevInfo.in_cisa_kev || false;
    const kevDate = kevInfo.added_date || "-";
    const knownRansomware = kevInfo.ransomware_campaign_use || false;
    const products = data.products || "N/A";

    let vendorsArr = [];
    if (data.affected?.cna_affected) {
        data.affected.cna_affected.forEach(item => {
            if (item.vendor) vendorsArr.push(item.vendor);
        });
    }
    if (vendorsArr.length === 0 && data.affected?.nvd_cpes) {
        data.affected.nvd_cpes.forEach(node => {
            if (node.nodes) {
                node.nodes.forEach(n => {
                    if (n.cpeMatch) {
                        n.cpeMatch.forEach(m => {
                            const parts = (m.criteria || "").split(':');
                            if (parts.length >= 5 && parts[3] && parts[3] !== '*' && parts[3] !== '-') {
                                vendorsArr.push(parts[3].replace(/_/g, ' '));
                            }
                        });
                    }
                });
            }
        });
    }
    let uniqueVendors = [...new Set(vendorsArr.map(v => {
        const trimmed = v.trim();
        if (!trimmed || trimmed.toUpperCase() === "N/A") return "";
        return /[A-Z]/.test(trimmed) ? trimmed : capitalize(trimmed);
    }).filter(Boolean))];
    const vendors = uniqueVendors.length > 0 ? uniqueVendors.join(', ') : products;

    const result = {
        id: input,
        score: hasScore ? score.toFixed(1) : "Score N/A",
        severity: severity,
        vector: vector,
        pocs: finalPocs,
        articles: articles,
        isKev: isKev,
        kevDate: kevDate,
        knownRansomware: knownRansomware,
        products: products,
        vendors: vendors
    };
    cveDetailsCache.set(input, { ...result, baseNews });
    return result;
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
        
        let url = `https://news.vinthub.io/${y}/${m}/${dateStr}?${Math.random().toString(36).substring(2, 10)}`;
        await updateStatus(`Checking news for ${dateStr}...`, 'status-text');

        try {
            let res = await fetch(url);
            if (res.ok) {
                let data = await res.json();
                for (let cve in data) {
                    const hasNewsArticle = Array.isArray(data[cve]) && data[cve].some(item => !item.listOnly);
                    if (hasNewsArticle) {
                        dayCves.push({ id: cve, date: dateStr, news: data[cve] });
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

function applyDayFilters(safeDateId) {
    const container = document.getElementById(`day-cards-${safeDateId}`);
    if (!container) return;

    const activeSev = container.dataset.filterSev || 'ALL';
    const activeVendor = container.dataset.filterVendor || 'ALL';

    container.querySelectorAll('.news-card').forEach(card => {
        const cardSev = card.dataset.severity || 'UNKNOWN';
        const cardVendors = JSON.parse(card.dataset.vendors || '[]');
        const matchesSev = activeSev === 'ALL' || cardSev === activeSev;
        const matchesVendor = activeVendor === 'ALL' || cardVendors.includes(activeVendor);
        card.style.display = (matchesSev && matchesVendor) ? '' : 'none';
    });
}

function setDayFilter(safeDateId, type, value, btnEl) {
    const container = document.getElementById(`day-cards-${safeDateId}`);
    if (!container) return;

    if (type === 'sev') container.dataset.filterSev = value;
    if (type === 'vendor') container.dataset.filterVendor = value;

    const rowId = type === 'sev' ? `sev-filters-${safeDateId}` : `vendor-filters-${safeDateId}`;
    const rowEl = document.getElementById(rowId);
    if (rowEl) {
        rowEl.querySelectorAll('.filter-pill').forEach(btn => {
            const isSelected = btn === btnEl;
            btn.dataset.active = isSelected ? 'true' : 'false';
            btn.style.background = isSelected ? 'var(--brand-accent, #3b82f6)' : 'rgba(148, 163, 184, 0.14)';
            btn.style.color = isSelected ? '#ffffff' : 'var(--text-main)';
            btn.style.borderColor = isSelected ? 'var(--brand-accent, #3b82f6)' : 'var(--border-color)';
        });
    }

    applyDayFilters(safeDateId);
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
        vendors: new Set()
    };

    for (let i = 0; i < cves.length; i++) {
        const cveId = cves[i].id;
        let percent = Math.round(((i + 1) / cves.length) * 100);
        await updateStatus(`Processing info for ${cveId}... (${percent}%)`);
        
        try {
            const details = await fetchCveDetailsData(cveId, cves[i].news, cves[i].date);

            processedDetails.push(details);

            let sev = details.severity || 'UNKNOWN';
            if (sev === 'NONE') sev = 'INFO';
            if (sev.includes('N/A')) sev = 'UNKNOWN';
            if (stats.severities[sev] === undefined) sev = 'UNKNOWN';
            
            stats.severities[sev].total++;
            if (details.isKev) stats.severities[sev].kev++;
            if (details.pocs && details.pocs.length > 0) stats.severities[sev].poc++;
            
            if (details.vendors && details.vendors !== "N/A") {
                  details.vendors.split(',').forEach(v => {
                      if (v.trim()) stats.vendors.add(v.trim());
                  });
            }
        } catch (e) {
            console.warn(`Failed to process ${cveId}`, e);
        }
    }

    if (processedDetails.length === 0) return;

    let vendorsArr = Array.from(stats.vendors).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    let vendorsHtml = "None identified";

    if (vendorsArr.length > 0) {
        let vendorsLimit = 10;
        if (vendorsArr.length <= vendorsLimit) {
            vendorsHtml = `<span style="color: var(--text-main);">${vendorsArr.join(', ')}</span>`;
        } else {
            const firstN = vendorsArr.slice(0, vendorsLimit).join(', ');
            const rest = ', ' + vendorsArr.slice(vendorsLimit).join(', ');
            const safeDateId = date.replace(/-/g, '');

            vendorsHtml = `
                <span style="color: var(--text-main);">${firstN}</span><span id="more-prod-${safeDateId}" style="display: none; color: var(--text-main);">${rest}
                <a href="javascript:void(0)" onclick="document.getElementById('more-prod-${safeDateId}').style.display='none'; document.getElementById('btn-more-${safeDateId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-weight: bold; margin-left: 4px;">(show less)</a></span>
                <a id="btn-more-${safeDateId}" href="javascript:void(0)" onclick="document.getElementById('more-prod-${safeDateId}').style.display='inline'; this.style.display='none';" style="color: var(--accent); text-decoration: none; font-weight: bold; margin-left: 4px;"><br>+${vendorsArr.length - vendorsLimit} more...</a>
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

    const safeDateId = date.replace(/-/g, '');
    const sevOrder = [
        { key: 'CRITICAL', label: 'Critical' },
        { key: 'HIGH', label: 'High' },
        { key: 'MEDIUM', label: 'Medium' },
        { key: 'LOW', label: 'Low' },
        { key: 'INFO', label: 'Info' },
        { key: 'UNKNOWN', label: 'Unknown' }
    ];

    const presentSeverities = sevOrder.filter(s => stats.severities[s.key].total > 0);
    const pillBaseStyle = 'padding: 0.25rem 0.7rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; cursor: pointer; border: 1px solid var(--border-color); transition: all 0.15s ease;';
    const activePillStyle = `${pillBaseStyle} background: var(--brand-accent, #3b82f6); color: #ffffff; border-color: var(--brand-accent, #3b82f6);`;
    const inactivePillStyle = `${pillBaseStyle} background: rgba(148, 163, 184, 0.14); color: var(--text-main);`;

    const sevPillsHtml = [
        `<button type="button" class="filter-pill" data-active="true" style="${activePillStyle}" onclick="setDayFilter('${safeDateId}', 'sev', 'ALL', this)">All</button>`,
        ...presentSeverities.map(s =>
            `<button type="button" class="filter-pill" data-active="false" style="${inactivePillStyle}" onclick="setDayFilter('${safeDateId}', 'sev', '${s.key}', this)">${s.label}</button>`
        )
    ].join('');

    const vendorPillsHtml = [
        `<button type="button" class="filter-pill" data-active="true" style="${activePillStyle}" onclick="setDayFilter('${safeDateId}', 'vendor', 'ALL', this)">All</button>`,
        ...vendorsArr.map(v => {
            const encoded = encodeURIComponent(v);
            return `<button type="button" class="filter-pill" data-active="false" style="${inactivePillStyle}" onclick="setDayFilter('${safeDateId}', 'vendor', decodeURIComponent('${encoded}'), this)">${v}</button>`;
        })
    ].join('');

    const summaryHtml = `
        <div id="day-summary-${safeDateId}" class="day-summary-box" style="width: 100%; min-width: 0; flex-shrink: 0; background: rgba(59, 130, 246, 0.1); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; margin-bottom: 0.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);"><h2 style="margin-bottom: 10px;">
                🗓️ Talked about on ${date}
            </h2>
            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem;">
                ${renderTotal()}
                ${renderBadge('CRITICAL', 'CRITICAL')}
                ${renderBadge('HIGH', 'HIGH')}
                ${renderBadge('MEDIUM', 'MEDIUM')}
                ${renderBadge('LOW', 'LOW')}
                ${renderBadge('INFO', 'INFO')}
                ${renderBadge('UNKNOWN', 'UNKNOWN')}
            </div>
            <div id="sev-filters-${safeDateId}" style="display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; margin-bottom: 0.6rem; font-size: 0.875rem;">
                <strong style="color: var(--text-muted); margin-right: 0.25rem;">Filter by severity:</strong>
                ${sevPillsHtml}
            </div>
            <div id="vendor-filters-${safeDateId}" style="display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; margin-bottom: 1rem; font-size: 0.875rem;">
                <strong style="color: var(--text-muted); margin-right: 0.25rem;">Filter by vendor:</strong>
                ${vendorPillsHtml}
            </div>
            <div style="font-size: 0.95rem; color: var(--text-muted); line-height: 1.5;">
          </div>
        </div>
        <div id="day-cards-${safeDateId}" data-filter-sev="ALL" data-filter-vendor="ALL" style="width: 100%; align-self: stretch; display: flex; flex-direction: column; gap: 1rem;"></div>
    `;
    dashboard.insertAdjacentHTML('beforeend', summaryHtml);
    const dayCardsContainer = document.getElementById(`day-cards-${safeDateId}`);

    const sevRank = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'NONE': 1, 'UNKNOWN': 0 };
    processedDetails.sort((a, b) => {
        const scoreA = parseFloat(a.score) || 0;
        const scoreB = parseFloat(b.score) || 0;
        if (scoreB !== scoreA) return scoreB - scoreA;
        return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    });

    for (const details of processedDetails) {
        const safeId = `${safeDateId}_${details.id.replace(/[^a-zA-Z0-9]/g, '_')}`;

        let cardSev = details.severity || 'UNKNOWN';
        if (cardSev.includes('N/A') || cardSev === 'NONE') cardSev = 'UNKNOWN';
        if (!stats.severities[cardSev]) cardSev = 'UNKNOWN';

        const cardVendors = (details.vendors && details.vendors !== "N/A")
            ? details.vendors.split(',').map(v => v.trim()).filter(Boolean)
            : [];

        const formatNewsDate = (dStr) => dStr || "UNDEFINED";

        let pocHtml = `<span style="color: var(--text-muted); font-size: 0.85rem;">No public PoCs</span>`;
        if (details.pocs.length > 0) {
            const pocLimit = 10;
            if (details.pocs.length <= pocLimit) {
                pocHtml = `<div class="poc-grid">${details.pocs.map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${i+1}</a>`).join('')}</div>`;
            } else {
                const firstPocs = details.pocs.slice(0, pocLimit).map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${i+1}</a>`).join('');
                const restPocs = details.pocs.slice(pocLimit).map((url, i) => `<a href="${url}" class="poc-link" target="_blank" title="${url}">💀 #${pocLimit + i + 1}</a>`).join('');
                pocHtml = `
                    <div class="poc-grid">
                        ${firstPocs}
                        <span id="more-pocs-${safeId}" style="display: none;">
                            ${restPocs}
                        </span>
                        <a id="btn-pocs-${safeId}" href="javascript:void(0)" onclick="document.getElementById('more-pocs-${safeId}').style.display='contents'; this.style.display='none'; document.getElementById('btn-less-pocs-${safeId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: bold; align-self: center; margin-left: 4px;">+${details.pocs.length - pocLimit} more...</a>
                        <a id="btn-less-pocs-${safeId}" href="javascript:void(0)" onclick="document.getElementById('more-pocs-${safeId}').style.display='none'; this.style.display='none'; document.getElementById('btn-pocs-${safeId}').style.display='inline';" style="color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: bold; align-self: center; display: none; margin-left: 4px;">(show less)</a>
                    </div>
                `;
            }
        }

        let articlesHtml = `<li><span style="color: var(--text-muted)">No news history available.</span></li>`;
        if (details.articles.length > 0) {
            const articleLimit = 5;
            const firstArticles = details.articles.slice(0, articleLimit).map(art => `
                <li>
                    <span class="article-date">${formatNewsDate(art.date)}</span>
                    <a href="${art.link}" target="_blank">${art.title}</a>
                </li>
            `).join('');

            if (details.articles.length <= articleLimit) {
                articlesHtml = firstArticles;
            } else {
                const restArticles = details.articles.slice(articleLimit).map(art => `
                    <li style="margin-bottom: 10px;">
                        <span class="article-date">${formatNewsDate(art.date)}</span>
                        <a href="${art.link}" target="_blank">${art.title}</a>
                    </li>
                `).join('');

                articlesHtml = `
                    ${firstArticles}
                    <div id="more-articles-${safeId}" style="display: none;">
                        ${restArticles}
                    </div>
                    <li id="li-btn-articles-${safeId}" style="list-style: none; ">
                        <a href="javascript:void(0)" onclick="document.getElementById('more-articles-${safeId}').style.display='block'; this.parentElement.style.display='none'; document.getElementById('li-btn-less-articles-${safeId}').style.display='block';" style="color: var(--accent); text-decoration: none; font-weight: bold; font-size: 0.9rem;">+${details.articles.length - articleLimit} more articles...</a>
                    </li>
                    <li id="li-btn-less-articles-${safeId}" style="list-style: none; margin-top: 0.5rem; display: none;">
                        <a href="javascript:void(0)" onclick="document.getElementById('more-articles-${safeId}').style.display='none'; this.parentElement.style.display='none'; document.getElementById('li-btn-articles-${safeId}').style.display='block';" style="color: var(--accent); text-decoration: none; font-weight: bold; font-size: 0.9rem;">(show less)</a>
                    </li>
                `;
            }
        }
        
        const kevHtml = details.isKev ? `<span class="badge-large kev-badge" title="Added to CISA KEV on ${details.kevDate}">⚠️ KEV</span>` : '';
        const ransomwareHtml = details.knownRansomware ? `<span class="badge-large ransomware-badge" title="Known Ransomware Campaign Use">☣️ Ransomware</span>` : '';

        const cardHtml = `
            <div class="news-card" data-severity="${cardSev}" data-vendors='${JSON.stringify(cardVendors).replace(/'/g, "&#39;")}'>
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
        dayCardsContainer.insertAdjacentHTML('beforeend', cardHtml);
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
