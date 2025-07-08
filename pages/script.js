// Enhanced JavaScript for Malwize - All API Functionality
let currentResults = [];
let apiBaseUrl = 'http://localhost:8000';
let currentTheme = localStorage.getItem('theme') || 'light';

// Theme Management
function toggleTheme() {
    const body = document.body;
    const themeToggle = document.querySelector('.theme-toggle');
    
    if (currentTheme === 'light') {
        body.setAttribute('data-theme', 'dark');
        currentTheme = 'dark';
        themeToggle.textContent = 'Light Mode';
        localStorage.setItem('theme', 'dark');
    } else {
        body.removeAttribute('data-theme');
        currentTheme = 'light';
        themeToggle.textContent = 'Dark Mode';
        localStorage.setItem('theme', 'light');
    }
    
    // Add smooth transition effect
    body.style.transition = 'all 0.3s ease';
    setTimeout(() => {
        body.style.transition = '';
    }, 300);
}

// Load saved theme
function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    const themeToggle = document.querySelector('.theme-toggle');
    
    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        currentTheme = 'dark';
        themeToggle.textContent = 'Light Mode';
    } else {
        themeToggle.textContent = 'Dark Mode';
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    
    // Initialize page-specific functionality
    const currentPage = window.location.pathname.split('/').pop();
    
    if (currentPage === 'upload.html') {
        initializeUploadPage();
    } else if (currentPage === 'hash_input.html') {
        initializeHashInputPage();
    } else if (currentPage === 'spreadsheet.html') {
        initializeSpreadsheetPage();
    } else if (currentPage === 'results.html') {
        initializeResultsPage();
    } else if (currentPage === 'log.html') {
        initializeLogPage();
    } else if (currentPage === 'dashboard.html') {
        initializeDashboardPage();
    }
    
    // Add global error handler
    window.addEventListener('error', function(event) {
        console.error('Global error:', event.error);
        log('error', `Global error: ${event.error?.message || event.message}`);
    });
    
    // Add unhandled promise rejection handler
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        log('error', `Unhandled promise rejection: ${event.reason?.message || event.reason}`);
    });
    
    log('info', 'Malwize Frontend Loaded');
    log('info', `Current page: ${currentPage}`);
    log('info', `API Base URL: ${apiBaseUrl}`);
});

// Page-specific initializations
function initializeUploadPage() {
    setupDragAndDrop();
    log('info', 'Upload page initialized');
}

function initializeHashInputPage() {
    log('info', 'Hash input page initialized');
}

function initializeSpreadsheetPage() {
    log('info', 'Spreadsheet page initialized');
}

function initializeResultsPage() {
    // Load any existing results from localStorage
    const savedResults = localStorage.getItem('scanResults');
    if (savedResults) {
        currentResults = JSON.parse(savedResults);
        displayResults(currentResults);
    }
    log('info', 'Results page initialized');
}

function initializeLogPage() {
    log('info', 'Log page initialized');
}

function initializeDashboardPage() {
    initializeApiStatus();
    log('info', 'Dashboard page initialized');
}

// API Status Management
function initializeApiStatus() {
    const statusContainer = document.getElementById('apiStatus');
    if (!statusContainer) return;
    
    const apis = [
        { name: 'VirusTotal', status: 'unknown' },
        { name: 'NVD CVE', status: 'unknown' },
        { name: 'AbuseIPDB', status: 'unknown' },
        { name: 'IP Geolocation', status: 'unknown' },
        { name: 'ThreatFox', status: 'unknown' }
    ];

    apis.forEach((api, index) => {
        const card = document.createElement('div');
        card.className = 'status-card';
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.innerHTML = `
            <div class="status-icon">${api.name.charAt(0)}</div>
            <div>${api.name}</div>
            <div style="font-size: 12px; color: var(--text-muted);">Checking...</div>
        `;
        statusContainer.appendChild(card);
        
        // Staggered animation
        setTimeout(() => {
            card.style.transition = 'all 0.3s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
}

function updateApiStatus(apiName, status, message) {
    const cards = document.querySelectorAll('.status-card');
    const apiIndex = {
        'VirusTotal': 0, 'NVD CVE': 1, 'AbuseIPDB': 2, 
        'IP Geolocation': 3, 'ThreatFox': 4
    }[apiName];

    if (cards[apiIndex]) {
        const card = cards[apiIndex];
        const icon = card.querySelector('.status-icon');
        const messageDiv = card.querySelector('div:last-child');

        card.className = `status-card ${status}`;
        icon.className = `status-icon ${status}`;
        messageDiv.textContent = message;
        
        // Add pulse animation for status change
        card.style.animation = 'pulse 0.6s ease';
        setTimeout(() => {
            card.style.animation = '';
        }, 600);
    }
}

// API Connection Test
async function testApiConnection() {
    const baseUrl = document.getElementById('apiBaseUrl')?.value || apiBaseUrl;
    apiBaseUrl = baseUrl;
    
    log('info', `Testing connection to ${baseUrl}...`);
    
    try {
        log('info', `Sending request to ${baseUrl}/docs`);
        const response = await fetch(`${baseUrl}/docs`);
        log('info', `Response status: ${response.status}`);
        
        if (response.ok) {
            log('success', 'API connection successful!');
            updateApiStatus('VirusTotal', 'active', 'Connected');
            updateApiStatus('NVD CVE', 'active', 'Connected');
            updateApiStatus('AbuseIPDB', 'active', 'Connected');
            updateApiStatus('IP Geolocation', 'active', 'Connected');
            updateApiStatus('ThreatFox', 'active', 'Connected');
        } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    } catch (error) {
        handleError(error, 'API connection test');
        updateApiStatus('VirusTotal', 'inactive', 'Connection Failed');
        updateApiStatus('NVD CVE', 'inactive', 'Connection Failed');
        updateApiStatus('AbuseIPDB', 'inactive', 'Connection Failed');
        updateApiStatus('IP Geolocation', 'inactive', 'Connection Failed');
        updateApiStatus('ThreatFox', 'inactive', 'Connection Failed');
    }
}

// File Upload Functions
function setupDragAndDrop() {
    const uploadArea = document.getElementById('uploadArea');
    if (!uploadArea) return;
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        console.log('=== DRAG AND DROP ===');
        console.log('Drop event:', e);
        console.log('Data transfer files:', e.dataTransfer.files);
        
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const files = e.dataTransfer.files;
        console.log('Number of dropped files:', files.length);
        
        if (files.length > 0) {
            console.log('Dropped file:', files[0]);
            console.log('File name:', files[0].name);
            console.log('File size:', files[0].size);
            console.log('File type:', files[0].type);
            handleFileUpload(files[0]);
        } else {
            console.log('No files dropped');
        }
    });
    
    uploadArea.addEventListener('click', () => {
        document.getElementById('fileInput').click();
    });
}

// Handle file input change event
function handleFileInputChange(event) {
    console.log('=== FILE INPUT CHANGE ===');
    console.log('Event:', event);
    console.log('Target files:', event.target.files);
    
    const files = event.target.files;
    console.log('Number of files:', files.length);
    
    if (files && files.length > 0) {
        console.log('First file:', files[0]);
        console.log('File name:', files[0].name);
        console.log('File size:', files[0].size);
        console.log('File type:', files[0].type);
        
        // Show upload button and status
        const uploadBtn = document.getElementById('uploadBtn');
        const uploadStatus = document.getElementById('uploadStatus');
        if (uploadBtn) {
            uploadBtn.style.display = 'inline-block';
            uploadBtn.textContent = `Upload ${files.length} File${files.length > 1 ? 's' : ''}`;
        }
        if (uploadStatus) {
            uploadStatus.style.display = 'block';
            uploadStatus.innerHTML = `<span style="color: var(--success-color);">✓ ${files.length} file${files.length > 1 ? 's' : ''} selected</span>`;
        }
        
        // Store files for later upload
        window.selectedFiles = files;
    } else {
        console.log('No files selected');
        // Hide upload button
        const uploadBtn = document.getElementById('uploadBtn');
        const uploadStatus = document.getElementById('uploadStatus');
        if (uploadBtn) uploadBtn.style.display = 'none';
        if (uploadStatus) uploadStatus.style.display = 'none';
    }
}

function triggerFileUpload() {
    const files = window.selectedFiles;
    if (files && files.length > 0) {
        handleFileUpload(files[0]);
    } else {
        showNotification('No files selected for upload', 'warning');
    }
}

async function handleFileUpload(file) {
    console.log('=== FILE UPLOAD STARTED ===');
    console.log('File object:', file);
    console.log('File name:', file?.name);
    console.log('File size:', file?.size);
    console.log('File type:', file?.type);
    
    if (!file) {
        const errorMsg = 'No file provided to upload';
        console.error('ERROR:', errorMsg);
        log('error', errorMsg);
        return;
    }
    
    if (!file.name) {
        const errorMsg = 'Invalid file object - missing file name';
        console.error('ERROR:', errorMsg);
        log('error', errorMsg);
        return;
    }
    
    console.log(`Starting upload for file: ${file.name}`);
    log('info', `Uploading ${file.name}...`);
    
    const formData = new FormData();
    formData.append('file', file);
    console.log('FormData created with file:', file.name);
    
    let endpoint = '';
    if (file.name.endsWith('.zip')) {
        endpoint = '/upload/folder_zip/';
        console.log('Detected ZIP file, using folder_zip endpoint');
    } else if (file.name.endsWith('.txt')) {
        endpoint = '/upload/hashes_txt/';
        console.log('Detected TXT file, using hashes_txt endpoint');
    } else if (file.name.endsWith('.csv')) {
        endpoint = '/upload/hashes_csv/';
        formData.append('hash_column', 'hash');
        console.log('Detected CSV file, using hashes_csv endpoint with hash column');
    } else {
        // For individual files, create a ZIP
        console.log('Individual file detected, creating ZIP archive...');
        const zip = new JSZip();
        zip.file(file.name, file);
        const zipBlob = await zip.generateAsync({type: 'blob'});
        const zipFile = new File([zipBlob], 'files.zip', {type: 'application/zip'});
        formData.set('file', zipFile);
        endpoint = '/upload/folder_zip/';
        console.log('ZIP created for individual file, using folder_zip endpoint');
    }
    
    try {
        console.log('=== SENDING REQUEST ===');
        console.log('API Base URL:', apiBaseUrl);
        console.log('Endpoint:', endpoint);
        console.log('Full URL:', `${apiBaseUrl}${endpoint}`);
        console.log('FormData contents:', formData);
        
        showProgress();
        log('info', `Sending request to ${apiBaseUrl}${endpoint}`);
        
        const response = await fetch(`${apiBaseUrl}${endpoint}`, {
            method: 'POST',
            body: formData
        });
        
        console.log('=== RESPONSE RECEIVED ===');
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        console.log('Response ok:', response.ok);
        
        log('info', `Response status: ${response.status}`);
        
        if (response.ok) {
            console.log('Response is OK, parsing JSON...');
            const result = await response.json();
            console.log('Parsed result:', result);
            console.log('Number of results:', result.results?.length || 0);
            
            log('success', `Upload successful! Found ${result.results.length} results`);
            showNotification(`Upload successful! Found ${result.results.length} results`, 'success');
            
            // Update upload status
            const uploadStatus = document.getElementById('uploadStatus');
            if (uploadStatus) {
                uploadStatus.innerHTML = `<span style="color: var(--success-color);">✓ Upload successful</span>`;
            }
            
            currentResults = result.results;
            localStorage.setItem('scanResults', JSON.stringify(currentResults));
            displayResults(currentResults);
            window.location.href = 'results.html';
        } else {
            console.error('Response not OK, getting error text...');
            const error = await response.text();
            console.error('Error response:', error);
            throw new Error(`HTTP ${response.status}: ${error}`);
        }
    } catch (error) {
        console.error('=== UPLOAD ERROR ===');
        console.error('Error details:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        
        const errorMsg = `Upload failed: ${error.message}`;
        showNotification(errorMsg, 'error');
        handleError(error, 'File upload');
        
        // Update upload status
        const uploadStatus = document.getElementById('uploadStatus');
        if (uploadStatus) {
            uploadStatus.innerHTML = `<span style="color: var(--error-color);">✗ Upload failed</span>`;
        }
    } finally {
        console.log('=== UPLOAD COMPLETED ===');
        hideProgress();
    }
}

// Hash Input Functions
async function scanHashes() {
    const hashInput = document.getElementById('hashInput').value;
    const hashes = hashInput.split('\n').filter(h => h.trim());
    
    if (hashes.length === 0) {
        showNotification('Please enter at least one hash', 'warning');
        log('warning', 'No hashes provided');
        return;
    }
    
    // Validate hash format
    const invalidHashes = [];
    const validHashes = [];
    
    for (const hash of hashes) {
        const trimmedHash = hash.trim();
        // Check if it's a valid SHA256 hash (64 characters, hex)
        if (trimmedHash.length === 64 && /^[a-fA-F0-9]+$/.test(trimmedHash)) {
            validHashes.push(trimmedHash);
        } else if (trimmedHash.length > 0) {
            invalidHashes.push(trimmedHash);
        }
    }
    
    if (invalidHashes.length > 0) {
        const errorMsg = `Invalid hash format detected: ${invalidHashes.slice(0, 3).join(', ')}${invalidHashes.length > 3 ? '...' : ''}. Please use valid SHA256 hashes (64 characters, hex).`;
        showNotification(errorMsg, 'error');
        log('error', errorMsg);
        return;
    }
    
    if (validHashes.length === 0) {
        showNotification('No valid hashes found. Please enter valid SHA256 hashes.', 'warning');
        log('warning', 'No valid hashes found');
        return;
    }
    
    log('info', `Scanning ${validHashes.length} hashes...`);
    showNotification(`Starting scan of ${validHashes.length} hashes...`, 'info');
    
    const blob = new Blob([validHashes.join('\n')], { type: 'text/plain' });
    const file = new File([blob], 'hashes.txt', { type: 'text/plain' });
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        showProgress();
        log('info', `Sending request to ${apiBaseUrl}/upload/hashes_txt/`);
        
        const response = await fetch(`${apiBaseUrl}/upload/hashes_txt/`, {
            method: 'POST',
            body: formData
        });
        
        log('info', `Response status: ${response.status}`);
        
        if (response.ok) {
            const result = await response.json();
            log('success', `Scan successful! Found ${result.results.length} results`);
            showNotification(`Scan completed! Found ${result.results.length} results`, 'success');
            currentResults = result.results;
            localStorage.setItem('scanResults', JSON.stringify(currentResults));
            window.location.href = 'results.html';
        } else {
            const error = await response.text();
            throw new Error(`HTTP ${response.status}: ${error}`);
        }
    } catch (error) {
        const errorMsg = `Scan failed: ${error.message}`;
        showNotification(errorMsg, 'error');
        handleError(error, 'Hash scanning');
    } finally {
        hideProgress();
    }
}

// Spreadsheet Functions
async function scanFromSpreadsheet() {
    const url = document.getElementById('spreadsheetUrl').value;
    const column = document.getElementById('spreadsheetColumn').value;
    
    if (!url) {
        log('warning', 'Please provide a spreadsheet URL');
        return;
    }
    
    log('info', `Scanning from spreadsheet: ${url}`);
    
    const formData = new FormData();
    formData.append('spreadsheet_url', url);
    formData.append('column', column);
    
    try {
        showProgress();
        log('info', `Sending request to ${apiBaseUrl}/scan/from_spreadsheet/`);
        
        const response = await fetch(`${apiBaseUrl}/scan/from_spreadsheet/`, {
            method: 'POST',
            body: formData
        });
        
        log('info', `Response status: ${response.status}`);
        
        if (response.ok) {
            const result = await response.json();
            log('success', `Spreadsheet scan successful! Found ${result.results.length} results`);
            currentResults = result.results;
            localStorage.setItem('scanResults', JSON.stringify(currentResults));
            window.location.href = 'results.html';
        } else {
            const error = await response.text();
            throw new Error(`HTTP ${response.status}: ${error}`);
        }
    } catch (error) {
        handleError(error, 'Spreadsheet scanning');
    } finally {
        hideProgress();
    }
}

// Enhanced Results Display with Table Functionality
let filteredResults = [];
let currentPage = 1;
const itemsPerPage = 20;

function createResultsSummary(results) {
    if (!results || results.length === 0) {
        return `
            <div class="summary-section">
                <h3>No Results Available</h3>
                <p>Upload files or scan hashes to see results here.</p>
            </div>
        `;
    }

    const totalResults = results.length;
    const successfulScans = results.filter(r => !r.error).length;
    const errorScans = results.filter(r => r.error).length;
    const highRiskCount = results.filter(r => (r.total_detections || 0) > 50).length;
    const mediumRiskCount = results.filter(r => (r.total_detections || 0) > 10 && (r.total_detections || 0) <= 50).length;
    const lowRiskCount = results.filter(r => (r.total_detections || 0) <= 10).length;

    return `
        <div class="summary-section">
            <h3>Scan Summary</h3>
            <div class="summary-stats">
                <div class="stat-item">
                    <span class="stat-number">${totalResults}</span>
                    <span class="stat-label">Total Scans</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number success">${successfulScans}</span>
                    <span class="stat-label">Successful</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number error">${errorScans}</span>
                    <span class="stat-label">Errors</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number high-risk">${highRiskCount}</span>
                    <span class="stat-label">High Risk</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number medium-risk">${mediumRiskCount}</span>
                    <span class="stat-label">Medium Risk</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number low-risk">${lowRiskCount}</span>
                    <span class="stat-label">Low Risk</span>
                </div>
            </div>
        </div>
    `;
}

function displayResults(results) {
    currentResults = results;
    filteredResults = [...results];
    currentPage = 1;
    
    const tableContainer = document.getElementById('resultsTableContainer');
    const summaryContainer = document.getElementById('resultsSummary');
    const analyticsDashboard = document.getElementById('analyticsDashboard');
    
    if (!tableContainer) return;
    
    if (results.length === 0) {
        tableContainer.innerHTML = `
            <div class="no-results">
                <h3>No Results Available</h3>
                <p>Start by uploading files or entering hashes to see results here.</p>
                <button class="btn" onclick="window.location.href='upload.html'">Upload Files</button>
                <button class="btn btn-secondary" onclick="window.location.href='hash_input.html'">Enter Hashes</button>
            </div>
        `;
        if (summaryContainer) summaryContainer.innerHTML = '';
        if (analyticsDashboard) analyticsDashboard.style.display = 'none';
        updateResultsStats();
        return;
    }
    
    // Show analytics dashboard with fade in
    if (analyticsDashboard) {
        analyticsDashboard.style.display = 'block';
        analyticsDashboard.style.opacity = '0';
        analyticsDashboard.style.transform = 'translateY(20px)';
        setTimeout(() => {
            analyticsDashboard.style.transition = 'all 0.5s ease';
            analyticsDashboard.style.opacity = '1';
            analyticsDashboard.style.transform = 'translateY(0)';
        }, 100);
        
        // Generate analytics
        generateAnalytics(results);
    }
    
    // Create summary and table
    const summary = createResultsSummary(results);
    if (summaryContainer) summaryContainer.innerHTML = summary;
    
    // Update stats and render table
    updateResultsStats();
    renderResultsTable();
    
    log('success', `Results displayed with ${results.length} items`);
}

function renderResultsTable() {
    const tableContainer = document.getElementById('resultsTableContainer');
    if (!tableContainer) return;
    
    if (filteredResults.length === 0) {
        tableContainer.innerHTML = `
            <div class="no-results">
                <h3>No Results Match Your Filters</h3>
                <p>Try adjusting your search criteria or filters.</p>
            </div>
        `;
        document.getElementById('pagination').style.display = 'none';
        return;
    }
    
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const pageResults = filteredResults.slice(startIndex, endIndex);
    
    let tableHTML = `
        <table class="results-table">
            <thead>
                <tr>
                    <th>Indicator</th>
                    <th>MD5</th>
                    <th>SHA-1</th>
                    <th>SHA-256</th>
                    <th>Threat</th>
                    <th>TA Origin Country</th>
                    <th>AS/Domain</th>
                    <th>IP/Domain/URL Country</th>
                    <th>VirusTotal</th>
                    <th>AbuseIPDB</th>
                </tr>
            </thead>
            <tbody>
    `;

    pageResults.forEach(result => {
        const hash = result.hash || result.sha256 || 'N/A';
        const shortHash = hash.length > 16 ? hash.substring(0, 16) + '...' : hash;
        
        // Extract different hash types
        const md5 = result.md5 || 'N/A';
        const sha1 = result.sha1 || 'N/A';
        const sha256 = result.sha256 || hash || 'N/A';
        
        // Handle threat information
        let threat = 'Unknown';
        if (result.popular_threat_category) {
            if (typeof result.popular_threat_category === 'string') {
                threat = result.popular_threat_category;
            } else if (Array.isArray(result.popular_threat_category)) {
                threat = result.popular_threat_category.join(', ');
            } else if (typeof result.popular_threat_category === 'object') {
                threat = Object.values(result.popular_threat_category).join(', ');
            } else {
                threat = String(result.popular_threat_category);
            }
        }
        
        // Extract country and AS information
        const taOriginCountry = result.country || result.origin_country || 'Unknown';
        const asDomain = result.as || result.domain || result.autonomous_system || 'Unknown';
        const ipDomainUrlCountry = result.ip_country || result.domain_country || result.url_country || 'Unknown';
        
        // VirusTotal and AbuseIPDB detection values
        let virustotalDetections = 'N/A';
        let abuseipdbDetections = 'N/A';
        
        if (result.source_api === 'virustotal') {
            if (result.error) {
                virustotalDetections = 'Error';
            } else if (result.detection_ratio) {
                virustotalDetections = result.detection_ratio;
            } else if (result.total_detections !== undefined) {
                virustotalDetections = `${result.total_detections}/76`;
            } else {
                virustotalDetections = 'N/A';
            }
        }
        
        if (result.source_api === 'abuseipdb') {
            if (result.error) {
                abuseipdbDetections = 'Error';
            } else if (result.abuseConfidenceScore !== undefined) {
                abuseipdbDetections = `${result.abuseConfidenceScore}%`;
            } else if (result.totalReports !== undefined) {
                abuseipdbDetections = `${result.totalReports} reports`;
            } else {
                abuseipdbDetections = 'N/A';
            }
        }

        tableHTML += `
            <tr>
                <td class="hash-cell">
                    <span title="${hash}">${shortHash}</span>
                    <div class="hash-full">${hash}</div>
                </td>
                <td>${md5}</td>
                <td>${sha1}</td>
                <td>${sha256}</td>
                <td>${threat}</td>
                <td>${taOriginCountry}</td>
                <td>${asDomain}</td>
                <td>${ipDomainUrlCountry}</td>
                <td>${virustotalDetections}</td>
                <td>${abuseipdbDetections}</td>
            </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    tableContainer.innerHTML = tableHTML;
    renderPagination();
}

function renderPagination() {
    const pagination = document.getElementById('pagination');
    if (!pagination) return;
    
    const totalPages = Math.ceil(filteredResults.length / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage + 1;
    const endIndex = Math.min(currentPage * itemsPerPage, filteredResults.length);
    
    if (totalPages <= 1) {
        pagination.style.display = 'none';
        return;
    }
    
    pagination.style.display = 'flex';
    
    // Update pagination info
    document.getElementById('startIndex').textContent = startIndex;
    document.getElementById('endIndex').textContent = endIndex;
    document.getElementById('totalItems').textContent = filteredResults.length;
    
    // Update pagination buttons
    document.getElementById('prevBtn').disabled = currentPage === 1;
    document.getElementById('nextBtn').disabled = currentPage === totalPages;
    
    // Generate page numbers
    const pageNumbers = document.getElementById('pageNumbers');
    let pageNumbersHTML = '';
    
    const maxVisiblePages = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage + 1 < maxVisiblePages) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    for (let i = startPage; i <= endPage; i++) {
        pageNumbersHTML += `
            <button class="pagination-btn ${i === currentPage ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>
        `;
    }
    
    pageNumbers.innerHTML = pageNumbersHTML;
}

function changePage(delta) {
    const totalPages = Math.ceil(filteredResults.length / itemsPerPage);
    const newPage = currentPage + delta;
    
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        renderResultsTable();
    }
}

function goToPage(page) {
    const totalPages = Math.ceil(filteredResults.length / itemsPerPage);
    if (page >= 1 && page <= totalPages) {
        currentPage = page;
        renderResultsTable();
    }
}

function filterResults() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sourceFilter = document.getElementById('sourceFilter').value;
    const riskFilter = document.getElementById('riskFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    
    filteredResults = currentResults.filter(result => {
        // Search filter
        const searchMatch = !searchTerm || 
            (result.hash && result.hash.toLowerCase().includes(searchTerm)) ||
            (result.file_type && result.file_type.toLowerCase().includes(searchTerm)) ||
            (result.popular_threat_category && (() => {
                let categoryStr = '';
                if (typeof result.popular_threat_category === 'string') {
                    categoryStr = result.popular_threat_category;
                } else if (Array.isArray(result.popular_threat_category)) {
                    categoryStr = result.popular_threat_category.join(', ');
                } else if (typeof result.popular_threat_category === 'object') {
                    categoryStr = Object.values(result.popular_threat_category).join(', ');
                } else {
                    categoryStr = String(result.popular_threat_category);
                }
                return categoryStr.toLowerCase().includes(searchTerm);
            })()) ||
            (result.popular_threat_names && result.popular_threat_names.toLowerCase().includes(searchTerm));
        
        // Source filter
        const sourceMatch = !sourceFilter || result.source_api === sourceFilter;
        
        // Risk filter
        let riskMatch = true;
        if (riskFilter) {
            const detections = result.total_detections || 0;
            if (riskFilter === 'high') riskMatch = detections > 50;
            else if (riskFilter === 'medium') riskMatch = detections > 10 && detections <= 50;
            else if (riskFilter === 'low') riskMatch = detections <= 10;
        }
        
        // Status filter
        const statusMatch = !statusFilter || 
            (statusFilter === 'success' && !result.error) ||
            (statusFilter === 'error' && result.error);
        
        return searchMatch && sourceMatch && riskMatch && statusMatch;
    });
    
    currentPage = 1;
    updateResultsStats();
    renderResultsTable();
}

function updateResultsStats() {
    const totalResults = currentResults.length;
    const filteredCount = filteredResults.length;
    const highRiskCount = filteredResults.filter(r => (r.total_detections || 0) > 50).length;
    const errorCount = filteredResults.filter(r => r.error).length;
    
    document.getElementById('totalResults').textContent = totalResults;
    document.getElementById('filteredResults').textContent = filteredCount;
    document.getElementById('highRiskCount').textContent = highRiskCount;
    document.getElementById('errorCount').textContent = errorCount;
}

function viewDetails(hash) {
    const result = currentResults.find(r => (r.hash || r.sha256) === hash);
    if (!result) {
        showNotification('Result not found', 'error');
        return;
    }
    
    // Create a detailed view modal or navigate to a details page
    const details = `
Hash: ${result.hash || result.sha256 || 'N/A'}
Source: ${result.source_api || 'Unknown'}
Status: ${result.error ? 'Error' : 'Success'}
Detections: ${result.total_detections || 0}/76
File Type: ${result.file_type || 'Unknown'}
Threat Category: ${(() => {
                if (!result.popular_threat_category) return 'Unknown';
                if (typeof result.popular_threat_category === 'string') {
                    return result.popular_threat_category;
                } else if (Array.isArray(result.popular_threat_category)) {
                    return result.popular_threat_category.join(', ');
                } else if (typeof result.popular_threat_category === 'object') {
                    return Object.values(result.popular_threat_category).join(', ');
                } else {
                    return String(result.popular_threat_category);
                }
            })()}
Threat Names: ${result.popular_threat_names || 'None'}
Network Activity: ${result.hosts || result.domains || result.urls || 'None'}
Behaviors: ${result.behavior_count || 0}
Capabilities: ${result.capabilities_count || 0}
    `;
    
    alert(details); // Replace with a proper modal in production
    log('info', `Viewed details for hash: ${hash}`);
}

// Analytics Functions
function generateAnalytics(results) {
    const vtResults = results.filter(r => r.source_api === 'virustotal' && !r.error);
    
    if (vtResults.length === 0) {
        const dashboard = document.getElementById('analyticsDashboard');
        if (dashboard) dashboard.style.display = 'none';
        return;
    }
    
    generateDetectionStats(vtResults);
    generateThreatCategories(vtResults);
    generateFileTypes(vtResults);
    generateNetworkAnalysis(vtResults);
    generateBehaviorAnalysis(vtResults);
    generateRiskAssessment(vtResults);
}

function generateDetectionStats(results) {
    const container = document.getElementById('detectionStats');
    if (!container) return;
    
    const stats = {
        total: results.length,
        malicious: results.filter(r => r.total_detections > 0).length,
        clean: results.filter(r => r.total_detections === 0).length,
        avgDetections: Math.round(results.reduce((sum, r) => sum + (r.total_detections || 0), 0) / results.length),
        maxDetections: Math.max(...results.map(r => r.total_detections || 0)),
        highRisk: results.filter(r => (r.total_detections || 0) > 50).length,
        mediumRisk: results.filter(r => (r.total_detections || 0) > 10 && (r.total_detections || 0) <= 50).length,
        lowRisk: results.filter(r => (r.total_detections || 0) <= 10).length
    };
    
    container.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Total Files</span>
            <span class="stat-value">${stats.total}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Malicious Files</span>
            <span class="stat-value high">${stats.malicious} (${Math.round(stats.malicious/stats.total*100)}%)</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Clean Files</span>
            <span class="stat-value low">${stats.clean} (${Math.round(stats.clean/stats.total*100)}%)</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Avg Detections</span>
            <span class="stat-value">${stats.avgDetections}/76</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Max Detections</span>
            <span class="stat-value high">${stats.maxDetections}/76</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">High Risk (>50)</span>
            <span class="stat-value high">${stats.highRisk}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Medium Risk (11-50)</span>
            <span class="stat-value medium">${stats.mediumRisk}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Low Risk (≤10)</span>
            <span class="stat-value low">${stats.lowRisk}</span>
        </div>
    `;
}

function generateThreatCategories(results) {
    const container = document.getElementById('threatCategories');
    if (!container) return;
    
    const categories = {};
    const threatNames = {};
    
    results.forEach(r => {
        if (r.popular_threat_category) {
            let categoryKey = 'Unknown';
            if (typeof r.popular_threat_category === 'string') {
                categoryKey = r.popular_threat_category;
            } else if (Array.isArray(r.popular_threat_category)) {
                categoryKey = r.popular_threat_category.join(', ');
            } else if (typeof r.popular_threat_category === 'object') {
                categoryKey = Object.values(r.popular_threat_category).join(', ');
            } else {
                categoryKey = String(r.popular_threat_category);
            }
            categories[categoryKey] = (categories[categoryKey] || 0) + 1;
        }
        if (r.popular_threat_names) {
            const names = r.popular_threat_names.split(';');
            names.forEach(name => {
                if (name.trim()) {
                    threatNames[name.trim()] = (threatNames[name.trim()] || 0) + 1;
                }
            });
        }
    });
    
    let html = '';
    
    if (Object.keys(categories).length > 0) {
        html += '<div class="stat-item"><span class="stat-label">Threat Categories</span></div>';
        Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([category, count]) => {
            const percentage = Math.round(count / results.length * 100);
            html += `
                <div class="stat-item">
                    <span class="stat-label">${category}</span>
                    <span class="stat-value">${count} (${percentage}%)</span>
                </div>
                <div class="progress-bar-small">
                    <div class="progress-fill-small" style="width: ${percentage}%"></div>
                </div>
            `;
        });
    }
    
    if (Object.keys(threatNames).length > 0) {
        html += '<div class="stat-item"><span class="stat-label">Top Threats</span></div>';
        Object.entries(threatNames).sort((a, b) => b[1] - a[1]).slice(0, 3).forEach(([name, count]) => {
            html += `
                <div class="stat-item">
                    <span class="stat-label">${name}</span>
                    <span class="stat-value">${count}</span>
                </div>
            `;
        });
    }
    
    container.innerHTML = html || '<div class="stat-item"><span class="stat-label">No threat data available</span></div>';
}

function generateFileTypes(results) {
    const container = document.getElementById('fileTypes');
    if (!container) return;
    
    const fileTypes = {};
    const fileSizes = [];
    
    results.forEach(r => {
        if (r.file_type) {
            fileTypes[r.file_type] = (fileTypes[r.file_type] || 0) + 1;
        }
        if (r.file_size) {
            fileSizes.push(r.file_size);
        }
    });
    
    let html = '';
    
    if (Object.keys(fileTypes).length > 0) {
        html += '<div class="stat-item"><span class="stat-label">File Types</span></div>';
        Object.entries(fileTypes).sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([type, count]) => {
            const percentage = Math.round(count / results.length * 100);
            html += `
                <div class="stat-item">
                    <span class="stat-label">${type}</span>
                    <span class="stat-value">${count} (${percentage}%)</span>
                </div>
                <div class="progress-bar-small">
                    <div class="progress-fill-small" style="width: ${percentage}%"></div>
                </div>
            `;
        });
    }
    
    if (fileSizes.length > 0) {
        const avgSize = Math.round(fileSizes.reduce((sum, size) => sum + size, 0) / fileSizes.length);
        const maxSize = Math.max(...fileSizes);
        const minSize = Math.min(...fileSizes);
        
        html += `
            <div class="stat-item">
                <span class="stat-label">Avg File Size</span>
                <span class="stat-value">${formatBytes(avgSize)}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Largest File</span>
                <span class="stat-value">${formatBytes(maxSize)}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Smallest File</span>
                <span class="stat-value">${formatBytes(minSize)}</span>
            </div>
        `;
    }
    
    container.innerHTML = html || '<div class="stat-item"><span class="stat-label">No file data available</span></div>';
}

function generateNetworkAnalysis(results) {
    const container = document.getElementById('networkAnalysis');
    if (!container) return;
    
    const hosts = new Set();
    const domains = new Set();
    const urls = new Set();
    const ips = new Set();
    
    results.forEach(r => {
        if (r.hosts) r.hosts.split(';').forEach(h => h.trim() && hosts.add(h.trim()));
        if (r.domains) r.domains.split(';').forEach(d => d.trim() && domains.add(d.trim()));
        if (r.urls) r.urls.split(';').forEach(u => u.trim() && urls.add(u.trim()));
        if (r.ips && Array.isArray(r.ips)) r.ips.forEach(ip => ips.add(ip));
    });
    
    const filesWithNetwork = results.filter(r => r.hosts || r.domains || r.urls || (r.ips && r.ips.length > 0)).length;
    
    container.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Unique Hosts</span>
            <span class="stat-value">${hosts.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Unique Domains</span>
            <span class="stat-value">${domains.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Unique URLs</span>
            <span class="stat-value">${urls.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Unique IPs</span>
            <span class="stat-value">${ips.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Files with Network Activity</span>
            <span class="stat-value">${filesWithNetwork}</span>
        </div>
    `;
}

function generateBehaviorAnalysis(results) {
    const container = document.getElementById('behaviorAnalysis');
    if (!container) return;
    
    const behaviors = new Set();
    const capabilities = new Set();
    const yaraRules = new Set();
    const sigmaRules = new Set();
    
    results.forEach(r => {
        if (r.behavior_tags) r.behavior_tags.split(';').forEach(b => b.trim() && behaviors.add(b.trim()));
        if (r.capabilities) r.capabilities.split(';').forEach(c => c.trim() && capabilities.add(c.trim()));
        if (r.yara_rules) r.yara_rules.split(';').forEach(y => y.trim() && yaraRules.add(y.trim()));
        if (r.sigma_rules) r.sigma_rules.split(';').forEach(s => s.trim() && sigmaRules.add(s.trim()));
    });
    
    const filesWithBehaviors = results.filter(r => r.behavior_count > 0).length;
    const filesWithCapabilities = results.filter(r => r.capabilities_count > 0).length;
    
    container.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Unique Behaviors</span>
            <span class="stat-value">${behaviors.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Unique Capabilities</span>
            <span class="stat-value">${capabilities.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">YARA Rules Matched</span>
            <span class="stat-value">${yaraRules.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Sigma Rules Matched</span>
            <span class="stat-value">${sigmaRules.size}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Files with Behaviors</span>
            <span class="stat-value">${filesWithBehaviors}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Files with Capabilities</span>
            <span class="stat-value">${filesWithCapabilities}</span>
        </div>
    `;
}

function generateRiskAssessment(results) {
    const container = document.getElementById('riskAssessment');
    if (!container) return;
    
    const highRisk = results.filter(r => (r.total_detections || 0) > 50).length;
    const mediumRisk = results.filter(r => (r.total_detections || 0) > 10 && (r.total_detections || 0) <= 50).length;
    const lowRisk = results.filter(r => (r.total_detections || 0) <= 10).length;
    
    let overallRisk = 'low';
    if (highRisk > results.length * 0.3) overallRisk = 'high';
    else if (highRisk > results.length * 0.1 || mediumRisk > results.length * 0.5) overallRisk = 'medium';
    
    container.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Overall Risk Level</span>
            <span class="risk-indicator risk-${overallRisk}">${overallRisk.toUpperCase()}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">High Risk Files</span>
            <span class="stat-value high">${highRisk} (${Math.round(highRisk/results.length*100)}%)</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Medium Risk Files</span>
            <span class="stat-value medium">${mediumRisk} (${Math.round(mediumRisk/results.length*100)}%)</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Low Risk Files</span>
            <span class="stat-value low">${lowRisk} (${Math.round(lowRisk/results.length*100)}%)</span>
        </div>
        <div class="stat-item recommendation">
            <span class="stat-label">Recommendation</span>
            <span class="stat-value recommendation">${getRiskRecommendation(overallRisk, highRisk, results.length)}</span>
        </div>
    `;
}

function getRiskRecommendation(risk, highRiskCount, totalCount) {
    if (risk === 'high') {
        return 'Quarantine Immediately';
    } else if (risk === 'medium') {
        return 'Monitor closely - review suspicious files';
    } else {
        return 'Low threat level - standard monitoring';
    }
}

// Download Functions
async function downloadResults(format) {
    if (currentResults.length === 0) {
        log('warning', 'No results to download');
        return;
    }
    
    log('info', `Downloading results as ${format.toUpperCase()}...`);
    
    try {
        const response = await fetch(`${apiBaseUrl}/download/${format}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_results.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            log('success', `Download completed: scan_results.${format}`);
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        log('error', `Download failed: ${error.message}`);
    }
}

function clearResults() {
    currentResults = [];
    filteredResults = [];
    localStorage.removeItem('scanResults');
    
    const tableContainer = document.getElementById('resultsTableContainer');
    const summaryContainer = document.getElementById('resultsSummary');
    const analyticsDashboard = document.getElementById('analyticsDashboard');
    
    if (tableContainer) {
        tableContainer.innerHTML = `
            <div class="no-results">
                <h3>No Results Available</h3>
                <p>Start by uploading files or entering hashes to see results here.</p>
                <button class="btn" onclick="window.location.href='upload.html'">Upload Files</button>
                <button class="btn btn-secondary" onclick="window.location.href='hash_input.html'">Enter Hashes</button>
            </div>
        `;
    }
    
    if (summaryContainer) summaryContainer.innerHTML = '';
    if (analyticsDashboard) analyticsDashboard.style.display = 'none';
    
    updateResultsStats();
    document.getElementById('pagination').style.display = 'none';
    
    log('info', 'Results cleared');
    showNotification('Results cleared', 'info');
}

// Progress Bar Functions
function showProgress() {
    const progressBar = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    
    if (progressBar && progressFill) {
        progressBar.style.display = 'block';
        progressFill.style.width = '0%';
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) progress = 90;
            progressFill.style.width = progress + '%';
        }, 200);
        
        window.progressInterval = interval;
    }
}

function hideProgress() {
    const progressFill = document.getElementById('progressFill');
    const progressBar = document.getElementById('uploadProgress');
    
    if (progressFill) progressFill.style.width = '100%';
    
    setTimeout(() => {
        if (progressBar) progressBar.style.display = 'none';
        if (window.progressInterval) {
            clearInterval(window.progressInterval);
        }
    }, 500);
}

// Logging Functions
function log(level, message) {
    const logSection = document.getElementById('logSection');
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${level}`;
    logEntry.textContent = `[${timestamp}] ${message}`;
    
    if (logSection) {
        logEntry.style.opacity = '0';
        logEntry.style.transform = 'translateX(-20px)';
        logSection.appendChild(logEntry);
        
        // Smooth animation for new log entries
        setTimeout(() => {
            logEntry.style.transition = 'all 0.3s ease';
            logEntry.style.opacity = '1';
            logEntry.style.transform = 'translateX(0)';
        }, 50);
        
        logSection.scrollTop = logSection.scrollHeight;
    }
    
    console.log(`[${level.toUpperCase()}] ${message}`);
}

function clearLog() {
    const logSection = document.getElementById('logSection');
    if (logSection) {
        logSection.style.opacity = '0';
        setTimeout(() => {
            logSection.innerHTML = '';
            logSection.style.opacity = '1';
            log('info', 'Log cleared');
        }, 200);
    }
}

// Error Handling
function handleError(error, context) {
    const errorMessage = error.message || error.toString();
    log('error', `${context}: ${errorMessage}`);
    console.error(`Error in ${context}:`, error);
    
    if (errorMessage.includes('Failed to fetch')) {
        log('error', 'Network error: Please check your API connection');
    } else if (errorMessage.includes('Not found')) {
        log('warning', 'Some hashes were not found in the database (this is normal)');
    } else {
        log('error', `Unexpected error: ${errorMessage}`);
    }
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add CSS animation for pulse effect
const style = document.createElement('style');
style.textContent = `
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
`;
document.head.appendChild(style);

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--accent-color, #444);
        color: var(--bg-primary, #fff);
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: 600;
        z-index: 1000;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
    `;
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) notification.parentNode.removeChild(notification);
        }, 300);
    }, 3000);
}

// Enhanced analytics functions

function toggleAnalytics() {
    const dashboard = document.getElementById('analyticsDashboard');
    if (!dashboard) return;
    
    if (dashboard.style.display === 'none' || dashboard.style.display === '') {
        dashboard.style.display = 'block';
        dashboard.style.opacity = '0';
        dashboard.style.transform = 'translateY(20px)';
        setTimeout(() => {
            dashboard.style.transition = 'all 0.5s ease';
            dashboard.style.opacity = '1';
            dashboard.style.transform = 'translateY(0)';
        }, 100);
        log('info', 'Analytics dashboard shown');
        showNotification('Analytics shown', 'info');
    } else {
        dashboard.style.transition = 'all 0.3s ease';
        dashboard.style.opacity = '0';
        dashboard.style.transform = 'translateY(20px)';
        setTimeout(() => {
            dashboard.style.display = 'none';
        }, 300);
        log('info', 'Analytics dashboard hidden');
        showNotification('Analytics hidden', 'info');
    }
} 