// Encryption helpers using Web Crypto API (AES-GCM + PBKDF2)
const ENCRYPTION_KEY_NAME = 'workify_enc_key';
const SALT = new Uint8Array([87,111,114,107,105,102,121,83,97,108,116,50,48,50,54,33]); // fixed salt

async function getEncryptionKey(passphrase) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: SALT, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, passphrase) {
    const key = await getEncryptionKey(passphrase);
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(JSON.stringify(data))
    );
    return JSON.stringify({
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted))
    });
}

async function decryptData(encryptedStr, passphrase) {
    const key = await getEncryptionKey(passphrase);
    const { iv, data } = JSON.parse(encryptedStr);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        key,
        new Uint8Array(data)
    );
    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decrypted));
}

function getPassphrase() {
    return sessionStorage.getItem('workify_passphrase');
}

function setPassphrase(p) {
    sessionStorage.setItem('workify_passphrase', p);
}

function getUsername() {
    return sessionStorage.getItem('workify_username');
}

function setUsername(u) {
    sessionStorage.setItem('workify_username', u);
}

function getStorageKey() {
    return 'workify_data_' + getUsername();
}

// --- EmailJS Integration ---
function getEmailConfig() {
    return JSON.parse(localStorage.getItem('workify_email_config_' + getUsername()) || 'null');
}

function setEmailConfig(config) {
    localStorage.setItem('workify_email_config_' + getUsername(), JSON.stringify(config));
}

async function sendEmail(toEmail, subject, message) {
    const config = getEmailConfig();
    if (!config || !config.publicKey || !config.serviceId || !config.templateId) {
        console.log('EmailJS not configured. Email simulated:', { toEmail, subject, message });
        return false;
    }

    try {
        emailjs.init(config.publicKey);
        await emailjs.send(config.serviceId, config.templateId, {
            to_email: toEmail,
            subject: subject,
            message: message
        });
        console.log('Email sent successfully to', toEmail);
        return true;
    } catch (err) {
        console.error('Failed to send email:', err);
        return false;
    }
}

// State
let activities = [];
let currentActivityId = null;

// DOM Elements
const authPage = document.getElementById('authPage');
const loginSection = document.getElementById('loginSection');
const signupSection = document.getElementById('signupSection');
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');
const appContainer = document.getElementById('appContainer');
const addForm = document.getElementById('addActivityForm');
const logModal = document.getElementById('logModal');
const logForm = document.getElementById('logForm');
const cancelLogBtn = document.getElementById('cancelLog');
const logsViewModal = document.getElementById('logsViewModal');
const closeLogsViewBtn = document.getElementById('closeLogsView');
const activitiesList = document.getElementById('activitiesList');
const emptyMessage = document.getElementById('emptyMessage');

// Show only one auth section
function showAuthSection(section) {
    [loginSection, signupSection].forEach(s => s.style.display = 'none');
    section.style.display = 'block';
}

// Toggle between login and signup
document.getElementById('showSignup').addEventListener('click', (e) => {
    e.preventDefault();
    showAuthSection(signupSection);
});

document.getElementById('showLogin').addEventListener('click', (e) => {
    e.preventDefault();
    showAuthSection(loginSection);
});

// Initialize
initApp();

async function initApp() {
    const username = getUsername();
    const passphrase = getPassphrase();

    if (username && passphrase) {
        await loadAndShow(passphrase);
    }
}

// Signup — directly create account
signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('signupEmail').value.trim().toLowerCase();
    const password = document.getElementById('signupPassword').value;
    const confirm = document.getElementById('signupConfirm').value;

    if (!email || !password) return;

    if (password !== confirm) {
        alert('Passwords do not match.');
        return;
    }

    const key = 'workify_data_' + email;
    if (localStorage.getItem(key)) {
        alert('An account with this email already exists. Please sign in.');
        return;
    }

    setUsername(email);
    setPassphrase(password);
    activities = [];
    await saveData();
    authPage.classList.add('hidden');
    appContainer.style.display = 'block';
    renderActivities();
});

// Login form handler
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value.trim().toLowerCase();
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) return;

    const key = 'workify_data_' + email;
    if (!localStorage.getItem(key)) {
        alert('No account found with this email. Please sign up first.');
        return;
    }

    setUsername(email);
    setPassphrase(password);

    await loadAndShow(password);
});

async function loadAndShow(passphrase) {
    const stored = localStorage.getItem(getStorageKey());
    if (stored) {
        try {
            activities = await decryptData(stored, passphrase);
        } catch (e) {
            alert('Wrong password. Please try again.');
            sessionStorage.removeItem('workify_passphrase');
            sessionStorage.removeItem('workify_username');
            return;
        }
    }
    authPage.classList.add('hidden');
    appContainer.style.display = 'block';
    await checkDataRetention();
    renderActivities();
}

async function saveData() {
    const passphrase = getPassphrase();
    const encrypted = await encryptData(activities, passphrase);
    localStorage.setItem(getStorageKey(), encrypted);
}

// --- Data Retention Logic ---
// Keep only current week, last week, and week before last (3 weeks total)
// Older data: send 2 warning "emails" with 2-day gap, then delete

function getMonday(d) {
    const date = new Date(d);
    const day = date.getDay();
    const diff = date.getDate() - day + (day === 0 ? -6 : 1);
    date.setHours(0, 0, 0, 0);
    date.setDate(diff);
    return date;
}

function getWeekLabel(dateStr) {
    const d = new Date(dateStr);
    const mon = getMonday(d);
    return mon.toISOString().split('T')[0];
}

function getRetentionKey() {
    return 'workify_retention_' + getUsername();
}

function getRetentionState() {
    return JSON.parse(localStorage.getItem(getRetentionKey()) || '{}');
}

function setRetentionState(state) {
    localStorage.setItem(getRetentionKey(), JSON.stringify(state));
}

async function checkDataRetention() {
    const now = new Date();
    const currentMonday = getMonday(now);
    const twoWeeksAgo = new Date(currentMonday);
    twoWeeksAgo.setDate(twoWeeksAgo.getDate() - 14); // Start of 2 weeks ago

    // Find activities with logs older than 2 full weeks before current week
    let hasOldData = false;
    const oldWeeks = new Set();

    activities.forEach(activity => {
        const weekStart = activity.weekStart ? new Date(activity.weekStart) : null;
        if (weekStart && weekStart < twoWeeksAgo) {
            hasOldData = true;
            oldWeeks.add(activity.weekStart);
        }
        // Also check individual logs for activities without weekStart
        if (!activity.weekStart) {
            activity.logs.forEach(log => {
                const logDate = new Date(log.date);
                const logMonday = getMonday(logDate);
                if (logMonday < twoWeeksAgo) {
                    hasOldData = true;
                    oldWeeks.add(logMonday.toISOString().split('T')[0]);
                }
            });
        }
    });

    if (!hasOldData) {
        // No old data, clear retention warnings
        const retState = getRetentionState();
        if (retState.firstWarning) {
            setRetentionState({});
        }
        document.getElementById('retentionBanner').style.display = 'none';
        return;
    }

    // We have old data — manage warning/deletion cycle
    const retState = getRetentionState();
    const today = now.toISOString().split('T')[0];

    if (!retState.firstWarning) {
        // Send first warning
        retState.firstWarning = today;
        const deleteDate = new Date(now);
        deleteDate.setDate(deleteDate.getDate() + 4);
        retState.scheduledDeletion = deleteDate.toISOString().split('T')[0];
        setRetentionState(retState);
        showRetentionBanner(1, retState, oldWeeks);
        // Send actual email
        const weeks = Array.from(oldWeeks).sort().join(', ');
        sendEmail(
            getUsername(),
            'Workify: Your old activity data will be deleted on ' + retState.scheduledDeletion,
            'Hi,\n\nThis is a reminder that your Workify activity data from weeks (' + weeks + ') is older than 2 weeks and will be permanently deleted on ' + retState.scheduledDeletion + '.\n\nA second and final reminder will be sent in 2 days.\n\nPlease export any data you wish to keep.\n\n— Workify'
        );
    } else if (!retState.secondWarning) {
        // Check if 2 days have passed since first warning
        const firstDate = new Date(retState.firstWarning);
        const daysSinceFirst = Math.floor((now - firstDate) / (1000 * 60 * 60 * 24));
        if (daysSinceFirst >= 2) {
            retState.secondWarning = today;
            setRetentionState(retState);
            showRetentionBanner(2, retState, oldWeeks);
            // Send actual email
            const weeks = Array.from(oldWeeks).sort().join(', ');
            sendEmail(
                getUsername(),
                'FINAL NOTICE — Workify data deletion on ' + retState.scheduledDeletion,
                'Hi,\n\nThis is your FINAL WARNING. Your Workify activity data from weeks (' + weeks + ') will be PERMANENTLY DELETED on ' + retState.scheduledDeletion + '.\n\nThis cannot be undone. Please export any data you wish to keep immediately.\n\n— Workify'
            );
        } else {
            showRetentionBanner(1, retState, oldWeeks);
        }
    } else {
        // Check if 2 days have passed since second warning — delete old data
        const secondDate = new Date(retState.secondWarning);
        const daysSinceSecond = Math.floor((now - secondDate) / (1000 * 60 * 60 * 24));
        if (daysSinceSecond >= 2) {
            // Delete old data
            activities = activities.filter(activity => {
                const weekStart = activity.weekStart ? new Date(activity.weekStart) : null;
                if (weekStart && weekStart < twoWeeksAgo) return false;
                return true;
            });
            // Also remove old logs from activities without weekStart
            activities.forEach(activity => {
                if (!activity.weekStart) {
                    activity.logs = activity.logs.filter(log => {
                        const logMonday = getMonday(new Date(log.date));
                        return logMonday >= twoWeeksAgo;
                    });
                    activity.count = activity.logs.length;
                }
            });
            setRetentionState({});
            await saveData();
            document.getElementById('retentionBanner').style.display = 'none';
        } else {
            showRetentionBanner(2, retState, oldWeeks);
        }
    }
}

function showRetentionBanner(warningNum, retState, oldWeeks) {
    const banner = document.getElementById('retentionBanner');
    const content = document.getElementById('retentionContent');
    const weeks = Array.from(oldWeeks).sort().join(', ');
    const deleteDate = retState.scheduledDeletion;

    let html = '';
    if (warningNum === 1) {
        html = `<strong>⚠️ Data Retention Warning (Email 1 of 2)</strong><br>
        You have activity data from old weeks (${weeks}) that exceeds the 2-week retention period.
        <div class="email-sim">
            <strong>To:</strong> ${getUsername()}<br>
            <strong>Subject:</strong> Your old Workify data will be deleted on ${deleteDate}<br><br>
            This is a reminder that data older than 2 weeks will be permanently deleted on <strong>${deleteDate}</strong>.
            A second reminder will be sent in 2 days.
        </div>`;
    } else {
        html = `<strong>⚠️ Final Data Retention Warning (Email 2 of 2)</strong><br>
        This is the final warning. Old data from weeks (${weeks}) will be deleted on <strong>${deleteDate}</strong>.
        <div class="email-sim">
            <strong>To:</strong> ${getUsername()}<br>
            <strong>Subject:</strong> FINAL NOTICE — Workify data deletion on ${deleteDate}<br><br>
            Your old activity data will be <strong>permanently deleted</strong> on <strong>${deleteDate}</strong>.
            Please export any data you wish to keep.
        </div>`;
    }

    content.innerHTML = html;
    banner.style.display = 'flex';
}

// Dismiss banner (only hides for current session)
document.getElementById('dismissBanner').addEventListener('click', () => {
    document.getElementById('retentionBanner').style.display = 'none';
});

// Add Activity
addForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('activityName').value.trim();
    const target = parseInt(document.getElementById('activityTarget').value);

    if (!name || !target) return;

    const activity = {
        id: Date.now().toString(),
        name,
        target,
        count: 0,
        logs: [],
        weekStart: getMonday(new Date()).toISOString().split('T')[0]
    };

    activities.push(activity);
    saveAndRender();
    addForm.reset();
});

// Log Modal
cancelLogBtn.addEventListener('click', () => {
    logModal.classList.remove('active');
    currentActivityId = null;
});

logForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const personName = document.getElementById('logName').value.trim();
    const description = document.getElementById('logDescription').value.trim();

    if (!personName) return;

    const activity = activities.find(a => a.id === currentActivityId);
    if (activity) {
        const now = new Date();
        const dayName = now.toLocaleDateString('en-US', { weekday: 'long' });
        activity.count++;
        activity.logs.push({
            person: personName,
            description: description,
            date: now.toLocaleString(),
            day: dayName
        });
        saveAndRender();
    }

    logModal.classList.remove('active');
    logForm.reset();
    currentActivityId = null;
});

// Close logs view
closeLogsViewBtn.addEventListener('click', () => {
    logsViewModal.classList.remove('active');
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', () => {
    sessionStorage.removeItem('workify_passphrase');
    sessionStorage.removeItem('workify_username');
    activities = [];
    appContainer.style.display = 'none';
    authPage.classList.remove('hidden');
    loginForm.reset();
    signupForm.reset();
    showAuthSection(loginSection);
});

// Email Settings
document.getElementById('emailSettingsBtn').addEventListener('click', () => {
    const config = getEmailConfig() || {};
    document.getElementById('ejsPublicKey').value = config.publicKey || '';
    document.getElementById('ejsServiceId').value = config.serviceId || '';
    document.getElementById('ejsTemplateId').value = config.templateId || '';
    document.getElementById('emailSettingsModal').classList.add('active');
});

document.getElementById('cancelEmailSettings').addEventListener('click', () => {
    document.getElementById('emailSettingsModal').classList.remove('active');
});

document.getElementById('emailSettingsForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const config = {
        publicKey: document.getElementById('ejsPublicKey').value.trim(),
        serviceId: document.getElementById('ejsServiceId').value.trim(),
        templateId: document.getElementById('ejsTemplateId').value.trim()
    };
    setEmailConfig(config);
    document.getElementById('emailSettingsModal').classList.remove('active');
    alert('Email settings saved! You will now receive real emails for data retention warnings.');
});

// Weekly Summary
document.getElementById('viewSummaryBtn').addEventListener('click', () => {
    showWeeklySummary();
});

// Detailed Summary
document.getElementById('viewDetailedBtn').addEventListener('click', () => {
    showDetailedSummary();
});

// Functions
function saveAndRender() {
    saveData();
    renderActivities();
}

function renderActivities() {
    if (activities.length === 0) {
        activitiesList.innerHTML = '';
        emptyMessage.style.display = 'block';
        return;
    }

    emptyMessage.style.display = 'none';
    activitiesList.innerHTML = activities.map(activity => {
        const percentage = Math.min((activity.count / activity.target) * 100, 100);
        const isComplete = activity.count >= activity.target;

        return `
            <div class="activity-card">
                <div class="activity-info">
                    <div class="activity-name">${escapeHtml(activity.name)}</div>
                    <div class="activity-progress">${activity.count} / ${activity.target} done this week</div>
                    <div class="progress-bar">
                        <div class="progress-fill ${isComplete ? 'complete' : ''}" style="width: ${percentage}%"></div>
                    </div>
                </div>
                <span class="activity-target">Target: ${activity.target}/week</span>
                <div class="counter-section">
                    <button class="btn-counter btn-minus" onclick="decrementCounter('${activity.id}')">−</button>
                    <span class="counter-value ${isComplete ? 'target-reached' : ''}">${activity.count}</span>
                    <button class="btn-counter btn-plus" onclick="incrementCounter('${activity.id}')">+</button>
                </div>
                <div class="activity-actions">
                    <button class="activity-logs-btn" onclick="viewLogs('${activity.id}')">Logs (${activity.logs.length})</button>
                    <button class="delete-activity" onclick="deleteActivity('${activity.id}')" title="Delete">&times;</button>
                </div>
            </div>
        `;
    }).join('');
}

function incrementCounter(id) {
    currentActivityId = id;
    document.getElementById('logDate').value = new Date().toLocaleString();
    logModal.classList.add('active');
    document.getElementById('logName').focus();
}

function decrementCounter(id) {
    const activity = activities.find(a => a.id === id);
    if (activity && activity.count > 0) {
        activity.count--;
        activity.logs.pop();
        saveAndRender();
    }
}

function deleteActivity(id) {
    if (confirm('Delete this activity?')) {
        activities = activities.filter(a => a.id !== id);
        saveAndRender();
    }
}

function viewLogs(id) {
    const activity = activities.find(a => a.id === id);
    if (!activity) return;

    document.getElementById('logsTitle').textContent = `Logs - ${activity.name}`;
    const logsContent = document.getElementById('logsContent');

    if (activity.logs.length === 0) {
        logsContent.innerHTML = '<p class="no-logs">No logs yet. Click + to log an activity.</p>';
    } else {
        logsContent.innerHTML = activity.logs.map(log => `
            <div class="log-entry">
                <div class="log-date">${escapeHtml(log.date)}</div>
                <div class="log-person">With: ${escapeHtml(log.person)}</div>
                ${log.description ? `<div class="log-desc">${escapeHtml(log.description)}</div>` : ''}
            </div>
        `).join('');
    }

    logsViewModal.classList.add('active');
}

function showDetailedSummary() {
    const logsContent = document.getElementById('logsContent');
    document.getElementById('logsTitle').textContent = 'Detailed Summary';

    let html = '';
    activities.forEach(activity => {
        if (activity.logs.length > 0) {
            html += `<div class="summary-day"><h4>${escapeHtml(activity.name)} [${activity.count}/${activity.target}]</h4>`;
            activity.logs.forEach(log => {
                html += `<div class="detailed-entry">
                    <span class="detail-name">${escapeHtml(log.person)}</span>
                    <span class="detail-date">${escapeHtml(log.date)}</span>
                    ${log.description ? `<span class="detail-desc">${escapeHtml(log.description)}</span>` : ''}
                </div>`;
            });
            html += '</div>';
        }
    });

    if (!html) {
        html = '<p class="no-logs">No activity logged yet.</p>';
    }

    logsContent.innerHTML = html;
    logsViewModal.classList.add('active');
}

function showWeeklySummary() {
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    const logsContent = document.getElementById('logsContent');
    document.getElementById('logsTitle').textContent = 'Weekly Summary';

    let html = '';

    // Show activities with no logs as "activity - target"
    const noLogActivities = activities.filter(a => a.logs.length === 0);
    if (noLogActivities.length > 0) {
        html += '<div class="summary-day"><h4>Pending Activities</h4>';
        noLogActivities.forEach(activity => {
            html += `<div class="summary-entry">${escapeHtml(activity.name)} - ${activity.target}</div>`;
        });
        html += '</div>';
    }

    days.forEach(day => {
        const dayEntries = [];
        activities.forEach(activity => {
            const dayLogs = activity.logs.filter(log => log.day === day);
            if (dayLogs.length > 0) {
                const names = dayLogs.map(l => l.person).join(', ');
                dayEntries.push(`${escapeHtml(activity.name)}[${dayLogs.length}/${activity.target}]: ${escapeHtml(names)}`);
            }
        });

        if (dayEntries.length > 0) {
            html += `<div class="summary-day"><h4>${day}</h4>`;
            dayEntries.forEach(entry => {
                html += `<div class="summary-entry">${entry}</div>`;
            });
            html += '</div>';
        }
    });

    if (!html) {
        html = '<p class="no-logs">No activities added yet.</p>';
    }

    logsContent.innerHTML = html;
    logsViewModal.classList.add('active');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
