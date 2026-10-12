/**
 * CampusMate - Client Application Logic
 * Manages Auth, Classrooms, Invitation Workflow, Owner Dashboard, Timeline & Tasks
 */

// Global State
const state = {
    user: null,
    token: localStorage.getItem("cm_token") || null,
    currentClassroom: null,
    pendingInviteToken: null,
    notifications: [],
    classrooms: [],
    tasks: []
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener("DOMContentLoaded", async () => {
    // Check URL parameters for invitation links (?invite=TOKEN)
    const urlParams = new URLSearchParams(window.location.search);
    const inviteParam = urlParams.get("invite");
    if (inviteParam) {
        state.pendingInviteToken = inviteParam;
    }

    if (state.token) {
        const authed = await fetchCurrentUser();
        if (authed) {
            handlePostAuthRouting();
        } else {
            navigateTo("screen-auth");
        }
    } else {
        if (state.pendingInviteToken) {
            // Unauthenticated user opened an invite link
            await loadInvitationPreview(state.pendingInviteToken, false);
        } else {
            navigateTo("screen-auth");
        }
    }

    refreshIcons();
});

function refreshIcons() {
    if (window.lucide) {
        lucide.createIcons();
    }
}

function handlePostAuthRouting() {
    updateNavUser();
    fetchNotifications();

    if (state.pendingInviteToken) {
        loadInvitationPreview(state.pendingInviteToken, true);
    } else {
        navigateTo("screen-classrooms");
        loadClassrooms();
    }
}

// ============================================================================
// NAVIGATION & SCREENS
// ============================================================================
function navigateTo(screenId) {
    document.querySelectorAll(".view-screen").forEach(el => el.classList.add("hidden"));
    const target = document.getElementById(screenId);
    if (target) {
        target.classList.remove("hidden");
    }

    const headerUser = document.getElementById("header-user-section");
    const mobileNav = document.getElementById("mobile-nav");

    if (screenId === "screen-auth") {
        headerUser.classList.add("hidden");
        mobileNav.classList.add("hidden");
    } else {
        if (state.user) {
            headerUser.classList.remove("hidden");
            mobileNav.classList.remove("hidden");
        }
    }

    if (screenId === "screen-tasks") {
        loadTasks();
    } else if (screenId === "screen-classrooms") {
        loadClassrooms();
    } else if (screenId === "screen-profile") {
        renderProfile();
    }

    refreshIcons();
    window.scrollTo({ top: 0, behavior: "smooth" });
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "toast-item max-w-sm px-4 py-3 rounded-xl shadow-lg text-xs font-semibold flex items-center space-x-2 pointer-events-auto transition";

    let bgClass = "bg-slate-900 text-white";
    let iconName = "info";

    if (type === "success") {
        bgClass = "bg-emerald-600 text-white shadow-emerald-600/20";
        iconName = "check-circle";
    } else if (type === "error") {
        bgClass = "bg-rose-600 text-white shadow-rose-600/20";
        iconName = "alert-circle";
    } else if (type === "warning") {
        bgClass = "bg-amber-600 text-white shadow-amber-600/20";
        iconName = "alert-triangle";
    }

    toast.className += ` ${bgClass}`;
    toast.innerHTML = `<i data-lucide="${iconName}" class="w-4 h-4 shrink-0"></i> <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    refreshIcons();

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 250);
    }, 3500);
}

// ============================================================================
// AUTHENTICATION WORKFLOW (Strictly Name, Email, Roll Number)
// ============================================================================
function switchAuthTab(tab) {
    const loginForm = document.getElementById("form-login");
    const regForm = document.getElementById("form-register");
    const loginTabBtn = document.getElementById("tab-login-btn");
    const regTabBtn = document.getElementById("tab-register-btn");

    if (tab === "register") {
        loginForm.classList.add("hidden");
        regForm.classList.remove("hidden");
        loginTabBtn.className = "flex-1 py-2 text-xs font-semibold rounded-lg text-slate-600 hover:text-slate-900 transition";
        regTabBtn.className = "flex-1 py-2 text-xs font-semibold rounded-lg bg-white text-slate-900 shadow-sm transition";
        document.getElementById("auth-title").innerText = "Create Student Profile";
        document.getElementById("auth-subtitle").innerText = "Enter your verified college credentials to register";
    } else {
        loginForm.classList.remove("hidden");
        regForm.classList.add("hidden");
        loginTabBtn.className = "flex-1 py-2 text-xs font-semibold rounded-lg bg-white text-slate-900 shadow-sm transition";
        regTabBtn.className = "flex-1 py-2 text-xs font-semibold rounded-lg text-slate-600 hover:text-slate-900 transition";
        document.getElementById("auth-title").innerText = "Welcome to CampusMate";
        document.getElementById("auth-subtitle").innerText = "Secure verified classroom access for academic groups";
    }
    refreshIcons();
}

function fillDemoCredentials(email, pass) {
    switchAuthTab("login");
    document.getElementById("login-email").value = email;
    document.getElementById("login-password").value = pass;
}

async function handleRegister(e) {
    e.preventDefault();
    const fullName = document.getElementById("reg-name").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const rollNumber = document.getElementById("reg-roll").value.trim();
    const password = document.getElementById("reg-password").value;

    if (!fullName || !email || !rollNumber || !password) {
        showToast("Please fill in all required fields", "warning");
        return;
    }

    try {
        const res = await fetch("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                full_name: fullName,
                college_email: email,
                roll_number: rollNumber,
                password: password
            })
        });

        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Registration failed", "error");
            return;
        }

        state.token = data.token;
        state.user = data.user;
        localStorage.setItem("cm_token", data.token);

        showToast("Registration successful! College email verified.", "success");
        handlePostAuthRouting();
    } catch (err) {
        showToast("Network error during registration", "error");
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;

    try {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Login failed", "error");
            return;
        }

        state.token = data.token;
        state.user = data.user;
        localStorage.setItem("cm_token", data.token);

        showToast(`Welcome back, ${data.user.full_name}!`, "success");
        handlePostAuthRouting();
    } catch (err) {
        showToast("Network error during sign in", "error");
    }
}

async function fetchCurrentUser() {
    try {
        const res = await fetch("/api/auth/me", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) {
            localStorage.removeItem("cm_token");
            state.token = null;
            state.user = null;
            return false;
        }
        const data = await res.json();
        state.user = data.user;
        return true;
    } catch (err) {
        return false;
    }
}

function handleLogout() {
    fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}` }
    });
    localStorage.removeItem("cm_token");
    state.token = null;
    state.user = null;
    showToast("Signed out successfully", "info");
    navigateTo("screen-auth");
}

function updateNavUser() {
    if (!state.user) return;
    document.getElementById("nav-user-name").innerText = state.user.full_name;
    document.getElementById("nav-user-avatar").innerText = state.user.full_name.charAt(0).toUpperCase();
}

// ============================================================================
// CLASSROOMS (MY CLASSROOMS & CREATION)
// ============================================================================
async function loadClassrooms() {
    const grid = document.getElementById("classrooms-grid");
    grid.innerHTML = `<div class="col-span-full text-center py-12 text-slate-400 text-xs">Loading classrooms...</div>`;

    try {
        const res = await fetch("/api/classrooms", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        state.classrooms = data.classrooms || [];

        if (state.classrooms.length === 0) {
            grid.innerHTML = `
                <div class="col-span-full bg-white rounded-2xl border border-slate-200/80 p-12 text-center space-y-3">
                    <div class="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-xl flex items-center justify-center mx-auto">
                        <i data-lucide="book-open" class="w-6 h-6"></i>
                    </div>
                    <h3 class="text-sm font-bold text-slate-800">No Enrolled Classrooms</h3>
                    <p class="text-xs text-slate-500 max-w-sm mx-auto">You have not created or joined any classrooms yet. Create a new classroom as an owner or request access via an invite link.</p>
                    <div class="pt-2 flex justify-center gap-2">
                        <button onclick="navigateTo('screen-create-classroom')" class="px-4 py-2 bg-brand-600 text-white rounded-xl text-xs font-semibold hover:bg-brand-700">Create Classroom</button>
                        <button onclick="openJoinModal()" class="px-4 py-2 bg-slate-100 text-slate-700 rounded-xl text-xs font-semibold hover:bg-slate-200">Enter Invite Link</button>
                    </div>
                </div>
            `;
            refreshIcons();
            return;
        }

        grid.innerHTML = state.classrooms.map(c => {
            const isOwner = c.role === "owner";
            const badgeClass = isOwner ? "bg-amber-50 text-amber-700 border-amber-200" : "bg-indigo-50 text-indigo-700 border-indigo-200";
            const roleIcon = isOwner ? "crown" : "user-check";

            return `
                <div class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-sm hover:shadow-md transition flex flex-col justify-between">
                    <div class="space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${badgeClass} flex items-center gap-1">
                                <i data-lucide="${roleIcon}" class="w-3 h-3"></i>
                                ${isOwner ? 'Owner' : 'Member'}
                            </span>
                            <span class="text-xs text-slate-400 flex items-center gap-1">
                                <i data-lucide="users" class="w-3.5 h-3.5"></i> ${c.member_count} members
                            </span>
                        </div>
                        <h3 class="text-base font-bold text-slate-900 leading-snug cursor-pointer hover:text-brand-600 transition" onclick="openClassroom('${c.id}')">${escapeHtml(c.name)}</h3>
                        <p class="text-xs text-slate-500 line-clamp-2">${escapeHtml(c.description || 'No description provided.')}</p>
                    </div>

                    <div class="pt-4 mt-3 border-t border-slate-100 flex items-center justify-between">
                        <span class="text-[11px] text-slate-400 truncate max-w-[130px]">By ${escapeHtml(c.owner_name)}</span>
                        <div class="flex items-center space-x-1.5">
                            ${isOwner ? `
                                <button onclick="openOwnerDashboard('${c.id}')" class="px-2.5 py-1.5 text-xs font-semibold rounded-lg bg-amber-50 text-amber-700 hover:bg-amber-100 border border-amber-200 flex items-center gap-1">
                                    <i data-lucide="shield" class="w-3.5 h-3.5"></i>
                                    <span>Manage</span>
                                    ${c.pending_count > 0 ? `<span class="bg-rose-500 text-white rounded-full px-1.5 text-[9px]">${c.pending_count}</span>` : ''}
                                </button>
                            ` : ''}
                            <button onclick="openClassroom('${c.id}')" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-50 text-brand-700 hover:bg-brand-100 border border-brand-200 flex items-center gap-1">
                                <span>Timeline</span>
                                <i data-lucide="arrow-right" class="w-3 h-3"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join("");

        refreshIcons();
    } catch (err) {
        showToast("Error loading classrooms", "error");
    }
}

async function handleCreateClassroom(e) {
    e.preventDefault();
    const name = document.getElementById("create-cls-name").value.trim();
    const desc = document.getElementById("create-cls-desc").value.trim();

    try {
        const res = await fetch("/api/classrooms", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ name, description: desc })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to create classroom", "error");
            return;
        }

        showToast("Classroom created successfully! You are the designated owner.", "success");
        document.getElementById("create-cls-name").value = "";
        document.getElementById("create-cls-desc").value = "";

        // Open newly created classroom owner dashboard
        openOwnerDashboard(data.classroom.id);
    } catch (err) {
        showToast("Error creating classroom", "error");
    }
}

// ============================================================================
// INVITATION LINK PREVIEW & JOIN REQUEST WORKFLOW
// ============================================================================
async function loadInvitationPreview(token, isAuthed) {
    state.pendingInviteToken = token;

    try {
        const headers = {};
        if (state.token) headers["Authorization"] = `Bearer ${state.token}`;

        const res = await fetch(`/api/invitations/preview?token=${encodeURIComponent(token)}`, { headers });
        const data = await res.json();

        if (res.status === 410) {
            // Revoked or Expired
            navigateTo("screen-invite-preview");
            document.getElementById("preview-cls-name").innerText = "Invitation Inactive";
            document.getElementById("preview-cls-desc").innerText = "";
            document.getElementById("preview-owner-name").innerText = "--";
            document.getElementById("preview-action-area").innerHTML = `
                <div class="bg-rose-50 border border-rose-200 rounded-xl p-4 text-center text-xs text-rose-800 font-semibold">
                    <i data-lucide="alert-triangle" class="w-6 h-6 mx-auto mb-1 text-rose-600"></i>
                    Status: ${data.status === 'revoked' ? 'Invitation Revoked' : 'Invitation Expired'}
                    <p class="text-[11px] font-normal text-rose-600 mt-1">This invitation link has been invalidated by the classroom owner.</p>
                </div>
            `;
            refreshIcons();
            return;
        }

        if (!res.ok || !data.valid) {
            showToast(data.error || "Invalid invitation link", "error");
            navigateTo("screen-classrooms");
            return;
        }

        // Show preview screen
        navigateTo("screen-invite-preview");
        document.getElementById("preview-cls-name").innerText = data.classroom_name;
        document.getElementById("preview-cls-desc").innerText = data.description || "Classroom invite";
        document.getElementById("preview-owner-name").innerText = data.owner_name;

        const actionArea = document.getElementById("preview-action-area");

        if (!state.user) {
            // Unauthenticated applicant
            actionArea.innerHTML = `
                <div class="bg-slate-50 border border-slate-200 rounded-xl p-4 text-center space-y-2">
                    <p class="text-xs text-slate-600">Please sign in or register with your college email to request access.</p>
                    <button onclick="navigateTo('screen-auth')" class="w-full py-2.5 rounded-xl bg-brand-600 text-white font-semibold text-xs hover:bg-brand-700 shadow-md">
                        Sign In or Register
                    </button>
                </div>
            `;
        } else if (data.is_member) {
            actionArea.innerHTML = `
                <div class="bg-emerald-50 border border-emerald-200 rounded-xl p-4 text-center space-y-2">
                    <p class="text-xs text-emerald-800 font-semibold">You are already an approved member of this classroom!</p>
                    <button onclick="openClassroom('${data.classroom_id}')" class="w-full py-2.5 rounded-xl bg-emerald-600 text-white font-semibold text-xs hover:bg-emerald-700">
                        Go to Classroom Timeline
                    </button>
                </div>
            `;
        } else if (data.request_status === "pending") {
            navigateTo("screen-request-pending");
            document.getElementById("pending-cls-name").innerText = data.classroom_name;
            return;
        } else {
            actionArea.innerHTML = `
                <button onclick="handleRequestJoin()" id="btn-request-join" class="w-full py-3 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm shadow-lg shadow-brand-500/25 transition flex items-center justify-center space-x-2">
                    <i data-lucide="user-plus" class="w-4 h-4"></i>
                    <span>Request to Join</span>
                </button>
            `;
        }

        refreshIcons();
    } catch (err) {
        showToast("Error inspecting invitation link", "error");
    }
}

async function handleRequestJoin() {
    if (!state.pendingInviteToken) return;

    try {
        const res = await fetch("/api/invitations/request-join", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ token: state.pendingInviteToken })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to submit request", "error");
            return;
        }

        // Show pending screen with exact prompt requirements
        navigateTo("screen-request-pending");
        document.getElementById("pending-cls-name").innerText = document.getElementById("preview-cls-name").innerText;
        showToast("Join request sent to classroom owner", "success");
    } catch (err) {
        showToast("Error sending join request", "error");
    }
}

function openJoinModal() {
    document.getElementById("modal-join-input").value = "";
    openModal("modal-join");
}

function submitJoinCode() {
    let input = document.getElementById("modal-join-input").value.trim();
    if (!input) {
        showToast("Please enter an invitation link or token", "warning");
        return;
    }
    // Extract token if user pasted full URL
    if (input.includes("invite=")) {
        const url = new URL(input, window.location.origin);
        input = url.searchParams.get("invite");
    }
    closeModal("modal-join");
    loadInvitationPreview(input, !!state.user);
}

// ============================================================================
// OWNER DASHBOARD & MEMBERSHIP MANAGEMENT
// ============================================================================
async function openOwnerDashboard(classroomId) {
    state.currentClassroom = classroomId;
    navigateTo("screen-owner-dashboard");

    try {
        const res = await fetch(`/api/classrooms/${classroomId}`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (!res.ok) {
            showToast("Access denied: You are not the owner of this classroom", "error");
            navigateTo("screen-classrooms");
            return;
        }
        const data = await res.json();
        const cls = data.classroom;

        document.getElementById("owner-dash-cls-name").innerText = cls.name;
        document.getElementById("owner-dash-cls-desc").innerText = cls.description || "Classroom Management Panel";

        // Load active invitation
        loadActiveInvitation(classroomId);

        // Load requests & members
        loadOwnerRequests(classroomId);
        loadOwnerMembers(classroomId);
    } catch (err) {
        showToast("Error opening owner dashboard", "error");
    }
}

async function loadActiveInvitation(classroomId) {
    const box = document.getElementById("active-invite-box");
    box.innerHTML = `<p class="text-xs text-slate-400">Checking active invitation link...</p>`;

    try {
        const res = await fetch(`/api/classrooms/${classroomId}/invitation/active`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        const inv = data.active_invitation;

        if (!inv) {
            box.innerHTML = `
                <div class="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                        <span class="text-xs font-semibold text-slate-700 block">No Active Invitation Link</span>
                        <span class="text-[11px] text-slate-400">Generate a secure link to allow classmates to submit join requests.</span>
                    </div>
                    <button onclick="openCreateInviteModal()" class="px-3.5 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-xs font-semibold">
                        Generate Invitation Link
                    </button>
                </div>
            `;
            return;
        }

        const expiresTxt = inv.expires_at ? `Expires: ${new Date(inv.expires_at).toLocaleDateString()}` : "No Expiration";

        box.innerHTML = `
            <div class="bg-indigo-50/50 border border-indigo-200/70 rounded-xl p-4 space-y-3">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div class="flex items-center space-x-2">
                        <span class="text-xs font-semibold text-indigo-900">Active Link Token Hash:</span>
                        <code class="text-[11px] bg-white px-2 py-0.5 rounded border border-indigo-200 text-indigo-700 font-mono">${inv.token_hash.slice(0, 16)}...</code>
                    </div>
                    <span class="text-[11px] font-semibold text-indigo-600 bg-white px-2 py-0.5 rounded border border-indigo-200">${expiresTxt}</span>
                </div>

                <div class="flex flex-wrap items-center gap-2 pt-1">
                    <button onclick="copyCurrentInviteLink()" class="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-800 text-xs font-semibold border border-indigo-200 shadow-sm flex items-center gap-1.5">
                        <i data-lucide="copy" class="w-3.5 h-3.5 text-brand-600"></i>
                        <span>Copy Link</span>
                    </button>
                    <button onclick="shareCurrentInviteLink()" class="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-800 text-xs font-semibold border border-indigo-200 shadow-sm flex items-center gap-1.5">
                        <i data-lucide="share-2" class="w-3.5 h-3.5 text-indigo-600"></i>
                        <span>Share Link</span>
                    </button>
                    <button onclick="revokeInviteLink()" class="px-3 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold border border-rose-200 shadow-sm flex items-center gap-1.5 ml-auto">
                        <i data-lucide="shield-x" class="w-3.5 h-3.5 text-rose-600"></i>
                        <span>Revoke Link</span>
                    </button>
                </div>
            </div>
        `;
        refreshIcons();
    } catch (err) {
        box.innerHTML = `<p class="text-xs text-rose-500">Failed to load invitation info</p>`;
    }
}

function openCreateInviteModal() {
    openModal("modal-create-invite");
}

async function confirmCreateInvitation() {
    closeModal("modal-create-invite");
    const expireSelect = document.getElementById("invite-expire-select").value;

    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/invitation`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ expires_in_days: expireSelect || null })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to create invitation", "error");
            return;
        }

        showToast("New invitation link generated! Copied to clipboard.", "success");
        if (navigator.clipboard) {
            navigator.clipboard.writeText(data.invite_url);
        }
        state.lastGeneratedInviteUrl = data.invite_url;
        loadActiveInvitation(state.currentClassroom);
    } catch (err) {
        showToast("Error generating invitation link", "error");
    }
}

async function copyCurrentInviteLink() {
    if (state.lastGeneratedInviteUrl) {
        navigator.clipboard.writeText(state.lastGeneratedInviteUrl);
        showToast("Classroom invite link copied to clipboard!", "success");
        return;
    }
    // If not in memory, generate fresh
    confirmCreateInvitation();
}

function shareCurrentInviteLink() {
    const url = state.lastGeneratedInviteUrl || window.location.origin;
    if (navigator.share) {
        navigator.share({
            title: "Join Classroom on CampusMate",
            text: "Here is your invitation to join our classroom on CampusMate:",
            url: url
        }).catch(() => {});
    } else {
        copyCurrentInviteLink();
    }
}

async function revokeInviteLink() {
    if (!confirm("Are you sure you want to revoke this invitation link? New applicants will no longer be able to use it, but existing approved members will keep access.")) {
        return;
    }

    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/invitation/revoke`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to revoke link", "error");
            return;
        }

        showToast("Invitation link revoked successfully.", "success");
        state.lastGeneratedInviteUrl = null;
        loadActiveInvitation(state.currentClassroom);
    } catch (err) {
        showToast("Error revoking link", "error");
    }
}

function switchOwnerTab(tab) {
    const reqBtn = document.getElementById("tab-requests-btn");
    const memBtn = document.getElementById("tab-members-btn");
    const reqPanel = document.getElementById("owner-requests-panel");
    const memPanel = document.getElementById("owner-members-panel");

    if (tab === "requests") {
        reqPanel.classList.remove("hidden");
        memPanel.classList.add("hidden");
        reqBtn.className = "flex-1 py-3 text-xs font-bold border-b-2 border-brand-600 text-brand-600 flex items-center justify-center space-x-2";
        memBtn.className = "flex-1 py-3 text-xs font-bold border-b-2 border-transparent text-slate-500 hover:text-slate-800 flex items-center justify-center space-x-2";
    } else {
        reqPanel.classList.add("hidden");
        memPanel.classList.remove("hidden");
        memBtn.className = "flex-1 py-3 text-xs font-bold border-b-2 border-brand-600 text-brand-600 flex items-center justify-center space-x-2";
        reqBtn.className = "flex-1 py-3 text-xs font-bold border-b-2 border-transparent text-slate-500 hover:text-slate-800 flex items-center justify-center space-x-2";
    }
    refreshIcons();
}

async function loadOwnerRequests(classroomId) {
    const list = document.getElementById("owner-requests-list");
    list.innerHTML = `<p class="text-xs text-slate-400">Loading join requests...</p>`;

    try {
        const res = await fetch(`/api/classrooms/${classroomId}/requests`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        const requests = data.requests || [];

        const pending = requests.filter(r => r.status === "pending");
        document.getElementById("owner-pending-badge").innerText = pending.length;

        if (pending.length === 0) {
            list.innerHTML = `
                <div class="text-center py-8 text-slate-400 text-xs">
                    <i data-lucide="user-check" class="w-8 h-8 mx-auto mb-2 text-slate-300"></i>
                    No pending join requests.
                </div>
            `;
            refreshIcons();
            return;
        }

        list.innerHTML = pending.map(r => `
            <div class="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div class="space-y-1">
                    <div class="flex items-center space-x-2">
                        <span class="text-xs font-bold text-slate-900">${escapeHtml(r.full_name)}</span>
                        <span class="text-[10px] font-semibold bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded border border-indigo-200">Roll: ${escapeHtml(r.roll_number)}</span>
                    </div>
                    <div class="text-[11px] text-slate-500 flex items-center space-x-3">
                        <span>${escapeHtml(r.college_email)}</span>
                        <span>•</span>
                        <span>Requested: ${new Date(r.requested_at).toLocaleDateString()}</span>
                    </div>
                </div>

                <div class="flex items-center space-x-2">
                    <button onclick="approveRequest('${r.id}')" class="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-sm transition flex items-center gap-1">
                        <i data-lucide="check" class="w-3.5 h-3.5"></i>
                        <span>Approve</span>
                    </button>
                    <button onclick="rejectRequest('${r.id}')" class="px-3.5 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold border border-rose-200 transition flex items-center gap-1">
                        <i data-lucide="x" class="w-3.5 h-3.5"></i>
                        <span>Reject</span>
                    </button>
                </div>
            </div>
        `).join("");

        refreshIcons();
    } catch (err) {
        list.innerHTML = `<p class="text-xs text-rose-500">Failed to load requests</p>`;
    }
}

async function approveRequest(requestId) {
    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/requests/${requestId}/approve`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Approval failed", "error");
            return;
        }

        showToast("Student approved! Access granted and tasks synced.", "success");
        loadOwnerRequests(state.currentClassroom);
        loadOwnerMembers(state.currentClassroom);
    } catch (err) {
        showToast("Error approving request", "error");
    }
}

async function rejectRequest(requestId) {
    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/requests/${requestId}/reject`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Rejection failed", "error");
            return;
        }

        showToast("Join request rejected.", "info");
        loadOwnerRequests(state.currentClassroom);
    } catch (err) {
        showToast("Error rejecting request", "error");
    }
}

async function loadOwnerMembers(classroomId) {
    const list = document.getElementById("owner-members-list");
    list.innerHTML = `<p class="text-xs text-slate-400">Loading members...</p>`;

    try {
        const res = await fetch(`/api/classrooms/${classroomId}/members`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        const members = data.members || [];

        document.getElementById("owner-members-badge").innerText = members.length;

        list.innerHTML = members.map(m => {
            const isOwner = m.role === "owner";
            return `
                <div class="bg-slate-50 border border-slate-200/80 rounded-xl p-3.5 flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <div class="w-8 h-8 rounded-full ${isOwner ? 'bg-amber-500' : 'bg-brand-600'} text-white font-bold text-xs flex items-center justify-center">
                            ${m.full_name.charAt(0).toUpperCase()}
                        </div>
                        <div>
                            <div class="flex items-center space-x-2">
                                <span class="text-xs font-bold text-slate-900">${escapeHtml(m.full_name)}</span>
                                <span class="text-[10px] font-semibold px-2 py-0.2 rounded border ${isOwner ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-slate-100 text-slate-600 border-slate-200'}">
                                    ${isOwner ? 'Owner' : 'Member'}
                                </span>
                            </div>
                            <span class="text-[11px] text-slate-500">${escapeHtml(m.college_email)} • Roll: ${escapeHtml(m.roll_number)}</span>
                        </div>
                    </div>

                    ${!isOwner ? `
                        <button onclick="removeMember('${m.user_id}', '${escapeHtml(m.full_name)}')" class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-rose-50 text-rose-700 hover:bg-rose-100 border border-rose-200 flex items-center gap-1">
                            <i data-lucide="user-minus" class="w-3.5 h-3.5"></i>
                            <span>Remove</span>
                        </button>
                    ` : '<span class="text-xs text-slate-400 italic">Primary Owner</span>'}
                </div>
            `;
        }).join("");

        refreshIcons();
    } catch (err) {
        list.innerHTML = `<p class="text-xs text-rose-500">Failed to load members</p>`;
    }
}

async function removeMember(userId, name) {
    if (!confirm(`Are you sure you want to remove ${name} from this classroom? They will lose access to all posts and assignments immediately.`)) {
        return;
    }

    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/members/${userId}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to remove member", "error");
            return;
        }

        showToast(`${name} was removed from the classroom.`, "info");
        loadOwnerMembers(state.currentClassroom);
    } catch (err) {
        showToast("Error removing member", "error");
    }
}

// ============================================================================
// CLASSROOM TIMELINE, POSTS & ASSIGNMENTS
// ============================================================================
async function openClassroom(classroomId) {
    state.currentClassroom = classroomId;
    navigateTo("screen-timeline");

    try {
        const res = await fetch(`/api/classrooms/${classroomId}`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });

        if (res.status === 403) {
            showToast("Access Denied: You must be an approved member to view this classroom", "error");
            navigateTo("screen-classrooms");
            return;
        }

        const data = await res.json();
        const cls = data.classroom;
        const isOwner = data.is_owner;

        document.getElementById("timeline-cls-name").innerText = cls.name;
        document.getElementById("timeline-cls-desc").innerText = cls.description || "Classroom Discussion & Schedule";

        const roleBadge = document.getElementById("timeline-role-badge");
        if (isOwner) {
            roleBadge.className = "text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200";
            roleBadge.innerText = "Owner";
            document.getElementById("owner-dashboard-btn").classList.remove("hidden");
        } else {
            roleBadge.className = "text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200";
            roleBadge.innerText = "Member";
            document.getElementById("owner-dashboard-btn").classList.add("hidden");
        }

        // Load timeline posts, assignments, and directory
        loadTimelinePosts(classroomId);
        loadTimelineAssignments(classroomId);
        loadTimelineDirectory(classroomId);
    } catch (err) {
        showToast("Error opening classroom", "error");
    }
}

function openTimelineFromOwner() {
    openClassroom(state.currentClassroom);
}

function openOwnerDashboardFromTimeline() {
    openOwnerDashboard(state.currentClassroom);
}

async function loadTimelinePosts(classroomId) {
    const list = document.getElementById("timeline-posts-list");
    list.innerHTML = `<p class="text-xs text-slate-400">Loading announcements...</p>`;

    try {
        const res = await fetch(`/api/classrooms/${classroomId}/posts`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        if (res.status === 403) {
            list.innerHTML = `<div class="p-6 bg-rose-50 text-rose-700 text-xs rounded-xl font-semibold">Access Denied: Only approved members can view posts.</div>`;
            return;
        }

        const data = await res.json();
        const posts = data.posts || [];

        if (posts.length === 0) {
            list.innerHTML = `
                <div class="bg-white rounded-2xl border border-slate-200/80 p-8 text-center text-slate-400 text-xs">
                    <i data-lucide="message-square" class="w-8 h-8 mx-auto mb-2 text-slate-300"></i>
                    No announcements posted yet. Start a discussion or share class news above.
                </div>
            `;
            refreshIcons();
            return;
        }

        list.innerHTML = posts.map(p => `
            <div class="bg-white rounded-2xl border border-slate-200/80 p-5 shadow-sm space-y-3">
                <div class="flex items-center justify-between pb-2 border-b border-slate-100">
                    <div class="flex items-center space-x-2">
                        <span class="text-xs font-bold text-slate-900">${escapeHtml(p.author_name)}</span>
                        ${p.is_faculty_verified ? `
                            <span class="text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded-full flex items-center gap-1">
                                <i data-lucide="badge-check" class="w-3 h-3 text-emerald-600"></i>
                                Faculty Verified
                            </span>
                        ` : ''}
                    </div>
                    <span class="text-[11px] text-slate-400">${new Date(p.created_at).toLocaleDateString()}</span>
                </div>
                <div>
                    <h4 class="text-sm font-bold text-slate-900 mb-1">${escapeHtml(p.title)}</h4>
                    <p class="text-xs text-slate-700 whitespace-pre-wrap leading-relaxed">${escapeHtml(p.content)}</p>
                </div>
            </div>
        `).join("");

        refreshIcons();
    } catch (err) {
        list.innerHTML = `<p class="text-xs text-rose-500">Failed to load posts</p>`;
    }
}

async function loadTimelineAssignments(classroomId) {
    const list = document.getElementById("timeline-assignments-list");
    list.innerHTML = `<p class="text-slate-400">Loading assignments...</p>`;

    try {
        const res = await fetch(`/api/classrooms/${classroomId}/assignments`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        const assignments = data.assignments || [];

        document.getElementById("timeline-assign-count").innerText = assignments.length;

        if (assignments.length === 0) {
            list.innerHTML = `<p class="text-slate-400 italic">No shared assignments.</p>`;
            return;
        }

        list.innerHTML = assignments.map(a => `
            <div class="bg-slate-50 border border-slate-200/80 rounded-xl p-3 space-y-1">
                <div class="flex items-center justify-between">
                    <span class="text-[10px] font-bold uppercase tracking-wider text-brand-600">${escapeHtml(a.subject)}</span>
                    <span class="text-[10px] text-rose-600 font-semibold">Due: ${new Date(a.due_date).toLocaleDateString()}</span>
                </div>
                <h5 class="text-xs font-bold text-slate-800">${escapeHtml(a.title)}</h5>
                ${a.description ? `<p class="text-[11px] text-slate-500">${escapeHtml(a.description)}</p>` : ''}
            </div>
        `).join("");
    } catch (err) {
        list.innerHTML = `<p class="text-rose-500">Failed to load assignments</p>`;
    }
}

async function loadTimelineDirectory(classroomId) {
    const list = document.getElementById("timeline-directory-list");
    try {
        const res = await fetch(`/api/classrooms/${classroomId}/members`, {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        const members = data.members || [];

        document.getElementById("timeline-member-count").innerText = members.length;

        list.innerHTML = members.map(m => `
            <div class="flex items-center justify-between py-1 border-b border-slate-50 last:border-none">
                <span class="text-slate-700 font-medium">${escapeHtml(m.full_name)}</span>
                <span class="text-[10px] text-slate-400 font-mono">${escapeHtml(m.roll_number)}</span>
            </div>
        `).join("");
    } catch (err) {
        list.innerHTML = `<p class="text-slate-400 italic">Directory unavailable</p>`;
    }
}

function openNewPostModal() {
    document.getElementById("post-title").value = "";
    document.getElementById("post-content").value = "";
    document.getElementById("post-is-faculty").checked = false;
    openModal("modal-new-post");
}

async function handleCreatePost(e) {
    e.preventDefault();
    const title = document.getElementById("post-title").value.trim();
    const content = document.getElementById("post-content").value.trim();
    const isFaculty = document.getElementById("post-is-faculty").checked;

    closeModal("modal-new-post");

    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/posts`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({
                title,
                content,
                is_faculty_verified: isFaculty
            })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to publish post", "error");
            return;
        }

        showToast("Announcement published to classroom timeline", "success");
        loadTimelinePosts(state.currentClassroom);
    } catch (err) {
        showToast("Error publishing announcement", "error");
    }
}

function openNewAssignmentModal() {
    document.getElementById("assign-subject").value = "";
    document.getElementById("assign-title").value = "";
    document.getElementById("assign-due").value = "";
    document.getElementById("assign-desc").value = "";
    openModal("modal-new-assignment");
}

async function handleCreateAssignment(e) {
    e.preventDefault();
    const subject = document.getElementById("assign-subject").value.trim();
    const title = document.getElementById("assign-title").value.trim();
    const due = document.getElementById("assign-due").value;
    const desc = document.getElementById("assign-desc").value.trim();

    closeModal("modal-new-assignment");

    try {
        const res = await fetch(`/api/classrooms/${state.currentClassroom}/assignments`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({
                subject,
                title,
                due_date: new Date(due).toISOString(),
                description: desc
            })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Failed to create assignment", "error");
            return;
        }

        showToast("Assignment shared and automatically synced to all member task lists!", "success");
        loadTimelineAssignments(state.currentClassroom);
    } catch (err) {
        showToast("Error creating assignment", "error");
    }
}

// ============================================================================
// MY TASKS & REMINDERS
// ============================================================================
async function loadTasks() {
    const list = document.getElementById("user-tasks-list");
    list.innerHTML = `<div class="p-8 text-center text-slate-400 text-xs">Loading tasks...</div>`;

    try {
        const res = await fetch("/api/tasks", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        state.tasks = data.tasks || [];

        renderTasksList(state.tasks);
    } catch (err) {
        showToast("Error loading tasks", "error");
    }
}

function renderTasksList(tasks) {
    const list = document.getElementById("user-tasks-list");

    if (tasks.length === 0) {
        list.innerHTML = `
            <div class="bg-white rounded-2xl border border-slate-200/80 p-12 text-center text-slate-400 text-xs space-y-2">
                <i data-lucide="check-circle-2" class="w-8 h-8 mx-auto text-emerald-500"></i>
                <h4 class="font-bold text-slate-700">All caught up!</h4>
                <p>When assignments are shared in your approved classrooms, they will automatically appear here.</p>
            </div>
        `;
        refreshIcons();
        return;
    }

    list.innerHTML = tasks.map(t => {
        const isDone = t.status === "completed";
        const dueDate = new Date(t.due_date);
        const formattedDue = dueDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

        return `
            <div class="bg-white rounded-2xl border border-slate-200/80 p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${isDone ? 'opacity-70 bg-slate-50' : ''}">
                <div class="flex items-start space-x-3">
                    <button onclick="toggleTaskStatus('${t.id}', '${isDone ? 'pending' : 'completed'}')" class="mt-0.5 p-1 rounded-lg border ${isDone ? 'bg-emerald-500 border-emerald-500 text-white' : 'border-slate-300 text-transparent hover:border-brand-500'} transition">
                        <i data-lucide="check" class="w-4 h-4"></i>
                    </button>
                    <div>
                        <div class="flex items-center space-x-2">
                            <span class="text-xs font-bold ${isDone ? 'line-through text-slate-500' : 'text-slate-900'}">${escapeHtml(t.title)}</span>
                            <span class="text-[10px] font-semibold bg-brand-50 text-brand-700 px-2 py-0.5 rounded border border-brand-200">${escapeHtml(t.classroom_name)}</span>
                        </div>
                        <span class="text-[11px] text-slate-500 flex items-center gap-1 mt-0.5">
                            <i data-lucide="calendar" class="w-3 h-3 text-slate-400"></i> Due: ${formattedDue}
                        </span>
                    </div>
                </div>

                <div class="flex items-center space-x-2">
                    <select onchange="updateTaskStatusDirect('${t.id}', this.value)" class="text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white font-medium">
                        <option value="pending" ${t.status === 'pending' ? 'selected' : ''}>Pending</option>
                        <option value="in_progress" ${t.status === 'in_progress' ? 'selected' : ''}>In Progress</option>
                        <option value="completed" ${t.status === 'completed' ? 'selected' : ''}>Completed</option>
                    </select>
                </div>
            </div>
        `;
    }).join("");

    refreshIcons();
}

function filterTasks(status) {
    document.querySelectorAll(".task-filter-btn").forEach(btn => {
        btn.classList.remove("active", "bg-brand-50", "text-brand-700", "border", "border-brand-200");
        btn.classList.add("bg-slate-100", "text-slate-600");
    });
    event.target.classList.add("active", "bg-brand-50", "text-brand-700", "border", "border-brand-200");
    event.target.classList.remove("bg-slate-100", "text-slate-600");

    if (status === "all") {
        renderTasksList(state.tasks);
    } else {
        const filtered = state.tasks.filter(t => t.status === status);
        renderTasksList(filtered);
    }
}

async function toggleTaskStatus(taskId, nextStatus) {
    await updateTaskStatusDirect(taskId, nextStatus);
}

async function updateTaskStatusDirect(taskId, nextStatus) {
    try {
        const res = await fetch(`/api/tasks/${taskId}`, {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${state.token}`
            },
            body: JSON.stringify({ status: nextStatus })
        });
        if (!res.ok) {
            showToast("Failed to update task", "error");
            return;
        }
        loadTasks();
    } catch (err) {
        showToast("Error updating task", "error");
    }
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================
async function fetchNotifications() {
    if (!state.token) return;

    try {
        const res = await fetch("/api/notifications", {
            headers: { "Authorization": `Bearer ${state.token}` }
        });
        const data = await res.json();
        state.notifications = data.notifications || [];

        const unread = state.notifications.filter(n => !n.is_read);
        const badge = document.getElementById("notif-badge");
        const countText = document.getElementById("notif-count-text");

        if (unread.length > 0) {
            badge.classList.remove("hidden");
            countText.innerText = `${unread.length} unread`;
        } else {
            badge.classList.add("hidden");
            countText.innerText = `0 unread`;
        }

        const list = document.getElementById("notif-list");
        if (state.notifications.length === 0) {
            list.innerHTML = `<p class="text-slate-400 text-center py-4">No notifications yet.</p>`;
            return;
        }

        list.innerHTML = state.notifications.map(n => `
            <div class="p-2.5 rounded-lg border border-slate-100 ${n.is_read ? 'bg-white' : 'bg-indigo-50/60 font-semibold'} space-y-1 cursor-pointer" onclick="markNotificationRead('${n.id}')">
                <div class="flex items-center justify-between">
                    <span class="text-slate-900">${escapeHtml(n.title)}</span>
                    <span class="text-[10px] text-slate-400">${new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
                <p class="text-slate-600 font-normal leading-tight">${escapeHtml(n.message)}</p>
            </div>
        `).join("");
    } catch (err) {
        // Silent fail
    }
}

function toggleNotificationsPanel() {
    const dropdown = document.getElementById("notif-dropdown");
    dropdown.classList.toggle("hidden");
    if (!dropdown.classList.contains("hidden")) {
        fetchNotifications();
    }
}

async function markNotificationRead(notifId) {
    await fetch(`/api/notifications/${notifId}/read`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}` }
    });
    fetchNotifications();
}

// ============================================================================
// PROFILE
// ============================================================================
function renderProfile() {
    if (!state.user) return;
    document.getElementById("profile-avatar").innerText = state.user.full_name.charAt(0).toUpperCase();
    document.getElementById("profile-full-name").innerText = state.user.full_name;
    document.getElementById("profile-field-name").innerText = state.user.full_name;
    document.getElementById("profile-field-email").innerText = state.user.college_email;
    document.getElementById("profile-field-roll").innerText = state.user.roll_number;
}

// ============================================================================
// MODAL HELPERS & UTILS
// ============================================================================
function openModal(modalId) {
    const m = document.getElementById(modalId);
    if (m) m.classList.remove("hidden");
    refreshIcons();
}

function closeModal(modalId) {
    const m = document.getElementById(modalId);
    if (m) m.classList.add("hidden");
}

function escapeHtml(text) {
    if (!text) return "";
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// ============================================================================
// PWA SERVICE WORKER REGISTRATION
// ============================================================================
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then((reg) => {
            console.log('[CampusMate] PWA ServiceWorker active:', reg.scope);
        }).catch((err) => {
            console.warn('[CampusMate] ServiceWorker registration skipped:', err);
        });
    });
}

