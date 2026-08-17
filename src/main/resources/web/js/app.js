// 蜜罐监控中心 SPA：路由、仪表盘图表、明细查询表格、用户管理
'use strict';

let CURRENT_USER = null;
const charts = [];

// ============================ 工具 ============================

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtTs = (s) => (s ? String(s).replace('T', ' ').replace(/\.\d+$/, '') : '-');

function toast(msg) {
    let el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        el.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);' +
            'background:#152238;border:1px solid var(--border);color:var(--text);padding:10px 22px;' +
            'border-radius:8px;z-index:200;display:none;box-shadow:0 10px 30px rgba(0,0,0,.4)';
        document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.display = 'block';
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.style.display = 'none'; }, 2200);
}

function showModal(id, show) {
    document.getElementById(id).classList.toggle('hide', !show);
}

function dateRangeFilter() {
    const field = (id, ph) =>
        `<span class="dt-field"><input id="${id}" class="dt-input" readonly placeholder="${ph}"><span class="dt-icon">🗓</span></span>`;
    return {
        html: field('f-start', '开始时间') + ' ~ ' + field('f-end', '结束时间'),
        init() {
            DtPicker.bind(document.getElementById('f-start'));
            DtPicker.bind(document.getElementById('f-end'));
        },
        params() {
            const p = {};
            const s = document.getElementById('f-start')?.dataset.ts;
            const e = document.getElementById('f-end')?.dataset.ts;
            if (s) p.start = +s;
            if (e) p.end = +e + 59999; // 含结束时间的当分钟
            return p;
        }
    };
}

// ============================ 启动 ============================

document.addEventListener('DOMContentLoaded', init);

async function init() {
    let me;
    try {
        me = await API.get('/api/me');
    } catch (e) {
        return; // 401 已由 API 封装跳转登录页
    }
    CURRENT_USER = me.user;
    document.getElementById('nav-user').textContent =
        CURRENT_USER.username + '（' + (CURRENT_USER.role === 'admin' ? '管理员' : '只读') + '）';
    if (CURRENT_USER.role !== 'admin') {
        document.querySelectorAll('.admin-only').forEach((el) => el.style.display = 'none');
    }
    document.getElementById('btn-logout').onclick = async () => {
        try { await API.post('/api/logout'); } catch (e) { /* 忽略 */ }
        location.href = '/login.html';
    };
    document.getElementById('btn-pwd').onclick = () => openPwdModal(false);
    document.querySelectorAll('.sidebar nav a').forEach((a) =>
        a.addEventListener('click', () => setTimeout(render, 0)));
    window.addEventListener('hashchange', render);
    window.addEventListener('resize', () => charts.forEach((c) => c.resize()));

    if (CURRENT_USER.mustChange) {
        render(); // 先渲染背景，弹窗强制置顶
        openPwdModal(true);
    } else {
        render();
    }
}

const TITLES = {
    dashboard: '攻击总览', sessions: '会话记录', auth: '登录尝试',
    commands: '命令记录', downloads: '恶意下载', locks: 'IP 锁定', users: '用户管理'
};

function render() {
    const page = (location.hash.replace('#', '') || 'dashboard');
    if (!(page in TITLES) || (page === 'users' && CURRENT_USER.role !== 'admin')) {
        location.hash = '#dashboard';
        return;
    }
    if (CURRENT_USER.mustChange) {
        openPwdModal(true); // 强制改密期间锁定导航
        return;
    }
    document.querySelectorAll('.sidebar nav a').forEach((a) =>
        a.classList.toggle('active', a.getAttribute('href') === '#' + page));
    document.getElementById('page-title').textContent = TITLES[page];
    charts.length = 0;
    const el = document.getElementById('content');
    el.innerHTML = '<div class="loading">加载中…</div>';
    VIEWS[page](el);
}

// ============================ 攻击总览 ============================

async function viewDashboard(el) {
    el.innerHTML = `
        <div class="cards">
            <div class="card"><div class="label">会话总数</div><div class="value c-cyan" id="c-sessions">-</div><div class="sub">今日 <b id="c-ts">-</b></div></div>
            <div class="card"><div class="label">登录尝试</div><div class="value c-orange" id="c-auth">-</div><div class="sub">今日 <b id="c-ta">-</b></div></div>
            <div class="card"><div class="label">命令执行</div><div class="value c-purple" id="c-cmds">-</div><div class="sub">今日 <b id="c-tc">-</b></div></div>
            <div class="card"><div class="label">恶意下载</div><div class="value c-red" id="c-dl">-</div><div class="sub">今日 <b id="c-td">-</b></div></div>
            <div class="card"><div class="label">攻击源 IP</div><div class="value c-green" id="c-ips">-</div><div class="sub">当前锁定 <b id="c-locks">-</b></div></div>
        </div>
        <div class="panel"><h3>近 14 天攻击趋势</h3><div id="chart-trend" class="chart"></div></div>
        <div class="grid-2">
            <div class="panel"><h3>协议分布（会话）</h3><div id="chart-proto" class="chart"></div></div>
            <div class="panel"><h3>攻击源 IP TOP10</h3><div id="chart-ips" class="chart"></div></div>
        </div>
        <div class="grid-2">
            <div class="panel"><h3>高频爆破用户名 TOP10</h3><div id="chart-users" class="chart"></div></div>
            <div class="panel"><h3>高频尝试口令 TOP10</h3><div id="chart-pwds" class="chart"></div></div>
        </div>`;
    try {
        const [ov, trend, proto, ips, users, pwds] = await Promise.all([
            API.get('/api/stats/overview'),
            API.get('/api/stats/trend?days=14'),
            API.get('/api/stats/protocol'),
            API.get('/api/stats/top-ips?limit=10'),
            API.get('/api/stats/top-usernames?limit=10'),
            API.get('/api/stats/top-passwords?limit=10')
        ]);
        const o = ov.data;
        const set = (id, v) => { document.getElementById(id).textContent = v; };
        set('c-sessions', o.totalSessions); set('c-ts', o.todaySessions);
        set('c-auth', o.totalAuth); set('c-ta', o.todayAuth);
        set('c-cmds', o.totalCommands); set('c-tc', o.todayCommands);
        set('c-dl', o.totalDownloads); set('c-td', o.todayDownloads);
        set('c-ips', o.uniqueIps); set('c-locks', o.activeLocks);
        renderTrend(trend.data);
        renderPie(proto.data);
        barChart('chart-ips', ips.data, '登录尝试次数');
        barChart('chart-users', users.data, '尝试次数');
        barChart('chart-pwds', pwds.data, '尝试次数');
    } catch (e) {
        toast(e.message);
    }
}

function newChart(id) {
    const c = echarts.init(document.getElementById(id));
    charts.push(c);
    return c;
}

const PALETTE = ['#22d3ee', '#34d399', '#fbbf24', '#f87171', '#a78bfa', '#60a5fa'];
const AXIS = {
    axisLine: { lineStyle: { color: '#1e2b45' } },
    axisLabel: { color: '#8aa0bf' },
    splitLine: { lineStyle: { color: 'rgba(30,43,69,.5)' } }
};

function renderTrend(rows) {
    newChart('chart-trend').setOption({
        color: PALETTE,
        tooltip: { trigger: 'axis' },
        legend: { textStyle: { color: '#8aa0bf' } },
        grid: { left: 50, right: 20, top: 40, bottom: 30 },
        xAxis: { type: 'category', data: rows.map((r) => r.day.slice(5)), ...AXIS },
        yAxis: { type: 'value', ...AXIS },
        series: [
            { name: '会话', type: 'line', smooth: true, data: rows.map((r) => r.sessions) },
            { name: '登录尝试', type: 'line', smooth: true, data: rows.map((r) => r.auth) },
            { name: '命令执行', type: 'line', smooth: true, data: rows.map((r) => r.commands) }
        ]
    });
}

function renderPie(rows) {
    newChart('chart-proto').setOption({
        color: PALETTE,
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { bottom: 0, textStyle: { color: '#8aa0bf' } },
        series: [{
            type: 'pie', radius: ['40%', '65%'], center: ['50%', '45%'],
            label: { color: '#8aa0bf' }, data: rows
        }]
    });
}

function barChart(id, rows, name) {
    const sorted = [...rows].reverse();
    newChart(id).setOption({
        color: ['#22d3ee'],
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: 110, right: 40, top: 10, bottom: 25 },
        xAxis: { type: 'value', ...AXIS },
        yAxis: {
            type: 'category', data: sorted.map((r) => r.name),
            axisLabel: { color: '#8aa0bf', width: 95, overflow: 'truncate' },
            axisLine: { lineStyle: { color: '#1e2b45' } }
        },
        series: [{ name, type: 'bar', data: sorted.map((r) => r.value), barMaxWidth: 16 }]
    });
}

// ============================ 明细表格页 ============================

const PROTOCOL_TAG = { ssh: 'cyan', telnet: 'orange', mysql: 'green', postgresql: 'purple', redis: 'red' };

function tableView(cfg) {
    return async function (el) {
        const state = { page: 1, size: 20 };
        el.innerHTML = `
            <div class="filters" id="tv-filters">
                ${cfg.filters.map((f) => f.html).join('')}
                <button class="btn primary" id="tv-search">查询</button>
                <button class="btn" id="tv-reset">重置</button>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr>${cfg.cols.map((c) => `<th>${c.label}</th>`).join('')}</tr></thead>
                    <tbody id="tv-body"></tbody>
                </table>
            </div>
            <div class="pager" id="tv-pager"></div>`;
        cfg.filters.forEach((f) => f.init && f.init()); // 时间选择器等筛选组件的 DOM 绑定
        document.getElementById('tv-search').onclick = () => { state.page = 1; load(); };
        document.getElementById('tv-reset').onclick = () => {
            document.querySelectorAll('#tv-filters input, #tv-filters select').forEach((i) => {
                i.value = '';
                delete i.dataset.ts; // 清除时间选择器暂存的毫秒值
            });
            state.page = 1;
            load();
        };

        async function load() {
            const body = document.getElementById('tv-body');
            const params = new URLSearchParams({ page: state.page, size: state.size });
            cfg.filters.forEach((f) => {
                const p = f.params();
                Object.entries(p).forEach(([k, v]) => {
                    if (v !== '' && v !== null && v !== undefined) params.set(k, v);
                });
            });
            body.innerHTML = `<tr><td colspan="${cfg.cols.length}" class="loading">加载中…</td></tr>`;
            try {
                const r = await API.get(cfg.api + '?' + params);
                const d = r.data;
                body.innerHTML = d.rows.length
                    ? d.rows.map((row) => `<tr>${cfg.cols.map((c) => `<td${c.cls ? ` class="${c.cls}"` : ''}${c.title ? ` title="${esc(row[c.key])}"` : ''}>${c.render ? c.render(row) : esc(row[c.key])}</td>`).join('')}</tr>`).join('')
                    : `<tr><td colspan="${cfg.cols.length}" class="empty-row">暂无数据</td></tr>`;
                document.getElementById('tv-pager').innerHTML = `
                    <span>共 ${d.total} 条</span>
                    <button class="btn sm" id="tv-prev" ${d.page <= 1 ? 'disabled' : ''}>上一页</button>
                    <button class="btn sm" id="tv-next" ${d.page * d.size >= d.total ? 'disabled' : ''}>下一页</button>
                    <span>第 ${d.page} 页 / 共 ${Math.max(1, Math.ceil(d.total / d.size))} 页</span>
                    <span>每页</span>
                    <input id="tv-size" type="number" min="5" max="200" value="${d.size}">
                    <button class="btn sm" id="tv-apply">应用</button>`;
                document.getElementById('tv-prev').onclick = () => { state.page--; load(); };
                document.getElementById('tv-next').onclick = () => { state.page++; load(); };
                document.getElementById('tv-apply').onclick = () => {
                    state.size = Math.max(5, Math.min(200, parseInt(document.getElementById('tv-size').value) || 20));
                    state.page = 1;
                    load();
                };
            } catch (e) {
                body.innerHTML = `<tr><td colspan="${cfg.cols.length}" class="empty-row">${esc(e.message)}</td></tr>`;
            }
        }
        load();
    };
}

const textFilter = (id, label, param, width) => ({
    html: `<input id="${id}" placeholder="${label}" style="width:${width || 150}px">`,
    params() { return { [param]: document.getElementById(id).value.trim() }; }
});
const protoFilter = () => ({
    html: `<select id="f-proto" style="width:130px">
        <option value="">全部协议</option><option>ssh</option><option>telnet</option>
        <option>mysql</option><option>postgresql</option><option>redis</option></select>`,
    params() { return { protocol: document.getElementById('f-proto').value }; }
});
const protoCell = (row) => `<span class="tag ${PROTOCOL_TAG[row.protocol] || 'gray'}">${esc(row.protocol)}</span>`;

// ============================ 用户管理 ============================

function viewUsers(el) {
    el.innerHTML = `
        <div class="filters"><button class="btn primary" id="u-add">＋ 新增用户</button></div>
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th>ID</th><th>用户名</th><th>角色</th><th>状态</th>
                    <th>创建时间</th><th>最近登录</th><th>操作</th>
                </tr></thead>
                <tbody id="u-body"></tbody>
            </table>
        </div>`;
    document.getElementById('u-add').onclick = () => openUserModal();
    loadUsers();

    async function loadUsers() {
        const body = document.getElementById('u-body');
        try {
            const r = await API.get('/api/users');
            body.innerHTML = r.data.map((u) => `
                <tr>
                    <td>${u.id}</td>
                    <td class="mono">${esc(u.username)}${u.mustChange ? ' <span class="tag orange">待改密</span>' : ''}</td>
                    <td>${u.role === 'admin' ? '<span class="tag cyan">管理员</span>' : '<span class="tag gray">只读</span>'}</td>
                    <td>${u.enabled ? '<span class="tag green">启用</span>' : '<span class="tag red">禁用</span>'}</td>
                    <td>${fmtTs(u.createdAt)}</td>
                    <td>${fmtTs(u.lastLoginAt)}</td>
                    <td>
                        <button class="btn sm" data-act="pwd" data-id="${u.id}" data-user="${esc(u.username)}">重置密码</button>
                        <button class="btn sm" data-act="toggle" data-id="${u.id}">${u.enabled ? '禁用' : '启用'}</button>
                        <button class="btn sm danger" data-act="del" data-id="${u.id}">删除</button>
                    </td>
                </tr>`).join('');
            body.querySelectorAll('button[data-act]').forEach((b) => b.onclick = () => act(b));
        } catch (e) {
            body.innerHTML = `<tr><td colspan="7" class="empty-row">${esc(e.message)}</td></tr>`;
        }
    }

    async function act(btn) {
        const id = btn.dataset.id;
        try {
            if (btn.dataset.act === 'pwd') {
                openResetPwdModal(id, btn.dataset.user, loadUsers); // 弹窗异步确认，由回调刷新列表
                return;
            } else if (btn.dataset.act === 'toggle') {
                const enable = btn.textContent === '启用';
                await API.put(`/api/users/${id}/status`, { enabled: enable });
                toast(enable ? '已启用' : '已禁用');
            } else if (btn.dataset.act === 'del') {
                if (!confirm('确认删除该用户？')) return;
                await API.del(`/api/users/${id}`);
                toast('已删除');
            }
            loadUsers();
        } catch (e) {
            toast(e.message);
        }
    }
}

function openUserModal() {
    const mask = document.createElement('div');
    mask.className = 'modal-mask';
    mask.innerHTML = `
        <div class="modal">
            <div class="modal-head">新增用户</div>
            <div class="field"><label>用户名</label><input id="nu-name" placeholder="字母数字_.-，2-32 位"></div>
            <div class="field"><label>初始密码</label><input id="nu-pwd" type="password" placeholder="至少 8 位"></div>
            <div class="field"><label>角色</label>
                <select id="nu-role"><option value="admin">admin（管理员）</option><option value="viewer">viewer（只读）</option></select>
            </div>
            <div class="form-error" id="nu-err"></div>
            <div class="modal-actions">
                <button class="btn" id="nu-cancel">取消</button>
                <button class="btn primary" id="nu-ok">创建</button>
            </div>
        </div>`;
    document.body.appendChild(mask);
    mask.querySelector('#nu-cancel').onclick = () => mask.remove();
    mask.querySelector('#nu-ok').onclick = async () => {
        try {
            await API.post('/api/users', {
                username: mask.querySelector('#nu-name').value.trim(),
                password: mask.querySelector('#nu-pwd').value,
                role: mask.querySelector('#nu-role').value,
                mustChange: true
            });
            mask.remove();
            toast('用户已创建');
            viewUsers(document.getElementById('content'));
        } catch (e) {
            mask.querySelector('#nu-err').textContent = e.message;
        }
    };
}

// ============================ 重置密码弹窗 ============================

function openResetPwdModal(uid, username, onDone) {
    const mask = document.createElement('div');
    mask.className = 'modal-mask';
    mask.innerHTML = `
        <div class="modal">
            <div class="modal-head">重置密码 · ${esc(username)}</div>
            <div class="field">
                <label>新密码</label>
                <div class="pwd-box">
                    <input id="rp-pwd" type="password" autocomplete="new-password" placeholder="至少 8 位">
                    <button type="button" class="pwd-eye" data-for="rp-pwd" title="显示/隐藏密码">👁</button>
                </div>
            </div>
            <div class="field">
                <label>确认新密码</label>
                <div class="pwd-box">
                    <input id="rp-pwd2" type="password" autocomplete="new-password">
                    <button type="button" class="pwd-eye" data-for="rp-pwd2" title="显示/隐藏密码">👁</button>
                </div>
            </div>
            <div class="form-error" id="rp-err"></div>
            <div class="modal-tip">重置后，该用户下次登录将被强制修改此密码</div>
            <div class="modal-actions">
                <button class="btn" id="rp-cancel">取消</button>
                <button class="btn primary" id="rp-ok">确定</button>
            </div>
        </div>`;
    document.body.appendChild(mask);
    const pwd = mask.querySelector('#rp-pwd');
    const pwd2 = mask.querySelector('#rp-pwd2');
    const err = mask.querySelector('#rp-err');
    const closeMask = () => mask.remove();
    mask.querySelectorAll('.pwd-eye').forEach((b) => b.onclick = () => {
        const inp = mask.querySelector('#' + b.dataset.for);
        inp.type = inp.type === 'password' ? 'text' : 'password';
        b.classList.toggle('on');
        inp.focus();
    });
    const submit = async () => {
        if (pwd.value.length < 8) { err.textContent = '新密码长度至少 8 位'; return; }
        if (pwd.value !== pwd2.value) { err.textContent = '两次输入的密码不一致'; return; }
        try {
            await API.put(`/api/users/${uid}/password`, { password: pwd.value, mustChange: true });
            closeMask();
            toast('密码已重置');
            onDone && onDone();
        } catch (e) {
            err.textContent = e.message;
        }
    };
    mask.querySelector('#rp-cancel').onclick = closeMask;
    mask.querySelector('#rp-ok').onclick = submit;
    mask.addEventListener('mousedown', (e) => { if (e.target === mask) closeMask(); });
    mask.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submit();
        else if (e.key === 'Escape') closeMask();
    });
    pwd.focus();
}

// ============================ 修改密码弹窗 ============================

function openPwdModal(forced) {
    showModal('pwd-modal', true);
    document.getElementById('pwd-modal-title').textContent =
        forced ? '首次登录，请修改初始密码' : '修改密码';
    // 后端始终校验原密码，首次登录也需输入初始密码，故原密码字段不再隐藏
    document.getElementById('pwd-cancel').style.display = forced ? 'none' : '';
    document.getElementById('pwd-err').textContent = '';
    document.getElementById('pwd-old').value = '';
    document.getElementById('pwd-new').value = '';
    document.getElementById('pwd-new2').value = '';
    document.getElementById('pwd-cancel').onclick = () => showModal('pwd-modal', false);
    document.getElementById('pwd-ok').onclick = async () => {
        const oldPwd = document.getElementById('pwd-old').value;
        const n1 = document.getElementById('pwd-new').value;
        const n2 = document.getElementById('pwd-new2').value;
        const errEl = document.getElementById('pwd-err');
        if (n1.length < 8) { errEl.textContent = '新密码长度至少 8 位'; return; }
        if (n1 !== n2) { errEl.textContent = '两次输入的新密码不一致'; return; }
        try {
            await API.put('/api/password', { oldPassword: oldPwd, newPassword: n1 });
            CURRENT_USER.mustChange = false;
            showModal('pwd-modal', false);
            toast('密码修改成功');
            location.reload(); // 整页刷新重拉 /api/me，确保改密后状态与服务端一致
        } catch (e) {
            errEl.textContent = e.message;
        }
    };
}

// ============================ 视图注册 ============================

const VIEWS = {
    dashboard: viewDashboard,

    sessions: tableView({
        api: '/api/sessions',
        filters: [textFilter('f-ip', '来源 IP', 'srcIp'), protoFilter(), dateRangeFilter()],
        cols: [
            { key: 'session_id', label: '会话 ID', cls: 'mono' },
            { key: 'protocol', label: '协议', render: protoCell },
            { key: 'src_ip', label: '来源 IP', cls: 'mono' },
            { key: 'src_port', label: '端口' },
            { key: 'opened_at', label: '开始时间', render: (r) => fmtTs(r.opened_at) },
            { key: 'closed_at', label: '结束时间', render: (r) => r.closed_at ? fmtTs(r.closed_at) : '<span class="tag red">异常断开</span>' },
            { key: 'duration_ms', label: '时长', render: (r) => r.duration_ms == null ? '-' : (r.duration_ms / 1000).toFixed(1) + 's' }
        ]
    }),

    auth: tableView({
        api: '/api/auth-attempts',
        filters: [
            textFilter('f-ip', '来源 IP', 'srcIp'),
            textFilter('f-user', '用户名', 'username'),
            protoFilter(),
            {
                html: '<select id="f-success" style="width:110px"><option value="">全部结果</option><option value="1">放行(蜜罐)</option><option value="0">拒绝</option></select>',
                params() { return { success: document.getElementById('f-success').value }; }
            },
            dateRangeFilter()
        ],
        cols: [
            { key: 'ts', label: '时间', render: (r) => fmtTs(r.ts) },
            { key: 'src_ip', label: '来源 IP', cls: 'mono' },
            { key: 'protocol', label: '协议', render: protoCell },
            { key: 'username', label: '用户名', cls: 'mono' },
            { key: 'password', label: '密码', cls: 'mono cell', title: true },
            { key: 'success', label: '结果', render: (r) => r.success ? '<span class="tag green">放行(蜜罐)</span>' : '<span class="tag red">拒绝</span>' }
        ]
    }),

    commands: tableView({
        api: '/api/commands',
        filters: [
            textFilter('f-ip', '来源 IP', 'srcIp'),
            textFilter('f-user', '用户名', 'username'),
            textFilter('f-kw', '命令关键字', 'keyword', 200),
            dateRangeFilter()
        ],
        cols: [
            { key: 'ts', label: '时间', render: (r) => fmtTs(r.ts) },
            { key: 'src_ip', label: '来源 IP', cls: 'mono' },
            { key: 'username', label: '用户名', cls: 'mono' },
            { key: 'command', label: '命令', cls: 'mono cell', title: true },
            { key: 'session_id', label: '会话', cls: 'mono' }
        ]
    }),

    downloads: tableView({
        api: '/api/downloads',
        filters: [textFilter('f-ip', '来源 IP', 'srcIp'), textFilter('f-kw', 'URL 关键字', 'keyword', 220), dateRangeFilter()],
        cols: [
            { key: 'ts', label: '时间', render: (r) => fmtTs(r.ts) },
            { key: 'src_ip', label: '来源 IP', cls: 'mono' },
            { key: 'username', label: '用户名', cls: 'mono' },
            { key: 'url', label: '恶意 URL', cls: 'mono cell', title: true }
        ]
    }),

    locks: tableView({
        api: '/api/ip-locks',
        filters: [textFilter('f-ip', '来源 IP', 'srcIp')],
        cols: [
            { key: 'ts', label: '锁定时间', render: (r) => fmtTs(r.ts) },
            { key: 'src_ip', label: '来源 IP', cls: 'mono' },
            { key: 'locked_until', label: '解除时间', render: (r) => fmtTs(r.locked_until) },
            { key: 'lockedActive', label: '状态', render: (r) => r.lockedActive ? '<span class="tag red">锁定中</span>' : '<span class="tag gray">已解除</span>' }
        ]
    }),

    users: viewUsers
};
