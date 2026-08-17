// 日期时间选择器：自绘轻量日历面板（无外部依赖）
// 月历 + 时分 + 快捷操作，供时间范围查询条件等场景使用。
// 用法：DtPicker.bind(input)，选中值写入 input.value（yyyy-MM-dd HH:mm），
//       毫秒时间戳存于 input.dataset.ts；面板样式依赖 style.css 中 .dtp-* / .dtp-day 等类。
'use strict';

const DtPicker = (() => {
    const pad = (n) => String(n).padStart(2, '0');
    const fmt = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const WEEK = ['一', '二', '三', '四', '五', '六', '日'];
    let pop = null;    // 弹出面板
    let anchor = null; // 正在编辑的输入框
    let view = null;   // { y, m } 日历当前展示月
    let sel = null;    // 当前选中的时间

    function build() {
        pop = document.createElement('div');
        pop.className = 'dtp hide';
        pop.innerHTML = `
            <div class="dtp-head">
                <button type="button" class="dtp-nav" data-nav="-1">‹</button>
                <span class="dtp-title" id="dtp-title"></span>
                <button type="button" class="dtp-nav" data-nav="1">›</button>
            </div>
            <div class="dtp-week">${WEEK.map((w) => `<span>${w}</span>`).join('')}</div>
            <div class="dtp-grid" id="dtp-grid"></div>
            <div class="dtp-time">
                <span>时间</span>
                <input id="dtp-hh" type="number" min="0" max="23"> :
                <input id="dtp-mm" type="number" min="0" max="59">
                <button type="button" class="btn sm ghost" id="dtp-now">此刻</button>
            </div>
            <div class="dtp-actions">
                <button type="button" class="btn sm" id="dtp-clear">清空</button>
                <span class="dtp-right">
                    <button type="button" class="btn sm" id="dtp-cancel">取消</button>
                    <button type="button" class="btn sm primary" id="dtp-ok">确定</button>
                </span>
            </div>`;
        document.body.appendChild(pop);

        const hh = pop.querySelector('#dtp-hh');
        const mm = pop.querySelector('#dtp-mm');
        const clamp = (v, max) => Math.max(0, Math.min(max, parseInt(v) || 0));

        pop.querySelector('[data-nav="-1"]').onclick = () => shiftMonth(-1);
        pop.querySelector('[data-nav="1"]').onclick = () => shiftMonth(1);
        pop.querySelector('#dtp-grid').addEventListener('click', (e) => {
            const b = e.target.closest('.dtp-day');
            if (!b) return;
            const d = new Date(+b.dataset.ts);
            d.setHours(sel.getHours(), sel.getMinutes(), 0, 0);
            sel = d;
            view = { y: d.getFullYear(), m: d.getMonth() };
            renderPanel();
        });
        hh.addEventListener('change', () => { sel.setHours(clamp(hh.value, 23)); renderTime(); });
        mm.addEventListener('change', () => { sel.setMinutes(clamp(mm.value, 59)); renderTime(); });
        pop.querySelector('#dtp-now').onclick = () => {
            sel = new Date();
            view = { y: sel.getFullYear(), m: sel.getMonth() };
            renderPanel();
        };
        pop.querySelector('#dtp-clear').onclick = () => {
            anchor.value = '';
            delete anchor.dataset.ts;
            close();
        };
        pop.querySelector('#dtp-cancel').onclick = close;
        pop.querySelector('#dtp-ok').onclick = () => {
            anchor.value = fmt(sel);
            anchor.dataset.ts = sel.getTime();
            close();
        };

        document.addEventListener('mousedown', (e) => {
            if (!pop || pop.classList.contains('hide')) return;
            if (e.target === anchor || pop.contains(e.target)) return;
            close();
        });
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
        window.addEventListener('scroll', close, true); // 滚动时收起，避免面板错位
        window.addEventListener('resize', close);
        window.addEventListener('hashchange', close);
    }

    function shiftMonth(dm) {
        const d = new Date(view.y, view.m + dm, 1);
        view = { y: d.getFullYear(), m: d.getMonth() };
        renderPanel();
    }

    function renderPanel() {
        pop.querySelector('#dtp-title').textContent = `${view.y} 年 ${view.m + 1} 月`;
        const first = new Date(view.y, view.m, 1);
        const start = new Date(view.y, view.m, 1 - (first.getDay() + 6) % 7); // 周一起始，固定铺满 6 行
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        let html = '';
        for (let i = 0; i < 42; i++) {
            const d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
            const cls = [];
            if (d.getMonth() !== view.m) cls.push('muted');
            if (+d === +today) cls.push('today');
            if (sel && d.getFullYear() === sel.getFullYear() &&
                d.getMonth() === sel.getMonth() && d.getDate() === sel.getDate()) cls.push('sel');
            html += `<button type="button" class="dtp-day${cls.length ? ' ' + cls.join(' ') : ''}" data-ts="${d.getTime()}">${d.getDate()}</button>`;
        }
        pop.querySelector('#dtp-grid').innerHTML = html;
        renderTime();
    }

    function renderTime() {
        pop.querySelector('#dtp-hh').value = pad(sel.getHours());
        pop.querySelector('#dtp-mm').value = pad(sel.getMinutes());
    }

    function position() {
        const r = anchor.getBoundingClientRect();
        const w = pop.offsetWidth, h = pop.offsetHeight;
        let left = r.left, top = r.bottom + 6;
        if (top + h > innerHeight - 8) top = Math.max(8, r.top - h - 6); // 下方放不下则向上弹出
        if (left + w > innerWidth - 8) left = Math.max(8, innerWidth - w - 8);
        pop.style.left = left + 'px';
        pop.style.top = top + 'px';
    }

    function open(input) {
        if (!pop) build();
        anchor = input;
        sel = input.dataset.ts ? new Date(+input.dataset.ts) : new Date();
        view = { y: sel.getFullYear(), m: sel.getMonth() };
        renderPanel();
        pop.classList.remove('hide');
        position();
    }

    function close() {
        if (pop) pop.classList.add('hide');
        anchor = null;
    }

    return {
        bind(input) {
            input.addEventListener('click', () => {
                if (anchor === input && pop && !pop.classList.contains('hide')) close();
                else open(input);
            });
        }
    };
})();
