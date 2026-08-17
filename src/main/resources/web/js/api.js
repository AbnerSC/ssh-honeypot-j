// API 封装：统一 JSON 收发、401 会话失效跳转、错误兜底
'use strict';

const API = {
    async request(method, url, body) {
        let resp;
        try {
            resp = await fetch(url, {
                method,
                headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
                body: body !== undefined ? JSON.stringify(body) : undefined,
                credentials: 'same-origin'
            });
        } catch (e) {
            throw new Error('网络请求失败，请检查服务是否在线');
        }
        if (resp.status === 401 && !url.startsWith('/api/login')) {
            location.href = '/login.html#timeout';
            return new Promise(() => {}); // 已跳转，挂起后续逻辑
        }
        let data = null;
        try { data = await resp.json(); } catch (e) { /* 非 JSON 响应 */ }
        if (data && data.ok === false) {
            throw new Error(data.error || ('请求失败 (HTTP ' + resp.status + ')'));
        }
        if (!resp.ok) {
            throw new Error('请求失败 (HTTP ' + resp.status + ')');
        }
        return data;
    },
    get(url) { return this.request('GET', url); },
    post(url, body) { return this.request('POST', url, body); },
    put(url, body) { return this.request('PUT', url, body); },
    del(url) { return this.request('DELETE', url); }
};
