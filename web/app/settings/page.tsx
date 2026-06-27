'use client';

import { useEffect, useState } from 'react';
import Nav from '../../components/Nav';
import { api } from '../../lib/api';

export default function SettingsPage() {
  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get('/admin/settings/panel')
      .then(res => {
        setConfig(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.put('/admin/settings/panel', config);
      alert('تنظیمات با موفقیت ذخیره شد');
    } catch (err) {
      alert('خطا در ذخیره تنظیمات');
    }
    setSaving(false);
  };

  if (loading) return <div className="p-8 text-white">Loading...</div>;

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950">
      <Nav />
      <main className="flex-1 p-8 text-white" dir="rtl">
        <div className="mx-auto max-w-3xl">
          <h1 className="mb-8 text-3xl font-bold">⚙️ تنظیمات سیستم (System Settings)</h1>
          <form onSubmit={handleSave} className="space-y-6 rounded-lg border border-zinc-800 bg-zinc-900/50 p-6">
            
            {/* Panel Provider Selection */}
            <div>
              <label className="block text-sm font-medium text-zinc-300">پنل فعال (Active Panel)</label>
              <select 
                value={config?.provider} 
                onChange={e => setConfig({...config, provider: e.target.value})}
                className="mt-1 block w-full rounded-md border border-zinc-700 bg-zinc-800 p-2 text-white outline-none"
              >
                <option value="rebecca">Rebecca / Marzban</option>
                <option value="remnawave">Remnawave</option>
              </select>
            </div>

            {/* Rebecca Settings */}
            {config?.provider === 'rebecca' && (
              <div className="space-y-4 rounded-md border border-zinc-700 p-4">
                <h3 className="font-semibold text-blue-400">تنظیمات Rebecca</h3>
                <div>
                  <label className="block text-sm text-zinc-400">آدرس پنل (Base URL)</label>
                  <input type="text" value={config.rebecca?.baseUrl || ''} onChange={e => setConfig({...config, rebecca: {...config.rebecca, baseUrl: e.target.value}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" />
                </div>
                <div>
                  <label className="block text-sm text-zinc-400">نام کاربری ادمین (Admin Username)</label>
                  <input type="text" value={config.rebecca?.username || ''} onChange={e => setConfig({...config, rebecca: {...config.rebecca, username: e.target.value}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" />
                </div>
                <div>
                  <label className="block text-sm text-zinc-400">رمز عبور ادمین (Admin Password)</label>
                  <input type="password" value={config.rebecca?.password || ''} onChange={e => setConfig({...config, rebecca: {...config.rebecca, password: e.target.value}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" />
                </div>
              </div>
            )}

            {/* Remnawave Settings */}
            {config?.provider === 'remnawave' && (
              <div className="space-y-4 rounded-md border border-zinc-700 p-4">
                <h3 className="font-semibold text-purple-400">تنظیمات Remnawave</h3>
                <div>
                  <label className="block text-sm text-zinc-400">آدرس پنل (Base URL)</label>
                  <input type="text" value={config.remnawave?.baseUrl || ''} onChange={e => setConfig({...config, remnawave: {...config.remnawave, baseUrl: e.target.value}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" />
                </div>
                <div>
                  <label className="block text-sm text-zinc-400">توکن API (Token)</label>
                  <input type="password" value={config.remnawave?.token || ''} onChange={e => setConfig({...config, remnawave: {...config.remnawave, token: e.target.value}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" />
                </div>
                <div>
                  <label className="block text-sm text-zinc-400">شناسه‌های اسکواد (Squad UUIDs - Comma Separated)</label>
                  <input type="text" value={config.remnawave?.squadUuids?.join(',') || ''} onChange={e => setConfig({...config, remnawave: {...config.remnawave, squadUuids: e.target.value.split(',').map(s => s.trim()).filter(Boolean)}})} className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 p-2" dir="ltr" placeholder="uuid1,uuid2" />
                </div>
              </div>
            )}

            <button disabled={saving} type="submit" className="w-full rounded-md bg-emerald-600 py-2 font-semibold text-white transition hover:bg-emerald-500">
              {saving ? 'در حال ذخیره...' : 'ذخیره تنظیمات'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}
