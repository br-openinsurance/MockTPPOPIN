function escape(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function pretty(o) {
  return escape(JSON.stringify(o, null, 2));
}

function formatTimestamp(ts) {
  if (!ts) return '';
  const date = new Date(ts * 1000); // Convert Unix timestamp to milliseconds
  return date.toLocaleString('pt-BR', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

document.addEventListener("DOMContentLoaded", () => {
    const FLOW_ID = document.body.dataset.flowId;

    const $list     = document.getElementById('logs-list');
    const $detail   = document.getElementById('logs-detail');
    const $status   = document.getElementById('logs-status');
    const $reload   = document.getElementById('logs-reload');
    const $copy     = document.getElementById('logs-copy');
    const $copyAll  = document.getElementById('logs-copy-all');

    if (!$list || !$detail) return;

    let logs = [];
    let idx  = -1;
    function renderList() {
      if (!logs.length) {
        $list.innerHTML = '<div class="p-3 text-sm text-gray-500">No logs.</div>';
        return;
      }
      $list.innerHTML = logs.map((it, i) => `
        <button data-i="${i}" class="w-full text-left px-3 py-2 border-b border-gray-200 hover:bg-gray-50 ${i===idx?'bg-green-50 border-l-4 border-green-500':''}">
          <div class="text-xs text-gray-500">${escape(formatTimestamp(it.created_at))}</div>
          <div class="text-sm truncate">${escape(it.message || '(no message)')}</div>
        </button>
      `).join('');
    }

    function select(i) {
      idx = i;
      renderList();
      const it = logs[i];
      if (!it) { $detail.textContent = 'Selecione um log.'; return; }
      $detail.innerHTML = `<pre class="whitespace-pre-wrap">${pretty(it)}</pre>`;
    }

    async function load() {
      if ($status) $status.textContent = 'Carregando…';
      if ($reload) {
        $reload.textContent = 'Carregando...';
        $reload.disabled = true;
        $reload.classList.add('bg-blue-200');
      }
      try {
        const res  = await fetch(`/flows/${encodeURIComponent(FLOW_ID)}/logs`, { credentials: 'same-origin' });
        logs = await res.json().catch(() => []);
        renderList();
        select(0);
        if ($status) $status.textContent = `Carregados ${logs.length}`;
      } catch {
        logs = [];
        renderList();
        $detail.textContent = 'Falha ao carregar.';
        if ($status) $status.textContent = 'Erro';
      } finally {
        if ($reload) {
          $reload.textContent = 'Carregado!';
          setTimeout(() => {
            $reload.textContent = 'Carregar Logs';
            $reload.disabled = false;
            $reload.classList.remove('bg-blue-200');
          }, 1500);
        }
      }
    }

    $list.addEventListener('click', e => {
      const b = e.target.closest('button[data-i]');
      if (b) select(Number(b.dataset.i));
    });
    $reload?.addEventListener('click', load);

    // Automatically load logs on page load
    load();
    $copy?.addEventListener('click', async () => {
      if (idx < 0) return;
      const originalText = $copy.textContent;
      $copy.textContent = 'Copiado!';
      $copy.classList.add('bg-green-200');
      await navigator.clipboard.writeText(JSON.stringify(logs[idx], null, 2));
      setTimeout(() => {
        $copy.textContent = originalText;
        $copy.classList.remove('bg-green-200');
      }, 1500);
    });
    $copyAll?.addEventListener('click', async () => {
      if (!logs.length) return;
      const originalText = $copyAll.textContent;
      $copyAll.textContent = 'Copiado!';
      $copyAll.classList.add('bg-green-200');
      await navigator.clipboard.writeText(JSON.stringify(logs, null, 2));
      setTimeout(() => {
        $copyAll.textContent = originalText;
        $copyAll.classList.remove('bg-green-200');
      }, 1500);
    });
});
