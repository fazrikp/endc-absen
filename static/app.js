document.addEventListener('DOMContentLoaded', () => {
  const modeSelect = document.getElementById('modeSelect');
  const methodSelect = document.getElementById('methodSelect');
  const keyInput = document.querySelector('input[name="aes_key"]');
  const xorInput = document.querySelector('input[name="xor_key"]');

  const syncFields = () => {
    const mode = modeSelect ? modeSelect.value : 'decrypt';
    const method = methodSelect ? methodSelect.value : 'auto';

    if (keyInput) {
      keyInput.disabled = method !== 'aes' && method !== 'auto';
      keyInput.placeholder = method === 'aes'
        ? 'AES key. Default sample: myKey123'
        : 'Optional when auto-detect is used';
    }

    if (xorInput) {
      xorInput.disabled = method !== 'xor' && method !== 'auto';
      xorInput.placeholder = method === 'xor'
        ? '0 - 255'
        : 'Optional when auto-detect is used';
    }

    if (mode === 'analyze') {
      if (keyInput) keyInput.disabled = true;
      if (xorInput) xorInput.disabled = true;
    }
  };

  if (modeSelect) modeSelect.addEventListener('change', syncFields);
  if (methodSelect) methodSelect.addEventListener('change', syncFields);
  syncFields();

  // MDB schema preview
  async function fetchMdbSchema(runId, tableName) {
    if (!runId || !tableName) return;
    const url = `/api/mdb_schema/${encodeURIComponent(runId)}/${encodeURIComponent(tableName)}`;
    try {
      const resp = await fetch(url);
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        console.error('Failed to fetch schema', err);
        return;
      }
      const data = await resp.json();
      const container = document.getElementById('mdbSchemaPreview');
      const tableBody = document.querySelector('#mdbSchemaTable tbody');
      tableBody.innerHTML = '';
      if (data && data.columns && data.columns.length) {
        data.columns.forEach(col => {
          const tr = document.createElement('tr');
          const tdName = document.createElement('td');
          tdName.textContent = col.name;
          const tdType = document.createElement('td');
          tdType.textContent = col.type || '';
          const tdPk = document.createElement('td');
          tdPk.textContent = col.is_pk ? 'YES' : '';
          tr.appendChild(tdName);
          tr.appendChild(tdType);
          tr.appendChild(tdPk);
          tableBody.appendChild(tr);
        });
        if (container) container.style.display = '';
      } else {
        if (container) container.style.display = 'none';
      }
    } catch (e) {
      console.error('Error fetching MDB schema', e);
    }
  }

  const previewBtn = document.getElementById('previewMdbSchemaBtn');
  if (previewBtn) {
    previewBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const panel = document.getElementById('mdbPanel');
      const runId = panel ? panel.dataset.runId : null;
      const tableSelect = document.querySelector('#mdbPanel select[name="table"]');
      const tableName = tableSelect ? tableSelect.value : null;
      fetchMdbSchema(runId, tableName);
    });
  }
});