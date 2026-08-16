# dsh-safety 动态沙箱容器镜像
# 用法：docker build -t dsh-safety-sandbox .
# 运行由 runner 的 docker 模式发起：--network none（内核级禁网）+ 只读挂载 + 资源限制
FROM node:24-slim

WORKDIR /sandbox

# 沙箱入口（构建时从 dist 复制）
COPY dist/dynamic/sandbox.mjs /sandbox/sandbox.mjs

# 非 root 运行
RUN useradd -m sandboxuser
USER sandboxuser

# 入口：插件目录 /sandbox/plugin（只读挂载），工作目录 /sandbox/work（可写挂载）
ENTRYPOINT ["node", "--permission", "--allow-fs-read=/sandbox/sandbox.mjs", "--allow-fs-read=/sandbox/plugin", "--allow-fs-read=/sandbox/work", "--allow-fs-write=/sandbox/work", "/sandbox/sandbox.mjs", "/sandbox/plugin", "/sandbox/work"]
