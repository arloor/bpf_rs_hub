# 基于libbpf-rs的lib集合

## 安装依赖

1. Clang编译器。至少需要Clang10，CO-RE需要Clang11或Clang12
2. libbpf库
3. bpftool可执行性文件，用来生成vmlinux.h和xx_skel.h
4. zlib (libz-dev or zlib-devel ) 和 libelf (libelf-dev or elfutils-libelf-devel )
5. pkg-config: libbpf-rs使用pkg-config来查找libbpf库

**ubuntu 22.04 安装：**

```bash
apt-get install -y libbpf-dev libz-dev libelf-dev pkg-config clang bpftool
```

**centos stream 9 安装：**

```bash
yum install -y libbpf zlib-devel elfutils-libelf-devel pkgconf-pkg-config clang bpftool 
```

## 生成vmlinux.h

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## 静态链接libbpf libelf zlib

```bash
yum install -y autoconf gettext-devel flex bison gawk make pkg-config automake
apt-get install -y autoconf autopoint flex bison gawk make pkg-config automake
``` 

激活vendored feature