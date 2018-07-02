# Meltdown 漏洞攻击
## 一.实验原理
Spectre和Meltdown是缓冲时延旁路攻击的两种实际攻击方法。
计算机操作系统有一个最基本的安全目标：保证用户程序不能任意访问内核/其他用户程序的内存。
一旦某个恶意应用可以任意访问其他应用程序/操作系统的内存，那么后果则不堪设想。
为了实现这个目标，操作系统和计算机硬件（CPU）采取了以下措施：
操作系统：通过虚拟内存为每个应用程序和内核开辟独立的地址空间，规定相应的访问权限。
CPU：通过硬件实现支持虚拟内存（TLB）及其相应的访问权限。

V3攻击可以被用于从用户态读取内核态数据。通常来说，如果用户态程序直接访问内核的内存区域会直接产生一个页错误（由于页表权限限制）。
然而，在特定条件下，攻击者可以利用推测执行机制来间接获取内核内存区域的内容。
例如，在某些实现中，推测执行的指令序列会将缓存在L1 Cache中的数据传递给随后的指令进行操作（并影响Cache状态）。
这会导致用户态程序能通过Cache侧信道的方式推测得到内核态数据。需要注意的是该攻击只限于已被内核分配页表的内存（在页表里被标为supervisor-only），
被标为not present的内存区域是不能被攻击的。

## 二.关闭meltdown 漏洞
用检测meltdown漏洞是否已经被修复，如被修复应该关闭Meltdown漏洞补丁pti
  打开/etc/default/grub在其中GRUB_CMDLINE_LINUX的值加上"nopti" （sudo vi /etc/default/grub 之后在vim编辑器中修改添加nopti)
  接下来运行命令 grub-mkconfig -o /boot/grub/grub.cfg reboot
  然后再重启计算机
  再grep . /sys/devices/system/cpu/vulnerabilities/* 
  此时应该有/sys/devices/system/cpu/vulnerabilities/meltdown:Vulnerable

## 三.实验细节
这里采用了flush+reload技术
这里参考了https://github.com/IAIK/meltdown
https://www.cnblogs.com/backahasten/p/7860254.html
