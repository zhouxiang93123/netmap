#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xccdbab75, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x4ef64f1b, __VMLINUX_SYMBOL_STR(cdev_del) },
	{ 0xd79e7b48, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x72197596, __VMLINUX_SYMBOL_STR(eventfd_ctx_fileget) },
	{ 0x85591b8e, __VMLINUX_SYMBOL_STR(cdev_init) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0x90ff9277, __VMLINUX_SYMBOL_STR(sockfd_lookup) },
	{ 0xdf0f75c6, __VMLINUX_SYMBOL_STR(eventfd_signal) },
	{ 0xc8b57c27, __VMLINUX_SYMBOL_STR(autoremove_wake_function) },
	{ 0x3a013b7d, __VMLINUX_SYMBOL_STR(remove_wait_queue) },
	{ 0xf087137d, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x67acb2d7, __VMLINUX_SYMBOL_STR(device_destroy) },
	{ 0x6729d3df, __VMLINUX_SYMBOL_STR(__get_user_4) },
	{ 0xd0b6f0cb, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xcde75f95, __VMLINUX_SYMBOL_STR(mmput) },
	{ 0x7485e15e, __VMLINUX_SYMBOL_STR(unregister_chrdev_region) },
	{ 0xfc28f7e7, __VMLINUX_SYMBOL_STR(get_netmap_socket) },
	{ 0x340b46, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x68dfc59f, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xf97456ea, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x31dcd070, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x74fd9f6c, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x654dd375, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x7b9bcca1, __VMLINUX_SYMBOL_STR(get_task_mm) },
	{ 0x98503a08, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irq) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0xc3aaf0a9, __VMLINUX_SYMBOL_STR(__put_user_1) },
	{ 0x83c34bf3, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xefbbd439, __VMLINUX_SYMBOL_STR(noop_llseek) },
	{ 0xc55ca8e9, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0xe112f659, __VMLINUX_SYMBOL_STR(use_mm) },
	{ 0x6091797f, __VMLINUX_SYMBOL_STR(synchronize_rcu) },
	{ 0x70c79791, __VMLINUX_SYMBOL_STR(fput) },
	{ 0xda3fd9d4, __VMLINUX_SYMBOL_STR(cdev_add) },
	{ 0xb2fd5ceb, __VMLINUX_SYMBOL_STR(__put_user_4) },
	{ 0xfd9917e0, __VMLINUX_SYMBOL_STR(tun_get_socket) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0xa202a8e5, __VMLINUX_SYMBOL_STR(kmalloc_order_trace) },
	{ 0x6d334118, __VMLINUX_SYMBOL_STR(__get_user_8) },
	{ 0xf1faac3a, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irq) },
	{ 0x33a9717a, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xc35f238e, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x21fb443e, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xe45f60d8, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0xd7bd3af2, __VMLINUX_SYMBOL_STR(add_wait_queue) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x622fa02a, __VMLINUX_SYMBOL_STR(prepare_to_wait) },
	{ 0x10e80bf1, __VMLINUX_SYMBOL_STR(eventfd_fget) },
	{ 0x20147085, __VMLINUX_SYMBOL_STR(fget) },
	{ 0xc1759ca2, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0x5a4896a8, __VMLINUX_SYMBOL_STR(__put_user_2) },
	{ 0x75bb675a, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0x941f2aaa, __VMLINUX_SYMBOL_STR(eventfd_ctx_put) },
	{ 0xb0ea57c8, __VMLINUX_SYMBOL_STR(unuse_mm) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x76d5ad07, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0x29537c9e, __VMLINUX_SYMBOL_STR(alloc_chrdev_region) },
	{ 0xab37c5f1, __VMLINUX_SYMBOL_STR(macvtap_get_socket) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=netmap_lin,tun,macvtap";


MODULE_INFO(srcversion, "D6012352DFECF421C90D580");
