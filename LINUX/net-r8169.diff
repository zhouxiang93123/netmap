--- net/r8169.c	2011-08-18 09:37:02.000000000 +0200
+++ net/r8169.c	2012-02-17 11:16:41.408764449 +0100
@@ -705,6 +705,10 @@ static int rtl8169_poll(struct napi_stru
 static const unsigned int rtl8169_rx_config =
 	(RX_FIFO_THRESH << RxCfgFIFOShift) | (RX_DMA_BURST << RxCfgDMAShift);
 
+#if defined(CONFIG_NETMAP) || defined(CONFIG_NETMAP_MODULE)
+#include <netmap/if_re_netmap_linux.h>
+#endif
+
 static u32 ocp_read(struct rtl8169_private *tp, u8 mask, u16 reg)
 {
 	void __iomem *ioaddr = tp->mmio_addr;
@@ -3467,6 +3471,10 @@ rtl8169_init_one(struct pci_dev *pdev, c
 	if (pci_dev_run_wake(pdev))
 		pm_runtime_put_noidle(&pdev->dev);
 
+#ifdef DEV_NETMAP
+	re_netmap_attach(tp);
+#endif /* DEV_NETMAP */
+
 	netif_carrier_off(dev);
 
 out:
@@ -3502,6 +3510,9 @@ static void __devexit rtl8169_remove_one
 
 	rtl_release_firmware(tp);
 
+#ifdef DEV_NETMAP
+	netmap_detach(dev);
+#endif /* DEV_NETMAP */
 	if (pci_dev_run_wake(pdev))
 		pm_runtime_get_noresume(&pdev->dev);
 
@@ -4438,6 +4449,11 @@ static inline void rtl8169_mark_as_last_
 static int rtl8169_rx_fill(struct rtl8169_private *tp)
 {
 	unsigned int i;
+#ifdef DEV_NETMAP
+	re_netmap_tx_init(tp);
+	if (re_netmap_rx_init(tp))
+		return 0; // success
+#endif /* DEV_NETMAP */
 
 	for (i = 0; i < NUM_RX_DESC; i++) {
 		void *data;
@@ -4821,6 +4837,10 @@ static void rtl8169_tx_interrupt(struct
 {
 	unsigned int dirty_tx, tx_left;
 
+#ifdef DEV_NETMAP
+	if (netmap_tx_irq(dev, 0))
+		return;
+#endif /* DEV_NETMAP */
 	dirty_tx = tp->dirty_tx;
 	smp_rmb();
 	tx_left = tp->cur_tx - dirty_tx;
@@ -4908,6 +4928,10 @@ static int rtl8169_rx_interrupt(struct n
 	unsigned int cur_rx, rx_left;
 	unsigned int count;
 
+#ifdef DEV_NETMAP
+	if (netmap_rx_irq(dev, 0, &count))
+   		return count;
+#endif /* DEV_NETMAP */
 	cur_rx = tp->cur_rx;
 	rx_left = NUM_RX_DESC + tp->dirty_rx - cur_rx;
 	rx_left = min(rx_left, budget);
