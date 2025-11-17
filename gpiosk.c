#include "gpiosk.h"


struct net_device *geth_devs;
struct geth_priv *geth_privs;


int lockup = 0;
int timeout = GETH_TIMEOUT;
int pool_size = 8;


void (*geth_interrupt)(int, void *, struct pt_regs *);

int gpio_ready = 0;

int gpio_ctl_o = -1;
int gpio_ctl_i = -1;
int gpio_data_o = -1;
int gpio_data_i = -1;

unsigned int gpio_ctl_i_irq;
unsigned int gpio_data_i_irq;

int comms_mode_o = 0;

int comms_mode_i = 0;
int ctl_bits_count = 0;
int data_bits_count = 0;

u8 o_value[MAX_PKTLEN] = {0};
u8 i_value[MAX_PKTLEN] = {0};


int i_q_ptr = -1;
int i_q_len[MAX_Q_LEN];
u8 i_q[MAX_Q_LEN][MAX_PKTLEN];

spinlock_t q_lock;


void geth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs){

    printk(KERN_INFO "napi interrupt\n");

	struct geth_priv *priv;
	struct net_device *dev = (struct net_device *)dev_id;

	if (!dev){
        printk(KERN_INFO "invalid dev\n");
		return;
    }

	priv = netdev_priv(dev);

	printk(KERN_INFO "napi receive\n");

	//spin_lock(&q_lock);

	i_q_ptr += 1;
	i_q_len[i_q_ptr] = data_bits_count / 8;
	memcpy(i_q[i_q_ptr], i_value, i_q_len[i_q_ptr]);

	//spin_unlock(&q_lock);

	napi_schedule(&priv->napi);

    printk(KERN_INFO "napi interrupt end\n");

	return;
}


int geth_poll(struct napi_struct *napi, int budget){


	int npackets = 0;
	struct sk_buff *skb;
	struct geth_priv *priv = container_of(napi, struct geth_priv, napi);
	struct net_device *dev = priv->dev;
	struct geth_packet pkt;
	
	void *orig_data, *orig_data_end;
	struct bpf_prog *xdp_prog = priv->xdp_prog;
	struct xdp_buff xdp_buff;
	u32 frame_sz;
	u32 act;
	int off;
	//spin_lock(&q_lock);

	//spin_unlock(&q_lock);

    printk(KERN_INFO "polling\n");

	xdp_set_return_frame_no_direct();

	pkt.dev = dev;
	pkt.datalen = i_q_len[i_q_ptr];
	memcpy(pkt.data, i_q[i_q_ptr], pkt.datalen);

	skb = dev_alloc_skb(NET_IP_ALIGN + pkt.datalen);
	skb_reserve(skb, NET_IP_ALIGN);  
	memcpy(skb_put(skb, pkt.datalen), pkt.data, pkt.datalen);
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if(unlikely(!xdp_prog)){
		goto noxdpprog;
	}
	frame_sz = skb_end_pointer(skb) - skb->head;
	frame_sz = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	xdp_init_buff(&xdp_buff, frame_sz, &priv->xdp_rxq);
	xdp_prepare_buff(&xdp_buff, skb->head, skb_headroom(skb), skb_headlen(skb), true);
	if (skb_is_nonlinear(skb)) {
		skb_shinfo(skb)->xdp_frags_size = skb->data_len;
		xdp_buff_set_frags_flag(&xdp_buff);
	} else {
		xdp_buff_clear_frags_flag(&xdp_buff);
	}

	orig_data = xdp_buff.data;
	orig_data_end = xdp_buff.data_end;
	act = bpf_prog_run_xdp(xdp_prog, &xdp_buff);
	switch(act){
		case XDP_PASS:
			printk(KERN_INFO "geth: XDP_PASS\n");
			break;
		default:
			printk(KERN_INFO "geth: XDP_DROP\n");
			goto exit;
	}
	off = orig_data - xdp_buff.data;
	if (off > 0)
		__skb_push(skb, off);
	else if (off < 0)
		__skb_pull(skb, -off);

	skb_reset_mac_header(skb);

	off = xdp_buff.data_end - orig_data_end;
	if (off != 0){
		__skb_put(skb, off); 
	}

	if (xdp_buff_has_frags(&xdp_buff)){
		skb->data_len = skb_shinfo(skb)->xdp_frags_size;
	} else {
		skb->data_len = 0;
	}

noxdpprog:

	netif_receive_skb(skb);

	npackets++;
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt.datalen;

exit:

	if (npackets < budget) {
        printk(KERN_INFO "npackets smaller than budget\n");
		unsigned long flags;
		spin_lock_irqsave(&priv->lock, flags);
		if (napi_complete_done(napi, npackets)){
			printk(KERN_INFO "napi complete\n");
        }
		spin_unlock_irqrestore(&priv->lock, flags);
	}

    printk(KERN_INFO "polling end\n");
	i_q_ptr -= 1;
	xdp_clear_return_frame_no_direct();

	return npackets;

}



netdev_tx_t geth_xmit(struct sk_buff *skb, struct net_device *dev){

    printk("entered xmit\n");

	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct geth_priv *priv = netdev_priv(dev);

	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	netif_trans_update(dev);

	priv->skb = skb;

	geth_hw_tx(data, len, dev);

    printk("exiting xmit\n");

	return 0;


}


void geth_hw_tx(char *buf, int len, struct net_device *dev){


    printk(KERN_INFO "entered hw tx\n");

	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;
	struct tcphdr *th;

	struct geth_priv *priv;
	u16 sport;
	u16 dport;


	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("geth: packet too short (%i octets)\n",
				len);
		return;
	}


	eh = (struct ethhdr*)buf;

	ih = (struct iphdr*)(buf + sizeof(struct ethhdr));


	printk("eth src: %02X:%02X:%02X:%02X:%02X:%02X\n", 
		eh->h_source[0],  
		eh->h_source[1],  
		eh->h_source[2],  
		eh->h_source[3],  
		eh->h_source[4],  
		eh->h_source[5]);
	printk("eth dst: %02X:%02X:%02X:%02X:%02X:%02X\n", 
		eh->h_dest[0], 
		eh->h_dest[1], 
		eh->h_dest[2], 
		eh->h_dest[3], 
		eh->h_dest[4], 
		eh->h_dest[5]);


	if(ih->protocol == IPPROTO_UDP){

		uh = (struct udphdr*)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));

		sport = ntohs(uh->source);
		dport = ntohs(uh->dest);

	} else if (ih->protocol == IPPROTO_TCP){

		th = (struct tcphdr*)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));

		sport = ntohs(th->source);
		dport = ntohs(th->dest);

	}

	printk("src: %08x:%05i\n",
		ntohl(ih->saddr), sport);

	printk("dst: %08x:%05i\n",
		ntohl(ih->daddr), dport);


	
	gpio_tx((u8*)buf, len);

	priv = netdev_priv(dev);

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += len;
	if(priv->skb) {
		dev_kfree_skb(priv->skb);
		priv->skb = 0;
	}
	if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {

		netif_stop_queue(dev);
		printk(KERN_INFO "simulate lockup at %ld, txp %ld\n", jiffies, (unsigned long) priv->stats.tx_packets);

	} 

}




int geth_open(struct net_device *dev){

	char macaddr[ETH_ALEN] = {0};

	int val = 1;

	printk(KERN_INFO "geth mac val: %d\n", val);

	sprintf(macaddr, "GETH0%d", val);

	memcpy((void*)dev->dev_addr, macaddr, ETH_ALEN);

	struct geth_priv *priv = netdev_priv(dev);
	napi_enable(&priv->napi);

	netif_start_queue(dev);

    printk(KERN_INFO "started geth\n");

	return 0;
}

int geth_stop(struct net_device *dev){

	netif_stop_queue(dev);

	struct geth_priv *priv = netdev_priv(dev);
	napi_disable(&priv->napi);

	return 0;

    printk(KERN_INFO "stopped geth\n");
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void geth_tx_timeout(struct net_device *dev)

#else 

void geth_tx_timeout(struct net_device *dev, unsigned int txqueue)

#endif 

{
	struct geth_priv *priv = netdev_priv(dev);
    struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	printk(KERN_INFO "transmit timeout at %ld, latency %ld\n", jiffies,
			jiffies - txq->trans_start);

	geth_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;

	spin_lock(&priv->lock);
	spin_unlock(&priv->lock);

	netif_wake_queue(dev);
	return;
}

/* XDP functions */



static bool geth_gro_requested(const struct net_device *dev){
	return !!(dev->wanted_features & NETIF_F_GRO);
}

static void geth_disable_xdp_range(struct net_device *dev, int start, int end, bool delete_napi){

	struct geth_priv *priv = netdev_priv(dev);
	int i;

	for (i = start; i < end; i++) {
		priv->xdp_rxq.mem = priv->xdp_mem;
		xdp_rxq_info_unreg(&priv->xdp_rxq);

		if (delete_napi)
			netif_napi_del(&priv->napi);
	}
}

static int geth_enable_xdp_range(struct net_device *dev, int start, int end, bool napi_already_on){

	struct geth_priv *priv = netdev_priv(dev);
	int err, i;

	for (i = start; i < end; i++) {

		if (!napi_already_on){
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
			netif_napi_add(dev, &priv->napi, geth_poll,2);
#else 
			netif_napi_add_weight(dev, &priv->napi, geth_poll,2);
#endif
		}
		err = xdp_rxq_info_reg(&priv->xdp_rxq, dev, i, priv->napi.napi_id);
		if (err < 0)
			goto err_rxq_reg;

		err = xdp_rxq_info_reg_mem_model(&priv->xdp_rxq, MEM_TYPE_PAGE_SHARED, NULL);
		if (err < 0)
			goto err_reg_mem;

		/* Save original mem info as it can be overwritten */
		priv->xdp_mem = priv->xdp_rxq.mem;
	}
	return 0;

err_reg_mem:
	xdp_rxq_info_unreg(&priv->xdp_rxq);
err_rxq_reg:
	for (i--; i >= start; i--) {
		xdp_rxq_info_unreg(&priv->xdp_rxq);
		if (!napi_already_on)
			netif_napi_del(&priv->napi);
	}

	return err;
}

static int geth_enable_xdp(struct net_device *dev){

	bool napi_already_on = geth_gro_requested(dev) && (dev->flags & IFF_UP);
	struct geth_priv *priv = netdev_priv(dev);
	int err, i;

	if (!xdp_rxq_info_is_reg(&priv->xdp_rxq)) {
		err = geth_enable_xdp_range(dev, 0, dev->real_num_rx_queues, napi_already_on);
		if (err)
			return err;

	}

	return 0;
}

static int geth_xdp_set(struct net_device *dev, struct bpf_prog *prog, struct netlink_ext_ack *extack){

	struct geth_priv *priv = netdev_priv(dev);
	struct bpf_prog *old_prog;
	int err;

	old_prog = priv->xdp_prog;
	priv->xdp_prog = prog;

	if (prog) {


		if (dev->flags & IFF_UP) {
			err = geth_enable_xdp(dev);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Setup for XDP failed");
				goto err;
			}
		}

		if (!old_prog) {
			if (!geth_gro_requested(dev)) {

				dev->features |= NETIF_F_GRO;
				netdev_features_change(dev);
			}
		}

	}
	printk("geth: loaded xdp prog\n");

	return 0;
err:
	priv->xdp_prog = old_prog;

	return err;
}

static int geth_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return geth_xdp_set(dev, xdp->prog, xdp->extack);
	default:
		return -EINVAL;
	}
}

/* XDP functions end */


const struct net_device_ops geth_netdev_ops = {
	.ndo_open            = geth_open,
	.ndo_stop            = geth_stop,
	.ndo_start_xmit      = geth_xmit,
	.ndo_tx_timeout      = geth_tx_timeout,
	.ndo_bpf             = geth_xdp,
};




void geth_setup(struct net_device *dev){

	ether_setup(dev); 
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &geth_netdev_ops;
	dev->features        |= NETIF_F_HW_CSUM;

	geth_privs = netdev_priv(dev);

	memset(geth_privs, 0, sizeof(struct geth_priv));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
	netif_napi_add(dev, &geth_privs->napi, geth_poll,2);
#else 
	netif_napi_add_weight(dev, &geth_privs->napi, geth_poll,2);
#endif

    spin_lock_init(&q_lock);
	spin_lock_init(&geth_privs->lock);
	geth_privs->dev = dev;

	printk(KERN_INFO "geth: setup success\n");
}




void gpio_ctl_on(void){

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_RISING);

	udelay(SYNC_UDELAY);

	gpio_set_value(gpio_ctl_o, IRQF_TRIGGER_NONE);
}

void gpio_data_on(void){

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_RISING);

	udelay(SYNC_UDELAY);

	gpio_set_value(gpio_data_o, IRQF_TRIGGER_NONE);

}

void gpio_tx(u8* data, int datalen){

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}

	gpio_data_on();

	for(int i = 0; i < datalen; i++) {

		for(int j = 0; j < 8; j++){

			if(CHECK_BIT(data[i], j)){

				if(!comms_mode_o){

					gpio_ctl_on();

					comms_mode_o = 1;
				}

				gpio_data_on();

			} else {

				if(comms_mode_o){
					
					gpio_ctl_on();

					comms_mode_o = 0;
				}

				gpio_data_on();

			}

		}

	}

	for(int i = 0; i < 3; i++){

		gpio_ctl_on();
	}
	
	gpio_data_on();

	comms_mode_o = 0;

}


irqreturn_t gpio_ctl_irq_handler(int irq, void *dev_id) {
	ctl_bits_count += 1;
	return IRQ_HANDLED;
}

irqreturn_t gpio_data_irq_handler(int irq, void *dev_id) {

	int pktidx = 0;
	int bitidx = 0;

	if(ctl_bits_count == 3){
		ctl_bits_count = 0;
		if(data_bits_count == 0){
			return IRQ_HANDLED;
		} else {
			if(gpio_ctl_i != 0 && gpio_ctl_o != 0){

				geth_interrupt(0, geth_devs, NULL);
			}else {
				printk("value: %02x%02x%02x%02x...%02x%02x%02x%02x\n", 
					i_value[0],
					i_value[1],
					i_value[2],
					i_value[3],
					i_value[MAX_PKTLEN-4],
					i_value[MAX_PKTLEN-3],
					i_value[MAX_PKTLEN-2],
					i_value[MAX_PKTLEN-1]
				);
			}
			memset(i_value, 0, MAX_PKTLEN);
			data_bits_count = 0;
			comms_mode_i = 0;
			return IRQ_HANDLED;
		}
	}

	if(ctl_bits_count == 1){
		ctl_bits_count = 0;
		if(comms_mode_i){
			comms_mode_i = 0;
		} else {
			comms_mode_i = 1;
		}
	}

	pktidx = data_bits_count / 8;
	bitidx = data_bits_count % 8;

	if(comms_mode_i){

		i_value[pktidx] = i_value[pktidx] | (1 << bitidx);

	} else {

		i_value[pktidx] = i_value[pktidx] | (0 << bitidx);

	}

	data_bits_count += 1;

	return IRQ_HANDLED;
}

static int _gpio_get_line(struct gpio_chip *gc, const void *data){
	if(gpio_ready){
		return 0;
	}
    if(gc->label != NULL){
        if(strcmp(gc->label, PINCTRL_BCM2711) == 0){
			printk("gpiosk: chip detected: label: %s base: %d num: %d\n", gc->label, gc->base, gc->ngpio);
			gpio_ctl_o = gc->base + PIN_CTL_OUT;
			gpio_ctl_i = gc->base + PIN_CTL_IN;
			gpio_data_o = gc->base + PIN_DATA_OUT;
			gpio_data_i = gc->base + PIN_DATA_IN;
			gpio_ready = 1;
        }
    } 
    return 0;
}

static int __init ksock_gpio_init(void) {

	int err;

	gpio_device_find(NULL, _gpio_get_line);
	if(!gpio_ready){
		printk("gpiosk: available gpio chip is not found\n");
		return -1;
	}
	if(gpio_request(gpio_ctl_o, "gpio-ctl-o")) {
		printk("gpiosk: can't allocate gpio_ctl_o: %d\n", gpio_ctl_o);
		return -1;
	}		

	if(gpio_direction_output(gpio_ctl_o, IRQF_TRIGGER_NONE)) {
		printk("gpiosk: can't set gpio_ctl_o to output\n");
		gpio_free(gpio_ctl_o);
		return -1;
	}

	if(gpio_request(gpio_data_o, "gpio-data-o")) {
		printk("gpiosk: can't allocate gpio_data_o: %d\n", gpio_data_o);
		gpio_free(gpio_ctl_o);
		return -1;
	}		

	if(gpio_direction_output(gpio_data_o, IRQF_TRIGGER_NONE)) {
		printk("gpiosk: can't set gpio_data_o to output\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		return -1;
	}

	if(gpio_request(gpio_ctl_i, "gpio-ctl-i")) {
		printk("gpiosk: can't allocate gpio_ctl_i: %d\n", gpio_ctl_i);
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		return -1;
	}

	if(gpio_direction_input(gpio_ctl_i)) {
		printk("gpiosk: can't set gpio_ctl_i to input\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		return -1;
	}

	if(gpio_request(gpio_data_i, "gpio-data-i")) {
		printk("gpiosk: can't allocate gpio_data_i: %d\n", gpio_data_i);
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		return -1;
	}


	if(gpio_direction_input(gpio_data_i)) {
		printk("gpiosk: can't set gpio_data_i to input\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		return -1;
	}


	gpio_ctl_i_irq = gpio_to_irq(gpio_ctl_i);

	if(request_irq(gpio_ctl_i_irq, gpio_ctl_irq_handler, IRQF_TRIGGER_RISING, "gpio_ctl_i_irq", NULL) != 0) {
		printk("gpiosk: can't request interrupt\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		return -1;
	}

	gpio_data_i_irq = gpio_to_irq(gpio_data_i);

	if(request_irq(gpio_data_i_irq, gpio_data_irq_handler, IRQF_TRIGGER_RISING, "gpio_data_i_irq", NULL) != 0) {
		printk("gpiosk: can't request interrupt\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		free_irq(gpio_ctl_i_irq, NULL);
		return -1;
	}

	printk("gpiosk: gpio_ctl_i to IRQ %d\n", gpio_ctl_i_irq);

	printk("gpiosk: gpio_data_i to IRQ %d\n", gpio_data_i_irq);

	printk("gpiosk: module is initialized into the kernel\n");

	printk("gpiosk: ctl_o: %d ctl_i: %d\n", gpio_ctl_o, gpio_ctl_i);
	printk("gpiosk: data_o: %d data_i: %d\n", gpio_data_o, gpio_data_i);
	
	geth_interrupt = geth_napi_interrupt;

	geth_devs = alloc_netdev(sizeof(struct geth_priv), "geth%d", NET_NAME_UNKNOWN, geth_setup);
	if (!geth_devs){
		printk("gpiosk: can't alloc netdev\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		free_irq(gpio_ctl_i_irq, NULL);
		free_irq(gpio_data_i_irq, NULL);
		return -ENOMEM;
	}

	err = register_netdevice(geth_devs);
	if (err < 0) {
		printk("gpiosk: can't register netdev\n");
		gpio_free(gpio_ctl_o);
		gpio_free(gpio_data_o);
		gpio_free(gpio_ctl_i);
		gpio_free(gpio_data_i);
		free_irq(gpio_ctl_i_irq, NULL);
		free_irq(gpio_data_i_irq, NULL);
		free_netdev(geth_devs);
		return -1;
	}

	return 0;

}

static void __exit ksock_gpio_exit(void) {


	gpio_free(gpio_ctl_o);
	gpio_free(gpio_data_o);

	gpio_free(gpio_ctl_i);
	gpio_free(gpio_data_i);
	free_irq(gpio_ctl_i_irq, NULL);
	free_irq(gpio_data_i_irq, NULL);

	unregister_netdev(geth_devs);
	free_netdev(geth_devs);

	printk("gpiosk: module is removed from the kernel\n");
}

module_init(ksock_gpio_init);
module_exit(ksock_gpio_exit);

MODULE_LICENSE("GPL");