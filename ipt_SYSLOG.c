/*
 * This is a module which is used for logging packets.
 */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/sock.h>
#include <linux/un.h>

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_LOG.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andras Elso <elso.andras@gmail.com>");
MODULE_DESCRIPTION("iptables syslog logging module");

static unsigned int loglist_maxlen __read_mostly = 1024;
module_param(loglist_maxlen, uint, 0600);
MODULE_PARM_DESC(loglist_maxlen, "loglist size");

static unsigned int reconnect_freq = 5000;
module_param(reconnect_freq, uint, 0600);
MODULE_PARM_DESC(reconnect_freq, "reconnect frequency if syslog offline");

struct logs {
	char *data;
	int counter;
	struct list_head logs_list ;
} ;

/* Use lock to serialize, so printks don't overlap */
static DEFINE_SPINLOCK(log_lock);
static struct socket *sl_socket = NULL;

#define STAT_PROC_FS_NAME "ip_syslog_stat"

static LIST_HEAD(logs_list);
static unsigned int loglist_total = 0;
static unsigned int loglist_dropped = 0;
static int counter = 0;

static void syslog_work_fn(struct work_struct *work);
static DECLARE_WORK(syslog_work, syslog_work_fn);

static void syslog_timer(unsigned long dummy);
static DEFINE_TIMER(timer, syslog_timer, 0, 0);

static int syslog_connect(struct socket **socket);
static void syslog_close(struct socket **socket);

/* One level of recursion won't kill us */
static void dump_packet(const struct nf_loginfo *info,
			const struct sk_buff *skb,
			unsigned int iphoff,
			char *buf, size_t buf_siz)
{
	struct iphdr _iph;
	const struct iphdr *ih;
	unsigned int logflags;

	size_t buf_len = strlen(buf);

#define BUF_ADD(ptr, siz, off, fmt...) \
	do { \
		off = strlen(ptr); \
		snprintf(((ptr)+(off)), ((siz) > (off) ? (siz)-(off) : 0), ##fmt); \
	} while (0)

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;
	else
		logflags = NF_LOG_MASK;

	ih = skb_header_pointer(skb, iphoff, sizeof(_iph), &_iph);
	if (ih == NULL) {
		BUF_ADD(buf,buf_siz,buf_len, "TRUNCATED");
		return;
	}

	/* Important fields:
	 * TOS, len, DF/MF, fragment offset, TTL, src, dst, options. */
	/* Max length: 40 "SRC=255.255.255.255 DST=255.255.255.255 " */
	BUF_ADD(buf,buf_siz,buf_len, "SRC=%u.%u.%u.%u DST=%u.%u.%u.%u ",
	       NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));

	/* Max length: 46 "LEN=65535 TOS=0xFF PREC=0xFF TTL=255 ID=65535 " */
	BUF_ADD(buf,buf_siz,buf_len, "LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
	       ntohs(ih->tot_len), ih->tos & IPTOS_TOS_MASK,
	       ih->tos & IPTOS_PREC_MASK, ih->ttl, ntohs(ih->id));

	/* Max length: 6 "CE DF MF " */
	if (ntohs(ih->frag_off) & IP_CE)
		BUF_ADD(buf,buf_siz,buf_len, "CE ");
	if (ntohs(ih->frag_off) & IP_DF)
		BUF_ADD(buf,buf_siz,buf_len, "DF ");
	if (ntohs(ih->frag_off) & IP_MF)
		BUF_ADD(buf,buf_siz,buf_len, "MF ");

	/* Max length: 11 "FRAG:65535 " */
	if (ntohs(ih->frag_off) & IP_OFFSET)
		BUF_ADD(buf,buf_siz,buf_len, "FRAG:%u ", ntohs(ih->frag_off) & IP_OFFSET);

	if ((logflags & IPT_LOG_IPOPT)
	    && ih->ihl * 4 > sizeof(struct iphdr)) {
		unsigned char _opt[4 * 15 - sizeof(struct iphdr)], *op;
		unsigned int i, optsize;

		optsize = ih->ihl * 4 - sizeof(struct iphdr);
		op = skb_header_pointer(skb, iphoff+sizeof(_iph),
					optsize, _opt);
		if (op == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "TRUNCATED");
			return;
		}

		/* Max length: 127 "OPT (" 15*4*2chars ") " */
		BUF_ADD(buf,buf_siz,buf_len, "OPT (");
		for (i = 0; i < optsize; i++)
			BUF_ADD(buf,buf_siz,buf_len, "%02X", op[i]);
		BUF_ADD(buf,buf_siz,buf_len, ") ");
	}

	switch (ih->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph;
		const struct tcphdr *th;

		/* Max length: 10 "PROTO=TCP " */
		BUF_ADD(buf,buf_siz,buf_len, "PROTO=TCP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		th = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					sizeof(_tcph), &_tcph);
		if (th == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		BUF_ADD(buf,buf_siz,buf_len, "SPT=%u DPT=%u ",
		       ntohs(th->source), ntohs(th->dest));
		/* Max length: 30 "SEQ=4294967295 ACK=4294967295 " */
		if (logflags & IPT_LOG_TCPSEQ)
			BUF_ADD(buf,buf_siz,buf_len, "SEQ=%u ACK=%u ",
			       ntohl(th->seq), ntohl(th->ack_seq));

		/* Max length: 13 "WINDOW=65535 " */
		BUF_ADD(buf,buf_siz,buf_len, "WINDOW=%u ", ntohs(th->window));
		/* Max length: 9 "RES=0x3F " */
		BUF_ADD(buf,buf_siz,buf_len, "RES=0x%02x ", (u8)(ntohl(tcp_flag_word(th) & TCP_RESERVED_BITS) >> 22));
		/* Max length: 32 "CWR ECE URG ACK PSH RST SYN FIN " */
		if (th->cwr)
			BUF_ADD(buf,buf_siz,buf_len, "CWR ");
		if (th->ece)
			BUF_ADD(buf,buf_siz,buf_len, "ECE ");
		if (th->urg)
			BUF_ADD(buf,buf_siz,buf_len, "URG ");
		if (th->ack)
			BUF_ADD(buf,buf_siz,buf_len, "ACK ");
		if (th->psh)
			BUF_ADD(buf,buf_siz,buf_len, "PSH ");
		if (th->rst)
			BUF_ADD(buf,buf_siz,buf_len, "RST ");
		if (th->syn)
			BUF_ADD(buf,buf_siz,buf_len, "SYN ");
		if (th->fin)
			BUF_ADD(buf,buf_siz,buf_len, "FIN ");

		/* Max length: 11 "URGP=65535 " */
		BUF_ADD(buf,buf_siz,buf_len, "URGP=%u ", ntohs(th->urg_ptr));

		if ((logflags & IPT_LOG_TCPOPT)
		    && th->doff * 4 > sizeof(struct tcphdr)) {
			unsigned char _opt[4 * 15 - sizeof(struct tcphdr)];
			const unsigned char *op;
			unsigned int i, optsize;

			optsize = th->doff * 4 - sizeof(struct tcphdr);
			op = skb_header_pointer(skb,
						iphoff+ih->ihl*4+sizeof(_tcph),
						optsize, _opt);
			if (op == NULL) {
				BUF_ADD(buf,buf_siz,buf_len, "TRUNCATED");
				return;
			}

			/* Max length: 127 "OPT (" 15*4*2chars ") " */
			BUF_ADD(buf,buf_siz,buf_len, "OPT (");
			for (i = 0; i < optsize; i++)
				BUF_ADD(buf,buf_siz,buf_len, "%02X", op[i]);
			BUF_ADD(buf,buf_siz,buf_len, ") ");
		}
		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE: {
		struct udphdr _udph;
		const struct udphdr *uh;

		if (ih->protocol == IPPROTO_UDP)
			/* Max length: 10 "PROTO=UDP "     */
			BUF_ADD(buf,buf_siz,buf_len, "PROTO=UDP " );
		else	/* Max length: 14 "PROTO=UDPLITE " */
			BUF_ADD(buf,buf_siz,buf_len, "PROTO=UDPLITE ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		uh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_udph), &_udph);
		if (uh == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		BUF_ADD(buf,buf_siz,buf_len, "SPT=%u DPT=%u LEN=%u ",
		       ntohs(uh->source), ntohs(uh->dest),
		       ntohs(uh->len));
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr _icmph;
		const struct icmphdr *ich;
		static const size_t required_len[NR_ICMP_TYPES+1]
			= { [ICMP_ECHOREPLY] = 4,
			    [ICMP_DEST_UNREACH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_SOURCE_QUENCH]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_REDIRECT]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_ECHO] = 4,
			    [ICMP_TIME_EXCEEDED]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_PARAMETERPROB]
			    = 8 + sizeof(struct iphdr),
			    [ICMP_TIMESTAMP] = 20,
			    [ICMP_TIMESTAMPREPLY] = 20,
			    [ICMP_ADDRESS] = 12,
			    [ICMP_ADDRESSREPLY] = 12 };

		/* Max length: 11 "PROTO=ICMP " */
		BUF_ADD(buf,buf_siz,buf_len, "PROTO=ICMP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ich = skb_header_pointer(skb, iphoff + ih->ihl * 4,
					 sizeof(_icmph), &_icmph);
		if (ich == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Max length: 18 "TYPE=255 CODE=255 " */
		BUF_ADD(buf,buf_siz,buf_len, "TYPE=%u CODE=%u ", ich->type, ich->code);

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (ich->type <= NR_ICMP_TYPES
		    && required_len[ich->type]
		    && skb->len-iphoff-ih->ihl*4 < required_len[ich->type]) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		switch (ich->type) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			/* Max length: 19 "ID=65535 SEQ=65535 " */
			BUF_ADD(buf,buf_siz,buf_len, "ID=%u SEQ=%u ",
			       ntohs(ich->un.echo.id),
			       ntohs(ich->un.echo.sequence));
			break;

		case ICMP_PARAMETERPROB:
			/* Max length: 14 "PARAMETER=255 " */
			BUF_ADD(buf,buf_siz,buf_len, "PARAMETER=%u ",
			       ntohl(ich->un.gateway) >> 24);
			break;
		case ICMP_REDIRECT:
			/* Max length: 24 "GATEWAY=255.255.255.255 " */
			BUF_ADD(buf,buf_siz,buf_len, "GATEWAY=%u.%u.%u.%u ",
			       NIPQUAD(ich->un.gateway));
			/* Fall through */
		case ICMP_DEST_UNREACH:
		case ICMP_SOURCE_QUENCH:
		case ICMP_TIME_EXCEEDED:
			/* Max length: 3+maxlen */
			if (!iphoff) { /* Only recurse once. */
				BUF_ADD(buf,buf_siz,buf_len, "[");
				dump_packet(info, skb,
					    iphoff + ih->ihl*4+sizeof(_icmph), buf, buf_siz);
				BUF_ADD(buf,buf_siz,buf_len, "] ");
			}

			/* Max length: 10 "MTU=65535 " */
			if (ich->type == ICMP_DEST_UNREACH
			    && ich->code == ICMP_FRAG_NEEDED)
				BUF_ADD(buf,buf_siz,buf_len, "MTU=%u ", ntohs(ich->un.frag.mtu));
		}
		break;
	}
	/* Max Length */
	case IPPROTO_AH: {
		struct ip_auth_hdr _ahdr;
		const struct ip_auth_hdr *ah;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 9 "PROTO=AH " */
		BUF_ADD(buf,buf_siz,buf_len, "PROTO=AH ");

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		ah = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_ahdr), &_ahdr);
		if (ah == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		BUF_ADD(buf,buf_siz,buf_len, "SPI=0x%x ", ntohl(ah->spi));
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr _esph;
		const struct ip_esp_hdr *eh;

		/* Max length: 10 "PROTO=ESP " */
		BUF_ADD(buf,buf_siz,buf_len, "PROTO=ESP ");

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		eh = skb_header_pointer(skb, iphoff+ih->ihl*4,
					sizeof(_esph), &_esph);
		if (eh == NULL) {
			BUF_ADD(buf,buf_siz,buf_len, "INCOMPLETE [%u bytes] ",
			       skb->len - iphoff - ih->ihl*4);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		BUF_ADD(buf,buf_siz,buf_len, "SPI=0x%x ", ntohl(eh->spi));
		break;
	}
	/* Max length: 10 "PROTO 255 " */
	default:
		BUF_ADD(buf,buf_siz,buf_len, "PROTO=%u ", ih->protocol);
	}

	/* Max length: 15 "UID=4294967295 " */
	if ((logflags & IPT_LOG_UID) && !iphoff && skb->sk) {
		read_lock_bh(&skb->sk->sk_callback_lock);
		if (skb->sk->sk_socket && skb->sk->sk_socket->file)
			BUF_ADD(buf,buf_siz,buf_len, "UID=%u ", skb->sk->sk_socket->file->f_uid);
		read_unlock_bh(&skb->sk->sk_callback_lock);
	}

	/* Proto    Max log string length */
	/* IP:      40+46+6+11+127 = 230 */
	/* TCP:     10+max(25,20+30+13+9+32+11+127) = 252 */
	/* UDP:     10+max(25,20) = 35 */
	/* UDPLITE: 14+max(25,20) = 39 */
	/* ICMP:    11+max(25, 18+25+max(19,14,24+3+n+10,3+n+10)) = 91+n */
	/* ESP:     10+max(25)+15 = 50 */
	/* AH:      9+max(25)+15 = 49 */
	/* unknown: 10 */

	/* (ICMP allows recursion one level deep) */
	/* maxlen =  IP + ICMP +  IP + max(TCP,UDP,ICMP,unknown) */
	/* maxlen = 230+   91  + 230 + 252 = 803 */
}

static struct nf_loginfo default_loginfo = {
	.type	= NF_LOG_TYPE_LOG,
	.u = {
		.log = {
			.level    = 0,
			.logflags = NF_LOG_MASK,
		},
	},
};

static void syslog_timer(unsigned long dummy)
{
	printk(KERN_DEBUG "ip_syslog: syslog_timer\n");
	schedule_work(&syslog_work);
}

static void syslog_work_fn(struct work_struct *work)
{
	struct msghdr   msg;
	struct kvec     iov;
	int ret;
	size_t n = 0;
	struct logs * log_entry;

	if (sl_socket != NULL)
		goto cont;
	ret = syslog_connect(&sl_socket);
	if (ret >= 0)
		goto cont;
	if (!timer_pending(&timer))
	{
		timer.expires = jiffies + msecs_to_jiffies(reconnect_freq);
		add_timer(&timer);
	}
	return ;

cont:

	if (list_empty(&logs_list))
		return;

	spin_lock_irq(&log_lock);

	while (!list_empty(&logs_list))
	{
		log_entry =  list_first_entry(&logs_list, struct logs, logs_list);

		printk(KERN_DEBUG "ip_syslog: work data (%d): %d\n", counter, log_entry->counter);

		n = strlen(log_entry->data);
		iov.iov_base     = (void *)log_entry->data;
		iov.iov_len      = n;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = (struct iovec *)&iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_namelen = 0;
		msg.msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL;

		ret = kernel_sendmsg(sl_socket, &msg, &iov, 1, n);
		if (ret < 0)
		{
			printk("ip_syslog: kernel_sendmsg error:%d\n", ret);
			if (ret == -EPIPE)
			{
				syslog_close(&sl_socket);
				schedule_work(&syslog_work);
			}
			break;
		}

		loglist_total--;
		list_del(&log_entry->logs_list);
		kfree(log_entry->data);
		kfree(log_entry);
	}

	spin_unlock_irq(&log_lock);
	return ;
}

static void
send_data(const char *buffer, const size_t length)
{
	struct logs *newlog;
	if (loglist_total >= loglist_maxlen) {
		struct logs * log_entry;

		loglist_dropped++;
		printk(KERN_WARNING "ip_SYSLOG: full at %d entries, dropping log. Dropped: %d\n", loglist_total, loglist_dropped);
		log_entry =  list_first_entry(&logs_list, struct logs, logs_list);

		loglist_total--;
		list_del(&log_entry->logs_list);
		kfree(log_entry->data);
		kfree(log_entry);
	}

	newlog = kzalloc(sizeof(struct logs), GFP_KERNEL);
	counter++;
	newlog->data = kstrdup(buffer, GFP_KERNEL);
	newlog->counter = counter;
	loglist_total++;
	list_add_tail(&newlog->logs_list, &logs_list);

	schedule_work(&syslog_work);

	printk(KERN_DEBUG "send_data: %d\n", counter);
}

static void
ipt_log_packet(unsigned int pf,
	       unsigned int hooknum,
	       const struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       const struct nf_loginfo *loginfo,
	       const char *prefix)
{
	static char buf[4096];
	size_t buf_siz = sizeof(buf);
	size_t buf_len = 0;

	*buf = '\0';

	if (!loginfo)
		loginfo = &default_loginfo;

	spin_lock_bh(&log_lock);
	BUF_ADD(buf,buf_siz,buf_len, "<%d>%sIN=%s OUT=%s ", loginfo->u.log.level,
	       prefix[0] ? prefix : "netfilter: ",
	       in ? in->name : "",
	       out ? out->name : "");
#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge) {
		const struct net_device *physindev;
		const struct net_device *physoutdev;

		physindev = skb->nf_bridge->physindev;
		if (physindev && in != physindev)
			BUF_ADD(buf,buf_siz,buf_len, "PHYSIN=%s ", physindev->name);

		physoutdev = skb->nf_bridge->physoutdev;
		if (physoutdev && out != physoutdev)
			BUF_ADD(buf,buf_siz,buf_len, "PHYSOUT=%s ", physoutdev->name);
	}
#endif

	if (in && !out) {
		/* MAC logging for input chain only. */
		BUF_ADD(buf,buf_siz,buf_len, "MAC=");
		if (skb->dev && skb->dev->hard_header_len
		    && skb->mac_header != skb->network_header) {
			int i;
			const unsigned char *p = skb_mac_header(skb);
			for (i = 0; i < skb->dev->hard_header_len; i++,p++)
				BUF_ADD(buf,buf_siz,buf_len, "%02x%c", *p,
				       i==skb->dev->hard_header_len - 1
				       ? ' ':':');
		} else
			BUF_ADD(buf,buf_siz,buf_len, " ");
	}

	dump_packet(loginfo, skb, 0, buf, buf_siz);
	BUF_ADD(buf,buf_siz,buf_len, "\n");
	send_data(buf, strlen(buf));
	spin_unlock_bh(&log_lock);
}

static unsigned int
ipt_log_target(struct sk_buff *skb,
	       const struct net_device *in,
	       const struct net_device *out,
	       unsigned int hooknum,
	       const struct xt_target *target,
	       const void *targinfo)
{
	const struct ipt_log_info *loginfo = targinfo;
	struct nf_loginfo li;

	li.type = NF_LOG_TYPE_LOG;
	li.u.log.level = loginfo->level;
	li.u.log.logflags = loginfo->logflags;

	ipt_log_packet(PF_INET, hooknum, skb, in, out, &li,
		       loginfo->prefix);
	return XT_CONTINUE;
}

static bool ipt_log_checkentry(const char *tablename,
			       const void *e,
			       const struct xt_target *target,
			       void *targinfo,
			       unsigned int hook_mask)
{
	const struct ipt_log_info *loginfo = targinfo;

	if (loginfo->level >= 8) {
		pr_debug("SYSLOG: level %u >= 8\n", loginfo->level);
		return false;
	}
	if (loginfo->prefix[sizeof(loginfo->prefix)-1] != '\0') {
		pr_debug("SYSLOG: prefix term %i\n",
			 loginfo->prefix[sizeof(loginfo->prefix)-1]);
		return false;
	}
	return true;
}

static struct xt_target ipt_log_reg __read_mostly = {
	.name		= "SYSLOG",
	.family		= AF_INET,
	.target		= ipt_log_target,
	.targetsize	= sizeof(struct ipt_log_info),
	.checkentry	= ipt_log_checkentry,
	.me		= THIS_MODULE,
};

static struct nf_logger ipt_log_logger ={
	.name		= "ipt_SYSLOG",
	.logfn		= &ipt_log_packet,
	.me		= THIS_MODULE,
};


static int ip_syslogstat_show(struct seq_file *m, void *v)
{
	spin_lock_bh(&log_lock);

	seq_printf(m,
		      "Counter           : %u\n"
		      "Queue length      : %u\n"
		      "Queue max. length : %u\n"
		      "Queue dropped     : %u\n",
		      counter,
		      loglist_total,
		      loglist_maxlen,
		      loglist_dropped);

	spin_unlock_bh(&log_lock);
	return 0;
}

static int ip_syslogstat_open(struct inode *inode, struct file *file)
{
        return single_open(file, ip_syslogstat_show, NULL);
}

static const struct file_operations ip_syslogstat_proc_fops = {
	.open		= ip_syslogstat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

static int syslog_connect(struct socket **socket)
{
	int ret = 0;
	int retry = 0;
	int logtype = SOCK_DGRAM;
	struct sockaddr_un syslog_server;

	while (retry < 2)
	{
		ret = sock_create_kern(PF_UNIX, logtype, 0, socket);
		if (ret < 0)
			break;

		syslog_server.sun_family = PF_UNIX;
		strcpy(syslog_server.sun_path , "/dev/log");
		ret = kernel_connect(*socket, (struct sockaddr *)&syslog_server, sizeof(struct sockaddr_un) - 1, 0);
		if (ret < 0)
		{
			if (ret == -EPROTOTYPE)
			{
				logtype = (logtype == SOCK_DGRAM ? SOCK_STREAM : SOCK_DGRAM);
			}
			retry++;
			goto cleanup_sock;
		}

		(*socket)->sk->sk_allocation = GFP_NOIO;
		return ret;

cleanup_sock:
		sock_release(*socket);
		*socket = NULL;
	}

	return ret;
}

static void syslog_close(struct socket **socket)
{
	kernel_sock_shutdown(*socket, SHUT_RDWR);
	sock_release(*socket);
	*socket = NULL;
}

static int __init ipt_log_init(void)
{
	int ret;
	struct proc_dir_entry *proc;

	ret = xt_register_target(&ipt_log_reg);
	if (ret < 0)
		return ret;

	proc = create_proc_entry(STAT_PROC_FS_NAME, 0, init_net.proc_net);
	if (proc) {
		proc->owner = THIS_MODULE;
		proc->proc_fops = &ip_syslogstat_proc_fops;
	} else {
		printk(KERN_ERR "ip_SYSLOG: failed to create proc entry\n");
		goto cleanup_target;
	}

	ret = syslog_connect(&sl_socket);
	if (ret < 0)
	{
		if (ret == -ECONNREFUSED)
		{
			timer.expires = jiffies + msecs_to_jiffies(reconnect_freq);
			add_timer(&timer);
		}
		else
			goto cleanup_proc;
	}

	nf_log_register(PF_INET, &ipt_log_logger);
	return 0;

cleanup_proc:
	proc_net_remove(&init_net, STAT_PROC_FS_NAME);
cleanup_target:
	xt_unregister_target(&ipt_log_reg);
	return ret;
}

static void __exit ipt_log_fini(void)
{
	nf_log_unregister(&ipt_log_logger);

	/* remove timer, if it is pending */
	if (timer_pending(&timer))
		del_timer(&timer);

	flush_scheduled_work();

	syslog_close(&sl_socket);
	if (loglist_total > 0)
		printk(KERN_WARNING "ip_SYSLOG: dropping %d log(s). Dropped: %d\n", loglist_total, loglist_dropped + loglist_total);

	proc_net_remove(&init_net, STAT_PROC_FS_NAME);
	xt_unregister_target(&ipt_log_reg);
}

module_init(ipt_log_init);
module_exit(ipt_log_fini);
