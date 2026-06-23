#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include "minifirewall-def.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mini Firewall Kernel Module");
MODULE_AUTHOR("Vivek Shankar");

static struct proc_dir_entry *proc_entry;
static struct FirewallRule *pHead, *pTail, *pIndex;
static int iMaxID;
static struct nf_hook_ops nfho_prerouting, nfho_localin, nfho_localout, nfho_postrouting;

// Function Prototypes
ssize_t mod_write(struct file *file, const char __user *buff, size_t len, loff_t *off);
ssize_t mod_read(struct file *file, char __user *page, size_t count, loff_t *off);
ssize_t delete_rule(struct FirewallRule *pRule);
int init_nf_module(void);
void cleanup_nf_module(void);

static const struct proc_ops minifirewall_proc_ops = {
    .proc_read = mod_read,
    .proc_write = mod_write,
    .proc_lseek = default_llseek,
};

int init_minifirewall_module(void)
{
    proc_entry = proc_create("minifirewall", 0644, NULL, &minifirewall_proc_ops);
    if (!proc_entry) return -ENOMEM;

    pHead = pTail = pIndex = NULL;
    iMaxID = 0;

    init_nf_module();
    printk(KERN_INFO "minifirewall: Module loaded\n");
    return 0;
}

void cleanup_minifirewall_module(void)
{
    struct FirewallRule *pCurr = NULL;
    cleanup_nf_module();
    remove_proc_entry("minifirewall", NULL);
    for (pCurr = pHead; pCurr != NULL;) {
        struct FirewallRule *pTemp = pCurr;
        pCurr = pCurr->m_pNext;
        vfree(pTemp);
    }
    printk(KERN_INFO "minifirewall: Module unloaded.\n");
}

module_init(init_minifirewall_module);
module_exit(cleanup_minifirewall_module);

ssize_t mod_read(struct file *file, char __user *page, size_t count, loff_t *off)
{
    if (*off > 0 || !pHead) return 0;
    if (!pIndex) pIndex = pHead;
    if (copy_to_user(page, pIndex, sizeof(struct FirewallRule))) return -EFAULT;
    *off += sizeof(struct FirewallRule);
    pIndex = pIndex->m_pNext;
    return sizeof(struct FirewallRule);
}

ssize_t delete_rule(struct FirewallRule *pRule)
{
    struct FirewallRule *pCurr = NULL;
    for (pCurr = pHead; pCurr != NULL; pCurr = pCurr->m_pNext) {
        if (pRule->m_iID == pCurr->m_iID) {
            if (pCurr == pHead) pHead = pCurr->m_pNext;
            if (pCurr == pTail) pTail = pCurr->m_pPrev;
            if (pCurr->m_pPrev) pCurr->m_pPrev->m_pNext = pCurr->m_pNext;
            if (pCurr->m_pNext) pCurr->m_pNext->m_pPrev = pCurr->m_pPrev;
            vfree(pCurr);
            return 0;
        }
    }
    return -EFAULT;
}

ssize_t mod_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
    struct FirewallRule* pRule = vmalloc(sizeof(struct FirewallRule));
    if (!pRule) return -ENOMEM;
    if (copy_from_user(pRule, buff, len)) { vfree(pRule); return -EFAULT; }
    if (pRule->m_bDeleted == 1) { delete_rule(pRule); vfree(pRule); }
    else {
        if (!pHead) { pHead = pTail = pRule; }
        else { pTail->m_pNext = pRule; pRule->m_pPrev = pTail; pTail = pRule; }
        pRule->m_iID = ++iMaxID;
    }
    return len;
}

unsigned int check_rules(int bInput, unsigned int proto, unsigned int saddr, unsigned int sport, unsigned int daddr, unsigned int dport)
{
    struct FirewallRule *pCurr;
    for (pCurr = pHead; pCurr != NULL; pCurr = pCurr->m_pNext) {
        if (pCurr->m_bInput == bInput && (pCurr->m_iProtocol == 0 || pCurr->m_iProtocol == proto)) {
            if (pCurr->m_bBlock == 1) return NF_DROP;
            else return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
}

unsigned int hook_prerouting(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
    struct iphdr *ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;
    return check_rules(1, ip_header->protocol, ip_header->saddr, 0, ip_header->daddr, 0);
}

unsigned int hook_postrouting(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*))
{
    struct iphdr *ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;
    return check_rules(0, ip_header->protocol, ip_header->saddr, 0, ip_header->daddr, 0);
}

unsigned int hook_localin(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*)) { return NF_ACCEPT; }
unsigned int hook_localout(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*)) { return NF_ACCEPT; }

int init_nf_module(void)
{
    nfho_prerouting.hook = hook_prerouting;
    nfho_prerouting.hooknum = NF_INET_PRE_ROUTING;
    nfho_prerouting.pf = PF_INET;
    nfho_prerouting.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_prerouting);

    nfho_localin.hook = hook_localin;
    nfho_localin.hooknum = NF_INET_LOCAL_IN;
    nfho_localin.pf = PF_INET;
    nfho_localin.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_localin);

    nfho_localout.hook = hook_localout;
    nfho_localout.hooknum = NF_INET_LOCAL_OUT;
    nfho_localout.pf = PF_INET;
    nfho_localout.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_localout);

    nfho_postrouting.hook = hook_postrouting;
    nfho_postrouting.hooknum = NF_INET_POST_ROUTING;
    nfho_postrouting.pf = PF_INET;
    nfho_postrouting.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_postrouting);

    return 0;
}

void cleanup_nf_module(void)
{
    nf_unregister_hook(&nfho_prerouting);
    nf_unregister_hook(&nfho_localin);
    nf_unregister_hook(&nfho_localout);
    nf_unregister_hook(&nfho_postrouting);
}
