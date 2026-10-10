#!/usr/bin/env python3
"""Compile actual DSCP classifier statements with CT/skb mocks, without I/O.

Usage: python3 test_directional_qos.py --source /path/to/qca-nss-ecm
Works with QSDK 12.5 30fbfa4 and QSDK 14.0 7894b769. A failed result on an
unmodified source is intentional. This is not a firmware or full-module test.
"""
import argparse, hashlib, json, pathlib, subprocess, tempfile
import re

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', required=True, type=pathlib.Path)
parser.add_argument('--output', type=pathlib.Path)
args=parser.parse_args()
file=args.source/'ecm_classifier_dscp.c'
source=file.read_text()

def block(text, anchor):
    start=text.index(anchor)
    opening=text.index('{',start)
    depth=1;end=opening+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]

helpers=[]
for name in ['ecm_classifier_dscp_is_bidi_packet_seen','ecm_classifier_dscp_fill_info']:
    definition=re.search(r'(?m)^static[^\n]*\b'+re.escape(name)+r'\(', source)
    if definition is None:
        raise RuntimeError('Missing definition: '+name)
    helpers.append(block(source,definition.group()))
protocol=block(source,'\tif (protocol == IPPROTO_TCP) {')
end=source.index('done:',source.index(protocol))+len('done:')
# Include the UDP else branch, the done-label, and actual IGS direction code.
begin=source.index(protocol)
end=source.index('#endif',source.index('#ifdef ECM_CLASSIFIER_DSCP_IGS',end))+len('#endif')
statements=source[begin:end]
stub=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DEBUG_TRACE(...) ((void)0)
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_CT_DIR_ORIGINAL 0
#define IP_CT_DIR_REPLY 1
#define CTINFO2DIR(x) ((x)>=3 ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL)
#define ECM_TRACKER_SENDER_TYPE_SRC 0
#define ECM_TRACKER_SENDER_TYPE_DEST 1
#define ECM_CONN_DIR_FLOW 0
#define ECM_CONN_DIR_RETURN 1
#define XT_DSCP_SHIFT 2
#define NF_CT_DSCPREMARK_EXT_PRIO 1
#define NF_CT_DSCPREMARK_EXT_DSCP 2
#define NF_CT_DSCPREMARK_EXT_MARK 8
#define ECM_CLASSIFIER_ACCELERATION_MODE_NO 0
#define ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG 1
#define ECM_CLASSIFIER_PROCESS_ACTION_MARK 2
#define ECM_CLASSIFIER_PROCESS_ACTION_IGS_QOS_TAG 4
#define NSS_IPV4_RULE_CREATE_QOS_VALID 1
#define NSS_IPV6_RULE_CREATE_QOS_VALID 1
#define NSS_IPV4_RULE_CREATE_IGS_VALID 2
#define NSS_IPV6_RULE_CREATE_IGS_VALID 2
typedef int ecm_tracker_sender_type_t;
struct response {unsigned flow_qos_tag,return_qos_tag,flow_int_pri,return_int_pri,
 flow_mark,return_mark,flow_dscp,return_dscp,process_actions,accel_mode,
 igs_flow_qos_tag,igs_return_qos_tag;};
struct ecm_classifier_dscp_instance {struct response process_response;bool packet_seen[2];};
struct ecm_tracker_ip_header {unsigned ds;};
struct sk_buff {unsigned priority,int_pri,mark;};
struct extension {unsigned flow_set_flags,return_set_flags,flow_priority,reply_priority,
 flow_int_pri,reply_int_pri,flow_mark,reply_mark,flow_dscp,reply_dscp,
 igs_flow_qos_tag,igs_reply_qos_tag;};
struct connection {bool unidir_accel_en;};
struct create_rule {struct {uint32_t flow_qos_tag,return_qos_tag;} qos_rule;
 struct {uint16_t igs_flow_qos_tag,igs_return_qos_tag;} igs_rule;unsigned valid_flags;};
'''
frontends=[]
source_hashes={file.name:hashlib.sha256(file.read_bytes()).hexdigest()}
for kind in ['ported', 'non_ported']:
    for family in ['ipv4', 'ipv6']:
        name='ecm_nss_'+kind+'_'+family+'.c'
        frontend=args.source/'frontends/nss'/name
        content=frontend.read_text()
        copies=block(content,'\tif (pr->process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {')
        copies+='\n#ifdef ECM_CLASSIFIER_DSCP_IGS\n'
        copies+=block(content,'\tif (pr->process_actions & ECM_CLASSIFIER_PROCESS_ACTION_IGS_QOS_TAG) {')
        copies+='\n#endif\n'
        frontends.append('static void create_'+kind+'_'+family+'(struct create_rule *nircm, struct response *pr) {\n'+copies+'\n}\n')
        source_hashes['frontends/nss/'+name]=hashlib.sha256(frontend.read_bytes()).hexdigest()
wrapper='''
static void process(struct ecm_classifier_dscp_instance *cdscpi,
 struct extension *dscpcte, struct sk_buff *skb, struct ecm_tracker_ip_header *ip_hdr,
 struct connection *ci, int protocol, int sender, int ctinfo,
 unsigned slow_pkts, unsigned ecm_classifier_accel_delay_pkts) {
'''+statements+'''
dscp_classifier_out:;
}
'''
tests=r'''
static unsigned checks,failures;
static void check(bool ok){checks++;if(!ok)failures++;}
static void check_create(struct response *pr) {
 void (*create[])(struct create_rule *,struct response *)={create_ported_ipv4,
  create_ported_ipv6,create_non_ported_ipv4,create_non_ported_ipv6};
 for(unsigned i=0;i<4;i++) {
  struct create_rule rule={0};create[i](&rule,pr);
  if(pr->process_actions&ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
   check(rule.qos_rule.flow_qos_tag==pr->flow_qos_tag);
   check(rule.qos_rule.return_qos_tag==pr->return_qos_tag);
   check(rule.valid_flags&NSS_IPV4_RULE_CREATE_QOS_VALID);
  }else check(rule.valid_flags==0);
#ifdef ECM_CLASSIFIER_DSCP_IGS
  if(pr->process_actions&ECM_CLASSIFIER_PROCESS_ACTION_IGS_QOS_TAG) {
   check(rule.igs_rule.igs_flow_qos_tag==pr->igs_flow_qos_tag);
   check(rule.igs_rule.igs_return_qos_tag==pr->igs_return_qos_tag);
   check(rule.valid_flags&NSS_IPV4_RULE_CREATE_IGS_VALID);
  }
#endif
 }
}
int main(void) {
 unsigned priorities[][2]={{0x00160006,0x00260006},{0,0x00260006},{0x00150000,0},{0,0}};
 for(unsigned pair=0;pair<4;pair++)for(int sender=0;sender<2;sender++)
 for(int ctinfo=0;ctinfo<6;ctinfo++)for(int delay=0;delay<4;delay++) {
  struct ecm_classifier_dscp_instance c={.process_response={.flow_qos_tag=50,.return_qos_tag=51}};
  struct extension ext={.flow_set_flags=1,.return_set_flags=1,
   .flow_priority=priorities[pair][0],.reply_priority=priorities[pair][1],
   .igs_flow_qos_tag=101,.igs_reply_qos_tag=202};
  struct sk_buff skb={.priority=33,.int_pri=5,.mark=7};
  struct ecm_tracker_ip_header ip={.ds=40};struct connection ci={0};
  bool same=(sender==0&&CTINFO2DIR(ctinfo)==0)||(sender==1&&CTINFO2DIR(ctinfo)==1);
  // delay=6 exceeds slow_pkts=5 and must still deny acceleration.
  process(&c,&ext,&skb,&ip,&ci,17,sender,ctinfo,5,delay==3?6:delay);
  if(delay==0||delay==2) {
   check(c.process_response.flow_qos_tag==priorities[pair][same?0:1]);
   check(c.process_response.return_qos_tag==priorities[pair][same?1:0]);
#ifdef ECM_CLASSIFIER_DSCP_IGS
   check(c.process_response.igs_flow_qos_tag==(same?101:202));
   check(c.process_response.igs_return_qos_tag==(same?202:101));
#endif
  }else check(!(c.process_response.process_actions&ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG));
  check_create(&c.process_response);
 }
 // Without both PRIO flags, preserve the established single-packet fallback.
 for(unsigned flags=0;flags<3;flags++)for(int sender=0;sender<2;sender++) {
  struct ecm_classifier_dscp_instance c={0};
  struct extension ext={.flow_set_flags=flags&1,.return_set_flags=(flags>>1)&1,
   .flow_priority=100,.reply_priority=200};struct connection ci={0};
  struct sk_buff skb={.priority=33};struct ecm_tracker_ip_header ip={0};
  process(&c,&ext,&skb,&ip,&ci,17,sender,2,5,0);
  check(c.process_response.flow_qos_tag==33&&c.process_response.return_qos_tag==33);
 }
 // Both packets already seen: the same explicit pair must still win.
 for(int sender=0;sender<2;sender++)for(int dir=0;dir<2;dir++) {
  struct ecm_classifier_dscp_instance c={.packet_seen={true,true}};
  struct extension ext={.flow_set_flags=1,.return_set_flags=1,.flow_priority=11,.reply_priority=22};
  struct connection ci={0};struct sk_buff skb={.priority=33};struct ecm_tracker_ip_header ip={0};
  process(&c,&ext,&skb,&ip,&ci,17,sender,dir?3:2,5,2);
  bool same=(sender==0&&dir==0)||(sender==1&&dir==1);
  check(c.process_response.flow_qos_tag==(same?11:22)&&c.process_response.return_qos_tag==(same?22:11));
 }
 // TCP's established extension path is unchanged, including NAT reversal.
 for(int sender=0;sender<2;sender++)for(int dir=0;dir<2;dir++) {
  struct ecm_classifier_dscp_instance c={0};
  struct extension ext={.flow_set_flags=NF_CT_DSCPREMARK_EXT_PRIO|NF_CT_DSCPREMARK_EXT_DSCP|NF_CT_DSCPREMARK_EXT_MARK,
   .return_set_flags=NF_CT_DSCPREMARK_EXT_PRIO|NF_CT_DSCPREMARK_EXT_DSCP|NF_CT_DSCPREMARK_EXT_MARK,
   .flow_priority=11,.reply_priority=22};
  struct connection ci={0};struct sk_buff skb={.priority=33};struct ecm_tracker_ip_header ip={0};
  process(&c,&ext,&skb,&ip,&ci,6,sender,dir?3:2,5,0);
  bool same=(sender==0&&dir==0)||(sender==1&&dir==1);
  check(c.process_response.flow_qos_tag==(same?11:22)&&c.process_response.return_qos_tag==(same?22:11));
 }
 printf("{\"checks\":%u,\"failures\":%u,\"passed\":%s}\n",checks,failures,failures?"false":"true");
 return failures?1:0;
}
'''
with tempfile.TemporaryDirectory(prefix='ecm-directional-qos-') as d:
    c=pathlib.Path(d)/'test.c';binary=c.with_suffix('')
    c.write_text(stub+'\n'.join(helpers)+''.join(frontends)+wrapper+tests)
    report={'mockedCT':True,'firmwareTested':False,'fullModuleBuilt':False,
            'actualSourceHashes':source_hashes,'variants':[]}
    for igs in [False,True]:
        options=['-DECM_CLASSIFIER_DSCP_IGS=1'] if igs else []
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                        '-Wno-unused-label','-Wno-unused-parameter',*options,
                        str(c),'-o',str(binary)],check=True)
        r=subprocess.run([str(binary)],text=True,capture_output=True,check=False)
        row=json.loads(r.stdout);row['igsEnabled']=igs;report['variants'].append(row)
    report['passed']=all(row['passed'] for row in report['variants'])
    if args.output:
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report));raise SystemExit(0 if report['passed'] else 1)
