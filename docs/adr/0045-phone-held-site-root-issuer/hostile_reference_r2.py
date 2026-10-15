"""SPEC ONLY. Synthetic DATA and logical owner observations; no crypto/keys/native calls."""
import copy, hashlib, json, pathlib
P=pathlib.Path(__file__).parent
class Denied(Exception): pass
def require(x):
 if not x: raise Denied()
def enc(v):
 def head(m,n):
  if n<24:return bytes([m*32+n])
  for size,ai in [(1,24),(2,25),(4,26),(8,27)]:
   if n<1<<(size*8):return bytes([m*32+ai])+n.to_bytes(size,'big')
  raise Denied()
 if isinstance(v,int) and 0<=v<2**64:return head(0,v)
 if isinstance(v,bytes):return head(2,len(v))+v
 if isinstance(v,list):return head(4,len(v))+b''.join(map(enc,v))
 raise Denied()
def sha(v):return hashlib.sha256(v).digest()
def ref(domain,envelope):return sha(domain+b'/envelope\0'+envelope)
IADM=b'Mnemosyne/Issuer1482/root-admission/v1'
IRCS=b'Mnemosyne/Issuer1482/root-current-status/v1'
IRSP=b'Mnemosyne/Issuer1482/current-response/v1'
B={k:bytes([i])*16 for i,k in enumerate(['principal','session','device','admission','intent','scope','key'],1)}
class Ceremony:
 def __init__(self,mode='IRCS_PAIR',owner=True,initial=False,current=True,key_exists=True):
  self.binding=copy.deepcopy(B);self.mode=mode;self.current=current;self.owner=owner
  require(owner and key_exists and (mode=='IADM' and initial or mode=='IRCS_PAIR' and current))
  self.create_calls=0;self.contexts=1;self.public_lookup_context=1;self.sign_context=1
  self.armed=False;self.calls=0;self.deadline=None;self.native=None;self.terminal=False;self.pre=None
  self.readiness=[1,b'c'*16,1 if mode=='IADM' else 2,b'0'*36,b's'*16,b'Site',b'k'*32,b'a'*16,1,1,b'w'*32,999,b'owner-evidence',b'n'*32]
  self.rd=sha(enc(self.readiness));self.read_done=False
 def arm(self,binding,now=110,face=100,native_started=False,digest=None,current=True):
  require(binding==self.binding and not self.armed and not native_started and not self.terminal)
  require(0<=face<30000 and face<=now<=face+250 and current and (digest or self.rd)==self.rd)
  self.armed=True;self.deadline=now+2000;self.native=now+10
 def task(self,kind,ordinal,body,reference=b''):
  return [1,b'c'*16,kind,ordinal,body,reference,self.rd]
 def sign(self,task,digest,now,domain,body_fields,binding=None,current=True,context=1):
  require(self.armed and not self.terminal and now<self.deadline and now<self.native+2000)
  require(current and self.owner and context==self.public_lookup_context==self.sign_context)
  require((binding or self.binding)==self.binding and sha(enc(task))==digest)
  require(task[1]==b'c'*16 and task[6]==self.rd and 0<len(task[4])<=8192)
  kind,ordinal=task[2:4]
  if self.mode=='IADM':require(kind==1 and ordinal==1 and self.calls==0 and domain==IADM and task[5]==b'')
  else:
   require(domain==IRCS and len(body_fields)==11 and body_fields[0]==b'IRCS/1')
   require(body_fields[1:8]==[b'r'*32,b'a'*16,1,1,b'w'*32,0,1])
   require(body_fields[8]!=bytes(32) and len(body_fields[8])==32 and body_fields[9]==b'b'*36 and body_fields[10]>0)
   require(enc(body_fields)==task[4])
   if self.calls==0:require(kind==2 and ordinal==1 and task[5]==b'')
   else:require(self.calls==1 and kind==3 and ordinal==2 and self.read_done and task[5]==ref(IRCS,self.pre) and body_fields[8]!=self.pre_fields[8] and body_fields[10]>self.pre_fields[10])
  self.calls+=1
  # Deliberately dummy envelope: tests byte references, NEVER verifies/signs crypto.
  envelope=enc([task[4],b'k'*32,b'TEST-NOT-A-SIGNATURE'])
  if self.calls==1:self.pre=envelope;self.pre_fields=body_fields
  if self.mode=='IADM' or self.calls==2:self.terminal=True
  return envelope
 def read(self):require(self.calls==1 and not self.terminal);self.read_done=True
 def ambiguous(self):self.terminal=True
 def restart(self):self.terminal=True

def fields(nonce=b'1'*32,serial=1):return [b'IRCS/1',b'r'*32,b'a'*16,1,1,b'w'*32,0,1,nonce,b'b'*36,serial]
def ready():
 m=Ceremony();m.arm(B);return m
def sign(m,kind=2,ordinal=1,f=None,reference=b'',now=200,domain=IRCS,**kw):
 f=fields() if f is None else f;t=m.task(kind,ordinal,enc(f),reference)
 return m.sign(t,sha(enc(t)),now,domain,f,**kw)
def run():
 checks=[]
 def deny(name,call):
  try:call()
  except Denied:checks.append(name)
  else:raise AssertionError(name)
 for key in B:
  b=copy.deepcopy(B);b[key]=b'foreign';m=Ceremony();deny('handoff_swap_'+key,lambda:m.arm(b))
  m=ready();deny('task_swap_'+key,lambda:sign(m,binding=b))
 for index,value in [(1,b'foreign'),(2,3),(3,2),(5,b'x'*32),(6,b'x'*32)]:
  m=ready();t=m.task(2,1,enc(fields()));d=sha(enc(t));t[index]=value
  deny('task_metadata_digest_'+str(index),lambda:m.sign(t,d,200,IRCS,fields()))
 for index in range(1,14):
  m=Ceremony();old=m.rd;m.readiness[index]=b'swapped';m.rd=sha(enc(m.readiness))
  deny('readiness_complete_record_'+str(index),lambda:m.arm(B,digest=old))
 deny('missing_current_owner',lambda:Ceremony(owner=False))
 deny('missing_current_IADM_for_IRCS',lambda:Ceremony(current=False))
 deny('missing_existing_key_no_creation',lambda:Ceremony(key_exists=False))
 m=Ceremony('IADM',initial=True,current=False);m.arm(B);t=m.task(1,1,b'canonical-IADM21-DATA');m.sign(t,sha(enc(t)),200,IADM,[]);assert m.calls==1 and m.create_calls==0;checks.append('acyclic_initial_IADM_without_current_IADM_MODEL_ONLY')
 deny('initial_without_independent_provision',lambda:Ceremony('IADM',initial=False,current=False))
 m=Ceremony();deny('prephase_overlaps_J_original_clock',lambda:m.arm(B,native_started=True))
 m=Ceremony();deny('expired_arm',lambda:m.arm(B,now=351))
 m=Ceremony();deny('prephase_expiry_equality',lambda:m.arm(B,now=30000,face=30000))
 m=ready();deny('original_phone_expiry_equality',lambda:sign(m,now=2110))
 m=ready();m.native=-2000;deny('server_original_expiry_independent',lambda:sign(m))
 m=ready();deny('current_authority_lost_after_arm',lambda:sign(m,current=False))
 m=ready();deny('second_LAContext_lookup_or_sign',lambda:sign(m,context=2))
 m=ready();deny('wrong_domain',lambda:sign(m,domain=IADM))
 for index,value in [(1,b'foreign'*5),(2,b'z'*16),(3,2),(4,2),(5,b'z'*32),(6,1),(7,2),(9,b'z'*36)]:
  f=fields();f[index]=value;m=ready();deny('IRCS_context_field_'+str(index),lambda:sign(m,f=f))
 m=ready();pre=sign(m);m.read();f=fields(b'2'*32,2);sign(m,3,2,f,ref(IRCS,pre),300);assert m.calls==2;checks.append('two_IRCS_complete_envelope_link_MODEL_ONLY')
 deny('third_signature',lambda:sign(m,3,2,f,ref(IRCS,pre),400))
 m=ready();pre=sign(m);deny('post_without_actual_read',lambda:sign(m,3,2,f,ref(IRCS,pre),300));m.read()
 deny('body_only_pre_reference',lambda:sign(m,3,2,f,sha(enc(fields())),300))
 deny('IRSP_reference_cannot_substitute_IRCS',lambda:sign(m,3,2,f,ref(IRSP,pre),300))
 deny('same_nonce',lambda:sign(m,3,2,fields(serial=2),ref(IRCS,pre),300))
 deny('serial_not_later',lambda:sign(m,3,2,fields(b'2'*32,1),ref(IRCS,pre),300))
 for operation in ['ambiguous','restart']:
  m=ready();getattr(m,operation)();deny(operation+'_no_resign',lambda:sign(m))
 m=ready();m.arm if False else None;deny('replay_arm',lambda:m.arm(B))
 assert ref(IRCS,b'e1')!=ref(IRCS,b'e2')!=ref(IRSP,b'e2');checks.append('domain_complete_envelope_reference_distinction')
 return {'status':'PASS_LOGICAL_SPEC_ASSERTIONS_ONLY','count':len(checks),'checks':checks,'limitations':['Synthetic logical owner facts are TEST ONLY, not provenance or enrollment proof','No signature verification, key/FaceID/TLS/native/durable IO execution','Not product implementation or accepted ADR','IADM21 structural/crypto parser is existing separate product; dummy body in initial-mode sequencing test is not parser evidence'],'candidate_sha256':sha((P/'PHONE_SITE_ROOT_ISSUER_PROTOCOL_CANDIDATE_R2.json').read_bytes()).hex()}
if __name__=='__main__':
 r=run();(P/'HOSTILE_REFERENCE_R2_RECEIPT.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'count':r['count']}))
