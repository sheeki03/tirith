#!/usr/bin/env python3
"""Pure producer controls: no product, daemon, network, clock mutation or child launch."""
import importlib.util,json,os,socket,sys,tempfile,unittest
from pathlib import Path
sys.dont_write_bytecode=True
base=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('expiry_control',base/'qualify-daemon-trust-expiry.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
w=m.load(base / 'measure-daemon-workloads.py',m.WORKLOAD_SHA,'expiry_control_transport')
ID='668b289e-2b24-478b-8757-2cf7b41bca23'
class Controls(unittest.TestCase):
 def test_clock_accepts_elapsed_time_and_refuses_jumps(self):
  a={'wall_seconds':1000,'monotonic_seconds':50}
  m.clock_delta(a,{'wall_seconds':1060.01,'monotonic_seconds':110})
  for b in ({'wall_seconds':1061,'monotonic_seconds':110},{'wall_seconds':999,'monotonic_seconds':110},{'wall_seconds':1060,'monotonic_seconds':49}):
   with self.assertRaisesRegex(RuntimeError,'clock jump'):m.clock_delta(a,b)
 def test_actual_minute_window_requires_future_deadline(self):
  before={'wall_seconds':1000};after={'wall_seconds':1001}
  m.expiry_window({'expires_at':'1970-01-01T00:17:40+00:00'},before,after)
  for stamp in ('1970-01-01T00:17:39','1970-01-01T00:17:00+00:00','1970-01-01T00:18:00+00:00'):
   with self.assertRaises(RuntimeError):m.expiry_window({'expires_at':stamp},before,after)
 def test_semantics_require_only_the_exact_blocker(self):
  p=Path('/owned/policy.yaml')
  value={'action':'block','findings':[{'rule_id':'shortened_url','severity':'HIGH'}], 'tier_reached':3,'urls_extracted_count':1,'bypass_honored':False,'policy_path_used':str(p)}
  m.semantic(w,value,1,p,False)
  m.semantic(w,{**value,'action':'allow','findings':[]},0,p,True)
  for delta in ({'action':'allow'},{'findings':[]},{'findings':value['findings']+[{'rule_id':'homograph','severity':'HIGH'}]},{'bypass_honored':True},{'policy_path_used':'/wrong'},{'policy_diagnostics':['error']},{'urls_extracted_count':0}):
   with self.assertRaises(RuntimeError):m.semantic(w,{**value,**delta},1,p,False)
 def test_mutation_requires_same_canonical_identity_and_real_change(self):
  value={'schema_version':1,'kind':'trust_expiry_change','state':'effective','grant_id':ID,'operation_id':ID}
  self.assertEqual(m.mutation(value,{'exit':0},'trust_expiry_change','effective',ID),ID)
  for delta in ({'grant_id':ID.upper()},{'state':'recorded'},{'no_op':True},{'error':'conflict'},{'grant_id':'d79aff14-3408-48eb-8a38-d3a8ef5f6923'}):
   with self.assertRaises((RuntimeError,ValueError)):m.mutation({**value,**delta},{'exit':0},'trust_expiry_change','effective',ID)
 def test_store_requires_exact_scope_and_detects_generation_replacement(self):
  with tempfile.TemporaryDirectory(prefix='texp-controls-',dir='/tmp') as tmp:
   p=Path(tmp)/'trust-grants.json'
   grant={'id':ID,'pattern':m.URL,'rule_id':'shortened_url','scope':{'kind':'user'},'created_at':'2026-09-28T00:00:00Z','expires_at':'2026-09-28T00:01:00Z'}
   raw=json.dumps({'schema_version':1,'grants':[grant]}).encode();p.write_bytes(raw);p.chmod(0o600)
   first=m.store_record(w,p,ID);self.assertEqual(first,m.store_record(w,p,ID))
   replacement=p.with_name('replacement');replacement.write_bytes(raw);replacement.chmod(0o600);replacement.replace(p)
   second=m.store_record(w,p,ID);self.assertEqual(first['sha256'],second['sha256']);self.assertNotEqual(first['generation'],second['generation'])
   p.write_text(json.dumps({'schema_version':1,'grants':[{**grant,'scope':{'kind':'project'}}]}))
   with self.assertRaisesRegex(RuntimeError,'scope'):m.store_record(w,p,ID)
   p.write_bytes(raw);p.chmod(0o644)
   with self.assertRaisesRegex(RuntimeError,'ownership/mode'):m.store_record(w,p,ID)
 def test_duplicate_and_additional_grants_refused(self):
  with tempfile.TemporaryDirectory(prefix='texp-controls-',dir='/tmp') as tmp:
   p=Path(tmp)/'trust-grants.json';p.write_text('{"schema_version":1,"schema_version":1,"grants":[]}');p.chmod(0o600)
   with self.assertRaisesRegex(RuntimeError,'duplicate'):m.store_record(w,p,ID)
   p.write_text('{"schema_version":1,"grants":[{},{}]}')
   with self.assertRaisesRegex(RuntimeError,'single-grant'):m.store_record(w,p,ID)
 def test_storage_only_allows_one_exact_owned_socket(self):
  with tempfile.TemporaryDirectory(prefix='texp-controls-',dir='/tmp') as tmp:
   root=Path(tmp);path=root/'daemon.sock';other=root/'wrong.sock'
   with socket.socket(socket.AF_UNIX) as sock:
    sock.bind(str(path));w.storage(root,allowed_socket=path)
    with self.assertRaisesRegex(RuntimeError,'special file'):w.storage(root)
    with self.assertRaisesRegex(RuntimeError,'special file'):w.storage(root,allowed_socket=other)
   path.unlink()
   (root/'alias').symlink_to('/tmp')
   with self.assertRaisesRegex(RuntimeError,'special file'):w.storage(root,allowed_socket=path)
 def test_pins_and_protocol_bounds_are_explicit(self):
  self.assertTrue(m.pin(m.WORKLOAD_SHA));self.assertTrue(m.pin(m.NATIVE_SHA))
  self.assertEqual(m.DEADLINE,150);self.assertEqual(m.MAX_CHILDREN,12);self.assertEqual(m.MAX_REQUESTS,16)
  self.assertEqual(m.CAPTURE,65536);self.assertIn(b'auto_update_hours: 0',m.POLICY)
  self.assertEqual(m.COMMAND,'curl --head '+m.URL)
if __name__=='__main__':unittest.main(verbosity=2)
