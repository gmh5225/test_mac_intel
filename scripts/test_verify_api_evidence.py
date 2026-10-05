import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import verify_api_evidence as verify


class EvidenceReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo=Path(os.environ.get('HVF_EVIDENCE_REPOSITORY',Path(__file__).resolve().parents[1]))
        cls.root=cls.repo/'results/2026-10-05-api-lifecycle'
        cls.files=verify.verified_files(cls.root/'37262095705')
        cls.audit=verify.decode(cls.files['audit.json'])
        cls.plan=verify.decode(cls.files['prepared/plan.json'])
        cls.contract=verify.load_contract(cls.repo,cls.plan)

    def test_all_retained_attempts_replay_without_promoting_unknowns(self):
        summary=verify.decode((self.root/'summary.json').read_bytes())
        results=[verify.verify_run(self.repo,self.root,record) for record in summary['runs']]
        first=next(result for result in results if result['run_id']=='37256339176')
        self.assertIsNone(first['native_passed'])
        self.assertTrue(first['child_retired'])
        self.assertEqual(first['completed_iterations'],411)

    def test_plan_only_has_unknown_counts_and_retirement(self):
        audit={**self.audit,'native_passed':None,'child_retired':None,'output_sha256':None}
        result=verify.verify_native({},audit,self.plan,self.contract)
        self.assertIsNone(result['completed_iterations'])
        self.assertIsNone(result['child_retired'])
        for name in ('failure-analysis.json','accounting-analysis.json','result.json','native-status.json'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                verify.verify_native({name:self.files[name]},audit,self.plan,self.contract)

    def test_stale_analysis_cannot_borrow_matching_raw_hash(self):
        for name,key,value in [('failure-analysis.json','completed_iterations',1000),
                ('failure-analysis.json','output_sha256','0'*64),
                ('accounting-analysis.json','event_version',4),
                ('accounting-analysis.json','guest','halt')]:
            files=dict(self.files)
            modified=verify.decode(files[name]);modified[key]=value
            files[name]=json.dumps(modified).encode()
            with self.subTest(name=name,key=key),self.assertRaises(ValueError):
                verify.verify_native(files,self.audit,self.plan,self.contract)

    def test_source_protocol_status_and_digest_cannot_be_relabelled(self):
        for key,value in [('event_version',4),('command',['wrong'])]:
            plan={**self.plan,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):
                verify.verify_native(self.files,self.audit,plan,self.contract)
        for key,value in [('output_sha256','0'*64),('native_passed',True),('child_retired',False)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                verify.verify_native(self.files,{**self.audit,key:value},self.plan,self.contract)
        with self.assertRaises(ValueError):
            verify.load_contract(self.repo,{**self.plan,'source_commit':'0'*40,'workflow_commit':'0'*40})

    def test_file_hashes_extra_files_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=b'original'
            (root/'output.log').write_bytes(payload)
            index={'output.log':{'sha256':verify.sha(payload)}}
            (root/'files.json').write_text(json.dumps(index))
            self.assertEqual(verify.verified_files(root),{'output.log':payload})
            (root/'output.log').write_bytes(b'edited')
            with self.assertRaises(ValueError):verify.verified_files(root)
            (root/'output.log').write_bytes(payload)
            (root/'borrowed-analysis.json').write_text('{}')
            with self.assertRaises(ValueError):verify.verified_files(root)
            index['../outside']={'sha256':'0'*64}
            (root/'files.json').write_text(json.dumps(index))
            with self.assertRaises(ValueError):verify.verified_files(root)

    def test_borrowed_check_run_or_annotation_is_rejected(self):
        snapshot=verify.decode(self.files['github-status.json'])
        run=snapshot['run'];job=snapshot['jobs']['jobs'][0];url=job['check_run_url']
        check={'id':job['id'],'url':url,'html_url':job['html_url'],'head_sha':run['head_sha'],
            'check_suite':{'id':run['check_suite_id']},'name':job['name'],
            'status':'completed','conclusion':job['conclusion'],
            'output':{'annotations_url':url+'/annotations','annotations_count':0}}
        envelope={'kind':'GitHub-job-check-annotations','run_id':str(run['id']),
            'run_attempt':run['run_attempt'],'head_sha':run['head_sha'],
            'checks':[{'job_id':job['id'],'endpoint':url,'check_run':check,'annotations':[]}]}
        verify.verify_check_annotations(snapshot,envelope,[])
        with self.assertRaises(ValueError):
            verify.verify_check_annotations(snapshot,envelope,[{'message':'The hosted runner lost communication with the server'}])
        for field,value in [('id',1),('head_sha','0'*40),('check_suite',{'id':1})]:
            changed=copy.deepcopy(envelope);changed['checks'][0]['check_run'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                verify.verify_check_annotations(snapshot,changed,[])

    def test_summary_cannot_claim_supplemental_facts_without_sidecar(self):
        summary=verify.decode((self.root/'summary.json').read_bytes())
        record=copy.deepcopy(next(record for record in summary['runs'] if record['run_id']=='37259797988'))
        record['supplemental_failure_analysis']={'completed_iterations':781}
        with self.assertRaises(ValueError):verify.verify_run(self.repo,self.root,record)

    def test_full_plan_contract_rejects_guest_helper_and_budget_relabelling(self):
        engine=verify.full_audit
        engine.HARNESS=self.repo;engine.BASE=self.root;engine.WORKFLOW=self.audit['workflow_commit']
        prepared={name.removeprefix('prepared/'):content for name,content in self.files.items()
                  if name.startswith('prepared/')}
        run=verify.decode(self.files['github-status.json'])['run']
        for key,value in [('guest','halt'),('helper_commit','0'*40),('timeout_seconds',900),
                           ('guest_hex','a30002f4'),('command',['wrong'])]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                engine.check_plan({**self.plan,key:value},prepared,run)

    def test_full_audit_rejects_over_budget_or_incomplete_success(self):
        engine=verify.full_audit;engine.HARNESS=self.repo;engine.BASE=self.root
        run_id='37259797988'
        manifest=verify.decode((self.root/run_id/'artifacts.json').read_bytes())
        final=next(item for item in manifest if item['name'].endswith('-final'))
        original_zip=zipfile.ZipFile
        for name,key,value in [('native-status.json','elapsed_seconds',601),
                ('controller-status.json','exit_status',143),
                ('controller-status.json','termination_reason','deadline'),
                ('uploads/plan.json','exit_status',1),('children.json','process_groups',[1])]:
            class ChangedArchive:
                def __init__(self,path):self.inner=original_zip(path);self.changed=Path(path).stem==str(final['id'])
                def __enter__(self):return self
                def __exit__(self,*args):self.inner.close()
                def namelist(self):return self.inner.namelist()
                def read(self,member):
                    content=self.inner.read(member)
                    if self.changed and member==name:
                        record=verify.decode(content);record[key]=value;return json.dumps(record).encode()
                    return content
            with self.subTest(name=name,key=key),patch.object(engine.zipfile,'ZipFile',ChangedArchive),self.assertRaises(ValueError):
                engine.audit_run(run_id)

    def test_artifact_origin_and_summary_rounds_cannot_be_borrowed(self):
        summary=verify.decode((self.root/'summary.json').read_bytes())
        record=copy.deepcopy(next(record for record in summary['runs'] if record['run_id']=='37259797988'))
        record['native_audit']['iterations']=9999
        with self.assertRaises(ValueError):verify.verify_run(self.repo,self.root,record)
        record=next(record for record in summary['runs'] if record['run_id']=='37259797988')
        index_path=self.root/record['run_id']/'files.json'
        index=verify.decode(index_path.read_bytes());index['output.log']['artifact_id']=1
        original_read=Path.read_bytes
        def changed(path):return json.dumps(index).encode() if path==index_path else original_read(path)
        with patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
            verify.verify_run(self.repo,self.root,record)

    def test_plan_only_cannot_retain_fabricated_native_audit_fields(self):
        summary=verify.decode((self.root/'summary.json').read_bytes())
        for record in summary['runs']:
            if record['run_id'] not in ('37263893167','37263895410'):continue
            files=verify.verified_files(self.root/record['run_id'])
            for key,value in [('native_status',{'status':0}),('native_audit',{'iterations':1000}),
                              ('final_native_result_present',True)]:
                changed=dict(files);audit=verify.decode(changed['audit.json']);audit[key]=value
                changed['audit.json']=json.dumps(audit).encode()
                with self.subTest(run=record['run_id'],key=key),patch.object(verify,'verified_files',return_value=changed),self.assertRaises(ValueError):
                    verify.verify_run(self.repo,self.root,record)

    def test_removing_artifact_origin_cannot_hide_changed_process_status(self):
        summary=verify.decode((self.root/'summary.json').read_bytes())
        record=next(record for record in summary['runs'] if record['run_id']=='37259797988')
        directory=self.root/record['run_id'];index_path=directory/'files.json'
        controller_path=directory/'controller-status.json'
        controller=verify.decode(controller_path.read_bytes())
        controller.update(exit_status=143,termination_reason='deadline')
        changed_controller=json.dumps(controller).encode()
        index=verify.decode(index_path.read_bytes())
        index['controller-status.json']={'sha256':verify.sha(changed_controller),'origin':'local metadata'}
        original_read=Path.read_bytes
        def changed(path):
            if path==index_path:return json.dumps(index).encode()
            if path==controller_path:return changed_controller
            return original_read(path)
        with patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
            verify.verify_run(self.repo,self.root,record)


if __name__=='__main__':unittest.main()
