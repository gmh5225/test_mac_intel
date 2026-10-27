"""Native source-only build controls for an admitted musl compiler profile."""
from pathlib import Path
import argparse,hashlib,json,shutil
from sdk import sha,profile
from role_acceptance import original_input
from client_build import build
from role_process import RoleProcess


def main():
 p=argparse.ArgumentParser();p.add_argument('--arch',required=True,choices=['arm64','x64'])
 for name in ['sdk','private','output']:p.add_argument('--'+name,required=True,type=Path)
 compiler=p.add_mutually_exclusive_group(required=True);compiler.add_argument('--baseline',type=Path);compiler.add_argument('--engine',type=Path)
 a=p.parse_args();private=a.private.resolve();private.mkdir();out=a.output.resolve();out.mkdir();assert not private.is_relative_to(out) and not out.is_relative_to(private)
 receipt=dict(status='started',arch=a.arch,baseline_compiler_control_only=a.engine is None,complete_source_engine_admitted=False,original_executed=False,
  original_or_source_or_client_files_uploaded=False,actual_original_client_correspondence=False,goal_complete=False)
 try:
  if a.engine is not None:
   from source_engine import qualify
   receipt['source_engine']=qualify(a.arch,a.engine.resolve());receipt['complete_source_engine_admitted']=True;compiler=a.engine.resolve()/'bun'
  else:compiler=a.baseline.resolve()
  original,pin=original_input(a.arch,private);receipt['original_pin']=pin
  def rebuild(label,workspace=None):
   return build(a.arch,original if workspace is None else None,compiler,a.sdk.resolve(),private/label,private/(label+'-logs'),workspace,baseline_control=a.engine is None)
  first=rebuild('published-build');workspace=private/'source-only-workspace';workspace.mkdir()
  for layout in ['preserved','readable']:shutil.copytree(private/'published-build'/layout/'sources',workspace/layout/'sources')
  repeat=rebuild('source-only-rebuild',workspace);assert not repeat['original_input_supplied']
  for layout in ['preserved','readable']:assert first['clients'][layout]['sha256']==repeat['clients'][layout]['sha256']
  edited=private/'edited-workspace';shutil.copytree(workspace,edited);entry=edited/'readable/sources/m6';raw=entry.read_bytes();assert raw.count(b'(Claude Code)')==1
  entry.write_bytes(raw.replace(b'(Claude Code)',b'(Claude Code recovery source control)'))
  changed=rebuild('edited-source-only-rebuild',edited);assert not changed['original_input_supplied']
  assert changed['clients']['preserved']['sha256']==repeat['clients']['preserved']['sha256'] and changed['clients']['preserved']['intentionally_edited_modules']==[]
  assert changed['clients']['readable']['sha256']!=repeat['clients']['readable']['sha256'] and changed['clients']['readable']['intentionally_edited_modules']==[6]
  def mapping(path):return [line.split('\t') for line in path.read_text().splitlines()]
  for layout in ['preserved','readable']:
   before=mapping(private/'source-only-rebuild'/layout/'readback/mapping.tsv');after=mapping(private/'edited-source-only-rebuild'/layout/'readback/mapping.tsv')
   assert len(before)==len(after)==2589 and [i for i,(x,y) in enumerate(zip(before,after)) if x!=y]==([6] if layout=='readable' else [])
  version_logs=private/'version-records';version_logs.mkdir();base=private/'published-build'
  process=RoleProcess(a.arch,first['runtime_image'],base/'tools/guard',base/'runtime-sdk',base/'musl-loader.path',base/'inbox',version_logs,profile(a.arch))
  versions=[]
  for kind,record in [('published-build',first),('source-only-rebuild',repeat),('edited-source-only-rebuild',changed)]:
   for layout in ['preserved','readable']:
    label=kind+'-'+layout
    control=process.execute(label+'-owned-profile',base/'tools/source-compiler',['-e','console.log(JSON.stringify({arch:process.arch,message:"owned musl version profile"}))'],argv0='bun')
    assert control['exit_code']==0 and not control['stderr'] and json.loads(control['stdout'])==dict(arch=a.arch,message='owned musl version profile')
    candidate=process.execute(label+'-version',Path(record['clients'][layout]['path']),['--version'],argv0='claude')
    expected=b'2.1.296 (Claude Code recovery source control)\n' if kind=='edited-source-only-rebuild' and layout=='readable' else b'2.1.296 (Claude Code)\n'
    assert candidate['exit_code']==0 and not candidate['stderr'] and candidate['stdout']==expected
    versions.append(dict(build=kind,layout=layout,owned_control=control['row'],client=candidate['row'],expected_stdout_hex=expected.hex()))
  assert len(versions)==6
  # All version streams have a fixed authored oracle; no build error logs or
  # captured bodies enter public output. Readback tables contain metadata only.
  shutil.copytree(version_logs,out/'validated-version-records')
  for kind,record in [('published-build',first),('source-only-rebuild',repeat),('edited-source-only-rebuild',changed)]:
   (out/(kind+'.json')).write_text(json.dumps(record,indent=2)+'\n')
   for layout in ['preserved','readable']:shutil.copyfile(private/kind/layout/'readback/mapping.tsv',out/(kind+'-'+layout+'-mapping.tsv'))
  receipt.update(status='both_native_musl_baseline_source_layouts_rebuilt_without_original_and_single_entry_edit_controlled' if a.engine is None else 'both_native_musl_complete_source_layouts_rebuilt_without_original_and_single_entry_edit_controlled',
   native_target_CPU=True,independent_builds_byte_equal=True,all_2589_rows_readback_each_layout=True,edited_only_module=6,
   all_other_2588_rows_unchanged=True,source_only_rebuilds_have_no_original_input=True,version_controls=versions,
   baseline_source_builds=[first['clients'],repeat['clients'],changed['clients']])
 except BaseException as error:
  receipt.update(status='baseline_musl_source_client_control_failed_not_admitted',error_type=type(error).__name__,error=str(error));raise
 finally:
  (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
  if receipt['status'] in ['both_native_musl_baseline_source_layouts_rebuilt_without_original_and_single_entry_edit_controlled','both_native_musl_complete_source_layouts_rebuilt_without_original_and_single_entry_edit_controlled']:
   files=[dict(file=f.relative_to(out).as_posix(),bytes=f.stat().st_size,sha256=sha(f)) for f in sorted(out.rglob('*')) if f.is_file()]
   (out/'MANIFEST.json').write_text(json.dumps(dict(schema_version=1,files=files),indent=2)+'\n')


if __name__=='__main__':main()
