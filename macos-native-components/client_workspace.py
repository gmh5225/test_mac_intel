"""Prove source-only reconstruction and a single controlled module edit."""
from pathlib import Path
import shutil
from client_build import build, rows


def edit_control(arch, engine, baseline_work, output, logs):
    workspace=output/'edited-workspace';workspace.mkdir(parents=True)
    for layout in ['preserved','readable']:
        target=workspace/layout;target.mkdir()
        shutil.copytree(baseline_work/layout/'sources',target/'sources')
        entry=target/'sources/m6';entry.write_bytes(entry.read_bytes()+b'\n// NEVERD_MAC_SOURCE_WORKSPACE_EDIT_PROOF\n')
    work=output/'edited-build'
    result=build(arch,None,engine,work,logs,workspace)
    assert not result['original_input_supplied'] and not result['actual_client_execution_acceptance']
    for layout,row in result['clients'].items():
        assert row['intentionally_edited_modules']==[6]
        before=rows(baseline_work/layout/'readback/mapping.tsv');after=rows(work/layout/'readback/mapping.tsv')
        assert len(before)==len(after)==2609
        changed=[]
        for ordinal,(left,right) in enumerate(zip(before,after)):
            assert {k:v for k,v in left.items() if k not in ['file','bytes','storage_sha256']}=={k:v for k,v in right.items() if k not in ['file','bytes','storage_sha256']}
            if (left['bytes'],left['storage_sha256'])!=(right['bytes'],right['storage_sha256']):changed.append(ordinal)
        assert changed==[6]
    return dict(status='private_workspace_only_rebuild_and_single_module_edit_readback_verified',
        edited_build=result,changed_module_indices=[6],unchanged_rows_per_layout=2608,
        original_input_used=False,prior_runtime_acceptance_inherited=False)
