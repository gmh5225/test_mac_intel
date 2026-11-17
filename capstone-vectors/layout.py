from pathlib import Path
from split_layout import decoder_proof as split_proof, leaf_proof
from merged_layout import decoder_proof as merged_proof, symbols

def object_proof(label,before,after,leaf):
    if label=='scan':
        return dict(original_plan_relocation=split_proof(before,after),new_leaf=leaf_proof(leaf))
    assert label=='merge'
    return merged_proof(before,after)

def linked_layout(before,after,label):
    old,new=symbols(before,'tTwW'),symbols(after,'tTwW')
    owned=lambda x:x[0] in ('X86_decodeScanFeatureExtension','X86_decodeEvexTransferScan') or x[0].startswith('decodeEvexRegisterScan')
    left,right=[x for x in old if not owned(x)],[x for x in new if not owned(x)]
    assert left==right,dict(missing=sorted(set(left)-set(right))[:12],changed=sorted(set(right)-set(left))[:12])
    result=dict(unmodified_text_positions_identical=True,text_symbols=len(left),
                plan_entries=dict(before=[x for x in old if owned(x)],after=[x for x in new if owned(x)]))
    for key,kinds in (('readonly','rR'),('writable','bBdDgGsSvV')):
        left,right=symbols(before,kinds),symbols(after,kinds)
        added=[x for x in right if x[0] in ('evex_transfer_scan_ids','evex_transfer_lengths')]
        right=[x for x in right if x not in added]
        assert [(x[0],x[1],x[3]) for x in left]==[(x[0],x[1],x[3]) for x in right]
        moves=[dict(symbol=a[0],before=a[2],after=b[2],bytes=a[3],delta=b[2]-a[2]) for a,b in zip(left,right) if a!=b]
        result[key]=dict(original_symbols=len(left),moves=moves,added=added,
                         address_deltas=sorted({x['delta'] for x in moves}))
    result['criterion']='Record every data address change; actual timing and A/A controls determine performance acceptance. This supersedes the earlier exact-address proxy before any timing of these candidates was collected.'
    return result
