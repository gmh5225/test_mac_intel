#include <stdint.h>
#include <stdio.h>
#include <capstone/capstone.h>
#include "utils.h"
#define GET_SUBTARGETINFO_ENUM
#include "arch/Mips/MipsGenSubtargetInfo.inc"
bool originalFeature(unsigned int mode, unsigned int feature)
{
	switch (feature) {
	case Mips_FeatureGP64Bit:
		return mode &
		       (CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureFP64Bit:
		return mode &
		       (CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureNaN2008:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureAbs2008:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips1:
		return mode &
		       (CS_MODE_MIPS1 | CS_MODE_MIPS2 | CS_MODE_MIPS32 |
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips2:
		return mode &
		       (CS_MODE_MIPS2 | CS_MODE_MIPS32 | CS_MODE_MIPS32R2 |
			CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips3_32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS3 |
			CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips3_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips3:
		return mode &
		       (CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips4_32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips4_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips4:
		return mode &
		       (CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips5_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips5:
		return mode &
		       (CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips32r3:
		return mode &
		       (CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips32r5:
		return mode & (CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			       CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips32r6:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64:
		return mode &
		       (CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips64r2:
		return mode &
		       (CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips64r3:
		return mode &
		       (CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64r5:
		return mode & (CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64r6:
		return mode & CS_MODE_MIPS64R6;
	case Mips_FeatureMips16:
		return mode & CS_MODE_MIPS16;
	case Mips_FeatureMicroMips:
		return mode & CS_MODE_MICRO;
	case Mips_FeatureNanoMips:
		return mode & (CS_MODE_NANOMIPS | CS_MODE_NMS1 | CS_MODE_I7200);
	case Mips_FeatureNMS1:
		return mode & CS_MODE_NMS1;
	case Mips_FeatureTLB:
		return mode & CS_MODE_I7200;
	case Mips_FeatureCnMips:
		return mode & (CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureCnMipsP:
		return mode & CS_MODE_OCTEONP;
	case Mips_FeaturePTR64Bit:
		return mode & CS_MODE_MIPS_PTR64;
	case Mips_FeatureSoftFloat:
		return mode & CS_MODE_MIPS_NOFLOAT;
	case Mips_FeatureI7200:
		return mode & CS_MODE_I7200;
	// optional features always enabled
	case Mips_FeatureDSP: // Mips DSP ASE
		return true;
	case Mips_FeatureDSPR2: // Mips DSP-R2 ASE
		return true;
	case Mips_FeatureDSPR3: // Mips DSP-R3 ASE
		return true;
	case Mips_FeatureMips3D: // Mips 3D ASE
		return true;
	case Mips_FeatureMSA: // Mips MSA ASE
		return true;
	case Mips_FeatureEVA: { // Mips EVA ASE
		if (mode & CS_MODE_NANOMIPS) {
			return mode & CS_MODE_I7200;
		}
		return true;
	}
	case Mips_FeatureCRC: // Mips R6 CRC ASE
		return true;
	case Mips_FeatureVirt: // Mips Virtualization ASE
		return true;
	case Mips_FeatureGINV: // Mips Global Invalidate ASE
		return true;
	case Mips_FeatureMT: { // Mips MT ASE
		if (mode & CS_MODE_NANOMIPS) {
			return mode & CS_MODE_I7200;
		}
		return true;
	}
	default:
		return false;
	}
}
bool candidateFeature(unsigned int mode, unsigned int feature)
{
	/* Generated decoder predicates pass a constant feature. Its mode mask
	 * can then be folded into the calling predicate. */
	static const unsigned int mode_masks[Mips_NumSubtargetFeatures] = {
		[Mips_FeatureGP64Bit] = CS_MODE_MIPS3 | CS_MODE_MIPS4 |
					CS_MODE_MIPS5 | CS_MODE_MIPS64 |
					CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
					CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
					CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureFP64Bit] =
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureNaN2008] = CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6,
		[Mips_FeatureAbs2008] = CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6,
		[Mips_FeatureMips1] =
			CS_MODE_MIPS1 | CS_MODE_MIPS2 | CS_MODE_MIPS32 |
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips2] =
			CS_MODE_MIPS2 | CS_MODE_MIPS32 | CS_MODE_MIPS32R2 |
			CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP,
		[Mips_FeatureMips3_32] =
			CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS3 |
			CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips3_32r2] =
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips3] = CS_MODE_MIPS3 | CS_MODE_MIPS4 |
				      CS_MODE_MIPS5 | CS_MODE_MIPS64 |
				      CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
				      CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
				      CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips4_32] =
			CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips4_32r2] =
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP,
		[Mips_FeatureMips4] =
			CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips5_32r2] =
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips5] = CS_MODE_MIPS5 | CS_MODE_MIPS64 |
				      CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
				      CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
				      CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips32] =
			CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips32r2] = CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
					 CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
					 CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
					 CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
					 CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips32r3] = CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
					 CS_MODE_MIPS32R6 | CS_MODE_MIPS64R3 |
					 CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6,
		[Mips_FeatureMips32r5] = CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
					 CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6,
		[Mips_FeatureMips32r6] = CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6,
		[Mips_FeatureMips64] = CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
				       CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
				       CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
				       CS_MODE_OCTEONP,
		[Mips_FeatureMips64r2] = CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
					 CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
					 CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureMips64r3] = CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
					 CS_MODE_MIPS64R6,
		[Mips_FeatureMips64r5] = CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6,
		[Mips_FeatureMips64r6] = CS_MODE_MIPS64R6,
		[Mips_FeatureMips16] = CS_MODE_MIPS16,
		[Mips_FeatureMicroMips] = CS_MODE_MICRO,
		[Mips_FeatureNanoMips] = CS_MODE_NANOMIPS | CS_MODE_NMS1 |
					 CS_MODE_I7200,
		[Mips_FeatureNMS1] = CS_MODE_NMS1,
		[Mips_FeatureTLB] = CS_MODE_I7200,
		[Mips_FeatureCnMips] = CS_MODE_OCTEON | CS_MODE_OCTEONP,
		[Mips_FeatureCnMipsP] = CS_MODE_OCTEONP,
		[Mips_FeaturePTR64Bit] = CS_MODE_MIPS_PTR64,
		[Mips_FeatureSoftFloat] = CS_MODE_MIPS_NOFLOAT,
		[Mips_FeatureI7200] = CS_MODE_I7200,
	};
	switch (feature) {
	case Mips_FeatureDSP:
	case Mips_FeatureDSPR2:
	case Mips_FeatureDSPR3:
	case Mips_FeatureMips3D:
	case Mips_FeatureMSA:
	case Mips_FeatureCRC:
	case Mips_FeatureVirt:
	case Mips_FeatureGINV:
		return true;
	case Mips_FeatureEVA:
	case Mips_FeatureMT:
		if (mode & CS_MODE_NANOMIPS)
			return mode & CS_MODE_I7200;
		return true;
	default:
		return feature < ARR_SIZE(mode_masks) &&
		       (mode & mode_masks[feature]);
	}
}
int main(void)
{
	uint32_t mode = 0;
	unsigned long long comparisons = 0;
	for (unsigned sample = 0; sample < 100000; ++sample) {
		if (sample <= 32)
			mode = sample == 32 ? 0 : UINT32_C(1) << sample;
		else if (sample < 1057)
			mode = (UINT32_C(1) << ((sample - 33) & 31)) |
			       (UINT32_C(1) << ((sample - 33) >> 5));
		else if (sample == 1057)
			mode = UINT32_MAX;
		else
			mode = mode * UINT32_C(1664525) + UINT32_C(1013904223);
		for (unsigned index = 0; index <= Mips_NumSubtargetFeatures+2; ++index) {
			unsigned feature = index == Mips_NumSubtargetFeatures+2 ? UINT32_MAX : index;
			if (originalFeature(mode, feature) != candidateFeature(mode, feature))
				return 1;
			++comparisons;
		}
	}
	printf("%llu feature/mode comparisons\n", comparisons);
	return 0;
}
