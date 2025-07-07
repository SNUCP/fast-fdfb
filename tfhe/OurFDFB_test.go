package tfhe_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	paramsListNew = []tfhe.ParametersLiteral[uint64]{
		tfhe.Params5,
		tfhe.Params6,
		tfhe.Params7,
		tfhe.Params8,
	}
)

func TestParamsNew(t *testing.T) {
	for _, params := range paramsListNew {
		t.Run(fmt.Sprintf("Compile/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.NotPanics(t, func() { params.Compile() })
		})
	}

	for _, params := range paramsListNew {
		t.Run(fmt.Sprintf("FailureProbability/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.LessOrEqual(t, math.Log2(params.Compile().EstimateFailureProbabilityNewFDFB()), -60.0)
		})
	}
}

func Benchmark_OurFDFB(b *testing.B) {
	for _, params := range paramsListNew {
		params := params.Compile()

		enc := tfhe.NewEncryptorHierarchyWithSharedLWEKey(params)
		evaluators := make([]*tfhe.Evaluator[uint64], len(enc))

		for depth := 0; depth < len(enc); depth++ {
			evaluators[depth] = tfhe.NewEvaluatorHierarchy(params, enc[depth].GenEvaluationKeyParallel(), depth+1)
		}

		// baseEnc and baseEval are temporary encryptor and evaluator to generate and decompose LUT.
		baseEnc := tfhe.NewEncryptor(params)
		baseEval := tfhe.NewEvaluator(params, baseEnc.GenEvaluationKeyParallel())

		decomposedlut := baseEval.NewDecomposedLut()
		baseEval.GenLookUpTableNegDecomposedAssign(func(x int) int { return 13 + x }, baseEval.Parameters.MessageModulus(), baseEval.Parameters.Scale(), decomposedlut)
		compressLUT := tfhe.NewLookUpTable(evaluators[len(evaluators)-1].Parameters)

		baseEval.GenCompressLUTAssign(compressLUT)
		ct := enc[0].EncryptLWE(1)
		ctCompress := ct.Copy()
		MSConst := baseEval.ModSwitchConstant()

		b.Run(fmt.Sprintf("prec=%v", num.Log2(params.MessageModulus())), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ctOut := enc[0].EncryptLWE(0)
				for depth := 0; depth < len(evaluators); depth++ {
					evaluators[depth].AddLWEAssign(ctOut, evaluators[depth].BootstrapLUTWithMSconst(ct, decomposedlut[depth], MSConst), ctOut)
				}
				evaluators[len(evaluators)-1].BootstrapLUTWithMSconstAssign(ct, compressLUT, MSConst*2, ctCompress)
				evaluators[len(evaluators)-1].AddLWEAssign(ctOut, evaluators[len(evaluators)-1].BootstrapLUT(ctCompress, decomposedlut[len(decomposedlut)-1]), ctOut)
			}
		})
	}
}

func Example_ourFDFB() {
	params := tfhe.Params5.Compile()
	enc := tfhe.NewEncryptorHierarchyWithSharedLWEKey(params)
	evaluators := make([]*tfhe.Evaluator[uint64], len(enc))

	for depth := 0; depth < len(enc); depth++ {
		evaluators[depth] = tfhe.NewEvaluatorHierarchy(params, enc[depth].GenEvaluationKeyParallel(), depth+1)
	}

	// baseEnc and baseEval are temporary encryptor and evaluator to generate and decompose LUT.
	baseEnc := tfhe.NewEncryptor(params)
	baseEval := tfhe.NewEvaluator(params, baseEnc.GenEvaluationKeyParallel())

	decomposedlut := baseEval.NewDecomposedLut()
	baseEval.GenLookUpTableNegDecomposedAssign(func(x int) int { return 18 - 3*x }, baseEval.Parameters.MessageModulus(), baseEval.Parameters.Scale(), decomposedlut)
	compressLUT := tfhe.NewLookUpTable(evaluators[len(evaluators)-1].Parameters)

	baseEval.GenCompressLUTAssign(compressLUT)
	ct := enc[0].EncryptLWE(5)
	ctOut := enc[0].EncryptLWE(0)
	ctCompress := ct.Copy()
	MSConst := baseEval.ModSwitchConstant()
	for depth := 0; depth < len(evaluators); depth++ {
		evaluators[depth].AddLWEAssign(ctOut, evaluators[depth].BootstrapLUTWithMSconst(ct, decomposedlut[depth], MSConst), ctOut)
	}
	evaluators[len(evaluators)-1].BootstrapLUTWithMSconstAssign(ct, compressLUT, MSConst*2, ctCompress)
	evaluators[len(evaluators)-1].AddLWEAssign(ctOut, evaluators[len(evaluators)-1].BootstrapLUT(ctCompress, decomposedlut[len(decomposedlut)-1]), ctOut)

	fmt.Println(enc[0].DecryptLWE(ctOut))
	// Output:
	// 3
}
