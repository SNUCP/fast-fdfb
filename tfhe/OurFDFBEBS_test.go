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
	paramsListNewEBS = []tfhe.ParametersLiteral[uint64]{
		tfhe.ParamsEBS5,
		tfhe.ParamsEBS6,
		tfhe.ParamsEBS7,
		tfhe.ParamsEBS8,
	}
)

func TestParamsNewEBS(t *testing.T) {
	for _, params := range paramsListNewEBS {
		t.Run(fmt.Sprintf("Compile/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.NotPanics(t, func() { params.Compile() })
		})
	}

	for _, params := range paramsListNewEBS {
		t.Run(fmt.Sprintf("FailureProbability/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.LessOrEqual(t, math.Log2(params.Compile().EstimateFailureProbabilityNewFDFB_EBS()), -60.0)
		})
	}
}

func Benchmark_OurFDFBEBS(b *testing.B) {
	for _, params := range paramsListNewEBS {
		params := params.Compile()
		enc := tfhe.NewEncryptor(params)
		eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

		decomposedlut := eval.NewDecomposedLutEBS()
		eval.GenLookUpTableNegDecomposedEBSAssign(func(x int) int { return 13 - 2*x }, eval.Parameters.MessageModulus(), eval.Parameters.Scale(), decomposedlut)
		compressLUT := tfhe.NewLookUpTable(eval.Parameters)
		eval.GenCompressLUTAssign(compressLUT)

		ct := enc.EncryptLWE(0)
		ctOut := ct.Copy()

		b.Run(fmt.Sprintf("prec=%v", num.Log2(params.MessageModulus())), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.BootstrapExtendedFullDomainAssignNew(ct, compressLUT, decomposedlut, ctOut)
			}
		})
	}
}

func Example_ourFDFBEBS() {
	params := tfhe.ParamsEBS5.Compile()

	enc := tfhe.NewEncryptor(params)
	eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	decomposedlut := eval.NewDecomposedLutEBS()
	eval.GenLookUpTableNegDecomposedEBSAssign(func(x int) int { return 18 - 3*x }, eval.Parameters.MessageModulus(), eval.Parameters.Scale(), decomposedlut)
	compressLUT := tfhe.NewLookUpTable(eval.Parameters)
	eval.GenCompressLUTAssign(compressLUT)

	ct := enc.EncryptLWE(5)
	ctOut := ct.Copy()
	eval.BootstrapExtendedFullDomainAssignNew(ct, compressLUT, decomposedlut, ctOut)
	fmt.Println(enc.DecryptLWE(ctOut))
	// Output:
	// 3
}
